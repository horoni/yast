const std = @import("std");

pub fn BpcsStream(comptime N: usize) type {
    if (N % 2 == 0) @compileError("Grid size N must be odd");

    return struct {
        const Self = @This();
        pub const GRID_W = N;
        pub const GRID_H = N;
        pub const GRID_SZ = N * N;
        pub const BYTES_PER_BLOCK = (GRID_SZ - 1) / 8;
        pub const CONJ_BIT_IDX = GRID_SZ - 1;

        img_data: []u8, // Interleaved RGB [W*H*3]
        width: u32,
        height: u32,
        bitplanes: u8,
        min_complexity: u32,

        // Planar channel pointers
        channels: [3][]u8,
        
        // Iteration state
        curr_channel: usize = 0,
        curr_bp: usize = 0,
        curr_x: usize = 0,
        curr_y: usize = 0,

        exhausted: bool = false,
        embedding: bool,

        grid: [GRID_SZ]u8 = [_]u8{0} ** GRID_SZ,
        
        // Pre-calculated diffs for complexity optimization
        diff_h: []u8,
        diff_v: []u8,

        pub fn init(
            allocator: std.mem.Allocator,
            img_data: []u8,
            width: u32,
            height: u32,
            bitplanes: u8,
            min_complexity: u32,
            embedding: bool,
        ) !Self {
            const px_count = @as(usize, width) * height;
            const diff_h = try allocator.alloc(u8, px_count);
            errdefer allocator.free(diff_h);
            const diff_v = try allocator.alloc(u8, px_count);
            errdefer allocator.free(diff_v);

            var self = Self{
                .img_data = img_data,
                .width = width,
                .height = height,
                .bitplanes = bitplanes,
                .min_complexity = min_complexity,
                .embedding = embedding,
                .diff_h = diff_h,
                .diff_v = diff_v,
                .channels = undefined,
            };

            const base_planar = 3 * px_count;
            for (0..3) |i| {
                self.channels[i] = img_data[base_planar + i * px_count .. base_planar + (i + 1) * px_count];
            }

            try self.splitAndCgc();
            try self.loadNextChannel();
            try self.setNextGrid();

            if (!embedding and !self.exhausted) {
                if (self.grid[CONJ_BIT_IDX] != 0) {
                    self.conjugateGrid();
                }
            }

            return self;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.diff_h);
            allocator.free(self.diff_v);
        }

        fn splitAndCgc(self: *Self) !void {
            const px_count = @as(usize, self.width) * self.height;
            var i: usize = 0;

            while (i + 16 <= px_count) : (i += 16) {
                for (0..16) |j| {
                    const idx = (i + j) * 3;
                    const r = self.img_data[idx];
                    const g = self.img_data[idx + 1];
                    const b = self.img_data[idx + 2];
                    
                    self.channels[0][i + j] = r ^ (r >> 1);
                    self.channels[1][i + j] = g ^ (g >> 1);
                    self.channels[2][i + j] = b ^ (b >> 1);
                }
            }
            while (i < px_count) : (i += 1) {
                const idx = i * 3;
                const r = self.img_data[idx];
                const g = self.img_data[idx + 1];
                const b = self.img_data[idx + 2];
                self.channels[0][i] = r ^ (r >> 1);
                self.channels[1][i] = g ^ (g >> 1);
                self.channels[2][i] = b ^ (b >> 1);
            }
        }

        pub fn mergeAndIcgc(self: *Self) void {
            const px_count = @as(usize, self.width) * self.height;
            for (0..px_count) |i| {
                var r = self.channels[0][i];
                var g = self.channels[1][i];
                var b = self.channels[2][i];

                inline for (.{ 1, 2, 4 }) |shift| {
                    r ^= (r >> shift);
                    g ^= (g >> shift);
                    b ^= (b >> shift);
                }

                self.img_data[i * 3] = r;
                self.img_data[i * 3 + 1] = g;
                self.img_data[i * 3 + 2] = b;
            }
        }

        fn loadNextChannel(self: *Self) !void {
            if (self.curr_channel >= 3) return;
            const ch = self.channels[self.curr_channel];
            const px_count = ch.len;
            const w = self.width;

            var i: usize = 0;
            while (i + 1 < px_count) : (i += 1) {
                self.diff_h[i] = ch[i] ^ ch[i + 1];
                if (i + w < px_count) {
                    self.diff_v[i] = ch[i] ^ ch[i + w];
                }
            }
            self.curr_bp = 0;
        }

        fn calcComplexity(self: *const Self, base_idx: usize, bit_shift: u3) u32 {
            var sum: u32 = 0;
            const w = self.width;
            const mask = @as(u8, 1) << bit_shift;

            // Horizontal
            for (0..N) |row| {
                const row_start = base_idx + row * w;
                for (0..N - 1) |col| {
                    if ((self.diff_h[row_start + col] & mask) != 0) sum += 1;
                }
            }

            // Vertical
            for (0..N - 1) |row| {
                const row_start = base_idx + row * w;
                for (0..N) |col| {
                    if ((self.diff_v[row_start + col] & mask) != 0) sum += 1;
                }
            }
            return sum;
        }

        fn setNextGrid(self: *Self) !void {
            const w = self.width;
            const h = self.height;

            while (self.curr_bp < self.bitplanes) {
                while (self.curr_y <= h - N) : (self.curr_y += N) {
                    const start_x = if (self.curr_x > 0) self.curr_x else 0;
                    var x = start_x;
                    while (x <= w - N) : (x += N) {
                        const idx = self.curr_y * w + x;
                        if (self.calcComplexity(idx, @intCast(self.curr_bp)) >= self.min_complexity) {
                            self.extractGrid(idx, @intCast(self.curr_bp));
                            self.curr_x = x + @as(u32, N);
                            return;
                        }
                    }
                    self.curr_x = 0;
                }
                
                self.curr_y = 0;
                self.curr_x = 0;
                self.curr_bp += 1;
                if (self.curr_bp >= self.bitplanes) {
                    self.curr_channel += 1;
                    if (self.curr_channel < 3) {
                        try self.loadNextChannel();
                        self.curr_bp = 0;
                    } else {
                        self.exhausted = true;
                        if (self.embedding) self.mergeAndIcgc();
                        return;
                    }
                }
            }
        }

        fn extractGrid(self: *Self, base_idx: usize, bit_shift: u3) void {
            const w = self.width;
            const ch = self.channels[self.curr_channel];
            for (0..N) |y| {
                for (0..N) |x| {
                    self.grid[y * N + x] = @intCast((ch[base_idx + y * w + x] >> bit_shift) & 1);
                }
            }
        }

        fn embedGrid(self: *Self, base_idx: usize, bit_shift: u3) void {
            const w = self.width;
            const ch = self.channels[self.curr_channel];
            const mask_clr = ~(@as(u8, 1) << bit_shift);
            for (0..N) |y| {
                for (0..N) |x| {
                    ch[base_idx + y * w + x] = (ch[base_idx + y * w + x] & mask_clr) | (@as(u8, self.grid[y * N + x]) << bit_shift);
                }
            }
        }

        fn conjugateGrid(self: *Self) void {
            for (0..N) |y| {
                for (0..N) |x| {
                    const checker = @as(u8, @intCast(1 ^ ((x & 1) ^ (y & 1))));
                    self.grid[y * N + x] ^= checker;
                }
            }
        }

        fn getGridComplexity(grid: *const [GRID_SZ]u8) u32 {
            var sum: u32 = 0;
            // Horizontal
            for (0..N) |y| {
                for (0..N - 1) |x| {
                    sum += grid[y * N + x] ^ grid[y * N + x + 1];
                }
            }
            // Vertical
            for (0..N - 1) |y| {
                for (0..N) |x| {
                    sum += grid[y * N + x] ^ grid[(y + 1) * N + x];
                }
            }
            return sum;
        }

        pub fn put(self: *Self, data: *const [BYTES_PER_BLOCK]u8) !void {
            if (self.exhausted) return error.Exhausted;

            for (0..BYTES_PER_BLOCK) |j| {
                for (0..8) |i| {
                    self.grid[j * 8 + i] = (data[j] >> @intCast(i)) & 1;
                }
            }
            self.grid[CONJ_BIT_IDX] = 0;

            if (getGridComplexity(&self.grid) < self.min_complexity) {
                self.conjugateGrid();
            }

            const idx = (self.curr_y * self.width) + (self.curr_x - N);
            self.embedGrid(idx, @intCast(self.curr_bp));
            try self.setNextGrid();
        }

        pub fn get(self: *Self, out: *[BYTES_PER_BLOCK]u8) !void {
            if (self.exhausted) return error.Exhausted;

            out.* = [_]u8{0} ** BYTES_PER_BLOCK;
            for (0..BYTES_PER_BLOCK) |j| {
                for (0..8) |i| {
                    out[j] |= @as(u8, self.grid[j * 8 + i]) << @intCast(i);
                }
            }

            try self.setNextGrid();
            if (!self.exhausted and self.grid[CONJ_BIT_IDX] != 0) {
                self.conjugateGrid();
            }
        }

        pub fn countCapacity(self: *Self) u64 {
            const orig_x       = self.curr_x;
            const orig_y       = self.curr_y;
            const orig_bp      = self.curr_bp;
            const orig_channel = self.curr_channel;

            var grids: u64 = 0;

            for (0..3) |channel| {
                self.curr_channel = channel;
                try self.loadNextChannel();

                for (0..self.bitplanes) |bp| {
                    var j: usize = 0;
                    while (j <= self.height - GRID_H) : (j += GRID_H) {
                        var i: usize = 0;
                        while (i <= self.width - GRID_W) : (i += GRID_W) {
                            if (self.calcComplexity(j * self.width + i, @intCast(bp)) >= self.min_complexity) {
                                grids += 1;
                            }
                        }
                    }
                }
            }

            self.curr_x       = orig_x;
            self.curr_y       = orig_y;
            self.curr_channel = orig_channel;
            try self.loadNextChannel();
            self.curr_bp      = orig_bp;

            return grids * BYTES_PER_BLOCK;
        }
    };
}
