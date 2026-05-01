const std = @import("std");
const Io = std.Io;
const zignal = @import("zignal");
const clap = @import("clap");
const bpcs = @import("bpcs.zig");
const container = @import("container.zig");

const Vault = @import("vault.zig").Vault;
const VAULT_PATH = "/etc/yast/vaultz.dat";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    const params = comptime clap.parseParamsComptime(
        \\-h, --help               Display this help and exit.
        \\-e, --encrypt            Encrypt mode.
        \\-d, --decrypt            Decrypt mode.
        \\-c, --cover     <str>    Cover image.
        \\-i, --input     <str>    Input file.
        \\-o, --output    <str>    Output file.
        \\-t, --threshold <usize>  BPCS threshold.
        \\-s, --size      <usize>  BPCS grid size (3, 5, 7... 31).
        \\-w, --wamaku             Encrypt with xChaCha20-poly1305.
        \\-p, --password           Encrypt with password.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, init.minimal.args, .{
        .diagnostic = &diag,
        .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(init.io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try stderr.writeAll(
        \\Usage: yast -e|-d -c <cover> [options]
        \\Options:
        \\  -e          Encrypt mode. Need -i argument
        \\  -d          Decrypt mode
        \\  -c <file>   Cover image
        \\  -i <file>   Input file
        \\  -o <file>   Output (*I)
        \\  -t <int>    Bpcs threshold (default: dynamically calculated) (*II)
        \\  -s <int>    Bpcs grid size (default: 9) (odd numbers from 3 to 31 inclusive) (*III)
        \\  -w          Encrypt with all keys in vault (default: false) (*IV)
        \\  -p          Encrypt with password. (default: false)
        \\  -h          this message
        \\Notes:
        \\  I.   if output name is not specified, then it will be 8 random characters.
        \\  II.  maximum complexity C for NxN grid is 2N(N-1). for ex. C = 2*9(9-1) = 144.
        \\       or C/2 = N^2 - N. you should use C/2 as threshold.
        \\  III. when N is odd, N^2 mod 8 = 1. this one bit needed for conjugation bit.
        \\  IV.  encrypts with all keys that lies in the vault at /etc/yast/vaultz.dat
        \\  V.   when encryption is enabled it uses Argon2id and xChaCha20-poly1305.
        \\
        );
        try stderr.flush();
        return;
    }

    if (res.args.encrypt == 0 and res.args.decrypt == 0) {
        std.log.err("You must specify -e or -d", .{});
        return;
    }

    const mode_encrypt = res.args.encrypt != 0;
    const cover_path = res.args.cover orelse {
        std.log.err("Missing cover image (-c)", .{});
        return;
    };

    const grid_size = if (res.args.size) |s| @as(usize, @intCast(s)) else 9;
    const threshold = if (res.args.threshold) |t| @as(u32, @intCast(t)) else @as(u32, @intCast(grid_size * grid_size - grid_size));
    const chacrypt = res.args.wamaku != 0;
    const pascrypt = res.args.password != 0;

    // Load image
    var img = zignal.Image(zignal.Rgb(u8)).load(io, gpa, cover_path) catch |err| {
        std.log.err("Failed to load image '{s}': {any}", .{ cover_path, err });
        return;
    };
    defer img.deinit(gpa);

    const px_count = @as(usize, img.cols) * img.rows;
    const img_buf = try gpa.alloc(u8, px_count * 6);
    defer gpa.free(img_buf);

    // Copy interleaved data
    @memcpy(img_buf[0 .. px_count * 3], std.mem.sliceAsBytes(img.data));

    switch (grid_size) {
        inline 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31 => |N| {
            try svbpcs(N, gpa, io, img_buf, img.cols, img.rows, threshold, mode_encrypt, chacrypt, pascrypt, res.args.input, res.args.output);
        },
        else => {
            std.log.err("Invalid grid size: {d}. Must be odd and 3-31.", .{grid_size});
            return;
        },
    }

    if (mode_encrypt) {
        const out_path = res.args.output orelse try genOutputName(io, true);
        // Copy back to zignal image
        @memcpy(std.mem.sliceAsBytes(img.data), img_buf[0 .. px_count * 3]);
        try img.save(io, gpa, out_path);
        std.log.info("Saved to {s}", .{out_path});
    }
}

fn svbpcs(
    comptime N: usize,
    allocator: std.mem.Allocator,
    io: std.Io,
    img_buf: []u8,
    width: u32,
    height: u32,
    threshold: u32,
    embedding: bool,
    is_enc_vault: bool,
    is_enc_passwd: bool,
    input_path: ?[]const u8,
    output_path: ?[]const u8,
) !void {
    var stream = try bpcs.BpcsStream(N).init(allocator, img_buf, width, height, 8, threshold, embedding);
    defer stream.deinit(allocator);
    const capacity = stream.countCapacity();

    std.log.info("Threshold: {d}", .{threshold});
    std.log.info("Grid size: {d}", .{N});
    std.log.info("Block size: {d}", .{bpcs.BpcsStream(N).BYTES_PER_BLOCK});
    std.log.info("Available capacity: {d}", .{capacity});
    std.log.info("Header size: {d} | {d}", .{container.ContainerHeader.header_size, container.ENCRYPTED_HEADER_SIZE});

    const is_enc = is_enc_passwd or is_enc_vault;
    var key: [32]u8 = undefined;
    var password: []u8 = undefined;
    if (is_enc) {
        password = try readPassword(io, allocator, "Enter password: ");
        container.deriveCoverKey(width, height, 0, password, &key);
    }
    defer if (is_enc) {
        std.crypto.secureZero(u8, &key);
        std.crypto.secureZero(u8, password);
        allocator.free(password);
    };

    if (embedding) {
        const in_path = input_path orelse {
            std.log.err("Encrypt mode requires input file (-i)", .{});
            return error.MissingInput;
        } ;
        
        // Read file
        const file: std.Io.File = std.Io.Dir.cwd().openFile(io, in_path, .{}) catch |err| {
            std.log.err("Failed to open {s}: {any}", .{ in_path, err });
            return error.FailedOpenFile;
        };
        defer file.close(io);
        const f_size = try file.length(io);
        const data = try allocator.alloc(u8, f_size);
        defer allocator.free(data);
        _ = try file.readPositionalAll(io, data, 0);
        std.log.info("s: {d}", .{f_size});

        var final_data = data;
        if (is_enc_vault) {
            const vault: Vault = try .loadVault(io, allocator, VAULT_PATH, password);
            defer vault.deinit(allocator);
            if (vault.keys.len == 0) return error.NotEnoughKeys;
            
            var con: container.Container = try .initVault(io, allocator, data, vault);
            defer con.deinit(allocator);
            final_data = try con.serialize(io, allocator, &vault.keys[vault.keys.len - 1]);
            std.log.info("Encryption overhead: {d}", .{final_data.len - f_size});
        }

        if (is_enc_passwd) {
            var con: container.Container = try .initPassword(io, allocator, data, password);
            defer con.deinit(allocator);
            final_data = try con.serialize(io, allocator, &key);
            std.log.info("Encryption overhead: {d}", .{final_data.len - f_size});
        }

        defer if (is_enc) allocator.free(final_data);

        if (final_data.len > capacity) {
            std.log.err("insufficent space for data. Need: {d}, Have: {d}",
                .{final_data.len, capacity});
            return error.InsufficentSpace;
        }

        const percent = @as(f32, @floatFromInt(final_data.len))
            / @as(f32, @floatFromInt(capacity)) * 100;
        std.log.info("Data takes up {d}%", .{percent});

        // Put data into stream
        try stream.putAll(io, final_data);
        stream.mergeAndIcgc();
    } else {
        // Decrypt / Extract
        const data = try stream.getAll(allocator, capacity);
        defer allocator.free(data);
        var final_data = data;
        if (is_enc_vault) {
            const vault = try Vault.loadVault(io, allocator, VAULT_PATH, password);
            defer vault.deinit(allocator);
            if (vault.keys.len == 0) return error.NotEnoughKeys;
            
            var con = try container.Container.deserialize(allocator, data, &vault.keys[vault.keys.len - 1]);
            defer con.deinit(allocator);
            final_data = try con.decryptVault(allocator, vault);
        }

        if (is_enc_passwd) {
            var con = try container.Container.deserialize(allocator, data, &key);
            defer con.deinit(allocator);
            final_data = try con.decryptPassword(io, allocator, password);
        }

        defer if (is_enc) allocator.free(final_data);

        const out_path = output_path orelse try genOutputName(io, false);
        const out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
        defer out_file.close(io);
        try out_file.writePositionalAll(io, final_data, 0);
        std.log.info("Extracted to {s}", .{out_path});
    }
}

var buff: [4096]u8 = undefined;

fn genOutputName(io: std.Io, image: bool) ![]u8 {
    if (image) {
        return std.fmt.bufPrint(&buff, "{s}.png", .{genOutputHex(io)});
    }
    return std.fmt.bufPrint(&buff, "{s}.bin", .{genOutputHex(io)});
}

fn genOutputHex(io: std.Io) [8]u8 {
    var buf: [4]u8 = undefined;
    io.random(&buf);
    return std.fmt.bytesToHex(&buf, .lower);
}

fn readPassword(io: std.Io, allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    var stdout_buf: [4096]u8 = undefined;
    var stdin_buf:  [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    var stdin_reader  = std.Io.File.stdin().reader(io,  &stdin_buf);
    const stdout = &stdout_writer.interface;
    const stdin  = &stdin_reader.interface;
    try stdout.writeAll(prompt);
    try stdout.flush();

    const fd = std.Io.File.stdin().handle;

    var termios = try std.posix.tcgetattr(fd);
    const old_termios = termios;
    termios.lflag.ECHO = false;
    termios.lflag.ECHOE = false;
    termios.lflag.ECHOK = false;
    termios.lflag.ECHONL = false;
    try std.posix.tcsetattr(fd, .NOW, termios);
    defer std.posix.tcsetattr(fd, .NOW, old_termios) catch {};

    const input = try stdin.takeDelimiterExclusive('\n');
    try stdout.writeAll("\n");
    try stdout.flush();

    const line = std.mem.trimEnd(u8, input, "\r");
    return try allocator.dupe(u8, line);
}

