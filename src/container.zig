const std = @import("std");
const crypto = std.crypto;
const argon2 = std.crypto.pwhash.argon2;

const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;
const XChaCha20IETF = crypto.stream.chacha.XChaCha20IETF;

const Vault = @import("vault.zig").Vault;

const nonce_len = XChaCha20Poly1305.nonce_length;
const tag_len = XChaCha20Poly1305.tag_length;
const salt_size = 16;

pub const HEADER_VERSION = 1;

pub const ContainerType = enum(u8) {
    raw = 0,
    vault_encrypted = 1,
    password_encrypted = 2,
};

pub const ContainerHeader = packed struct {
    version: u16,
    container_type: u8,
    data_length: u32,
    data_offset: u32,
    checksum: u32,

    const Self = @This();
    pub const header_size = blk: {
        var size = 0;
        const fields = std.meta.fields(Self);
        for (fields) |field| size += @sizeOf(field.type);
        break :blk size;
    };

    pub fn init(container_type: ContainerType, data_length: u32) Self {
        var obj = Self{
            .version = HEADER_VERSION,
            .container_type = @intFromEnum(container_type),
            .data_length = data_length,
            .data_offset = ENCRYPTED_HEADER_SIZE,
            .checksum = 0,
        };
        obj.checksum = obj.getChecksum();
        return obj;
    }

    pub fn toBytes(self: *const ContainerHeader, out: *[header_size]u8) void {
        const fields = std.meta.fields(Self);
        inline for (fields) |field| {
            const offset = @offsetOf(Self, field.name);
            const size   = @sizeOf(field.type);
            const val    = @field(self, field.name);
            std.mem.writeInt(field.type, out[offset..][0..size], val, .little);
        }
    }

    pub fn fromBytes(bytes: *const [header_size]u8) !Self {
        var result: Self = undefined;
        const fields = std.meta.fields(Self);

        inline for (fields) |field| {
            const offset = @offsetOf(Self, field.name);
            const size   = @sizeOf(field.type);
            const val    = std.mem.readInt(field.type, bytes[offset..][0..size], .little);
            @field(result, field.name) = val;
        }

        if (result.getChecksum() != result.checksum) return error.HeaderChecksumMismatch;
        if (result.version > HEADER_VERSION) return error.IncompatibleHeaderVersion;

        return result;
    }

    /// Calculates checksum of struct
    pub fn getChecksum(self: *Self) u32 {
        var crc = std.hash.Crc32.init();

        const fields = std.meta.fields(Self);
        inline for (fields) |field| {
            if (comptime std.mem.eql(u8, field.name, "checksum")) continue;
            const val = @field(self, field.name);
            var buf: [@sizeOf(field.type)]u8 = undefined;
            std.mem.writeInt(field.type, &buf, val, .little);
            crc.update(&buf);
        }
        return crc.final();
    }

    pub fn encrypt(self: *const Self, io: std.Io, out: *[ENCRYPTED_HEADER_SIZE]u8, key: *const [32]u8) !void {
        var hdr_plain: [ContainerHeader.header_size]u8 = undefined;
        self.toBytes(&hdr_plain);

        const nonce = out[0..nonce_len];
        try io.randomSecure(nonce);

        const ciphertext = out[nonce_len..ENCRYPTED_HEADER_SIZE];

        XChaCha20IETF.xor(
            ciphertext,
            &hdr_plain,
            0,
            key.*,
            nonce.*,
        );
    }

    pub fn decrypt(data: []const u8, out: *[ContainerHeader.header_size]u8, key: *const [32]u8) !void {
        if (data.len < ENCRYPTED_HEADER_SIZE) {
            return error.InvalidHeader;
        }

        const nonce = data[0..nonce_len];
        const ciphertext = data[nonce_len..ENCRYPTED_HEADER_SIZE];

        XChaCha20IETF.xor(
            &out.*,
            ciphertext,
            0,
            key.*,
            nonce.*,
        );
    }

};

pub const ENCRYPTED_HEADER_SIZE = XChaCha20IETF.nonce_length +
    ContainerHeader.header_size;

pub const Container = struct {
    header: ContainerHeader,
    payload: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }

    pub fn serialize(self: *const Self, io: std.Io, allocator: std.mem.Allocator, key: *const [32]u8) ![]u8 {
        const total_size = ENCRYPTED_HEADER_SIZE + self.payload.len;
        const blob = try allocator.alloc(u8, total_size);
        errdefer allocator.free(blob);

        try self.header.encrypt(io, blob[0..ENCRYPTED_HEADER_SIZE], key);
        @memcpy(blob[ENCRYPTED_HEADER_SIZE..], self.payload);

        return blob;
    }

    pub fn deserialize(allocator: std.mem.Allocator, blob: []const u8, key: *const [32]u8) !Self {
        if (blob.len < ENCRYPTED_HEADER_SIZE) {
            return error.BlobTooSmall;
        }

        var hdr_plain: [ContainerHeader.header_size]u8 = undefined;
        try ContainerHeader.decrypt(blob[0..ENCRYPTED_HEADER_SIZE], &hdr_plain, key);
        
        const header = try ContainerHeader.fromBytes(&hdr_plain);

        if (blob.len < header.data_offset + header.data_length) {
            return error.PayloadTruncated;
        }

        return Self{
            .header = header,
            .payload = try allocator.dupe(u8, blob[header.data_offset .. header.data_offset + header.data_length]),
        };
    }

    pub fn initPassword(io: std.Io, allocator: std.mem.Allocator, plaintext: []const u8, password: []const u8) !Self {
        const payload_len = salt_size + nonce_len + tag_len + plaintext.len;
        const payload = try allocator.alloc(u8, payload_len);
        errdefer allocator.free(payload);

        const salt  = payload[0                     .. salt_size];
        const nonce = payload[salt_size             .. salt_size + nonce_len];
        const tag   = payload[salt_size + nonce_len .. salt_size + nonce_len + tag_len];
        const ciphertext = payload[salt_size + nonce_len + tag_len ..];

        try io.randomSecure(salt);
        try io.randomSecure(nonce);

        var master_key: [32]u8 = undefined;
        try argon2.kdf(
            allocator,
            &master_key,
            password,
            salt,
            argon2.Params.owasp_2id,
            .argon2id,
            io
        );
        defer crypto.secureZero(u8, &master_key);

        XChaCha20Poly1305.encrypt(
            ciphertext,
            tag[0..tag_len],
            plaintext,
            "",
            nonce[0..nonce_len].*,
            master_key,
        );

        return Self {
            .header  = .init(.password_encrypted, @intCast(payload.len)),
            .payload = payload,
        };
    }

    pub fn initVault(io: std.Io, allocator: std.mem.Allocator, plaintext: []const u8, vault: Vault) !Self {
        if (vault.keys.len == 0) return error.EmptyVault;

        var payload = try allocator.dupe(u8, plaintext);
        errdefer allocator.free(payload);

        for (vault.keys, 0..) |key, i| {
            const out_len = nonce_len + payload.len + tag_len;
            const out = try allocator.alloc(u8, out_len);
            errdefer allocator.free(out);

            const nonce      = out[0                 .. nonce_len];
            const tag        = out[nonce_len         .. nonce_len + tag_len];
            const ciphertext = out[nonce_len + tag_len ..];

            try io.randomSecure(nonce);

            XChaCha20Poly1305.encrypt(
                ciphertext,
                tag[0..tag_len],
                payload,
                "",
                nonce.*,
                key
            );

            if (i == 0) crypto.secureZero(u8, payload);
            allocator.free(payload);
            payload = out;
        }

        return Self {
            .header  = .init(.vault_encrypted, @intCast(payload.len)),
            .payload = payload,
        };
    }

    pub fn decryptPassword(self: *const Self, io: std.Io, allocator: std.mem.Allocator, password: []const u8) ![]u8 {
        if (self.header.container_type != @intFromEnum(ContainerType.password_encrypted)) {
            return error.InvalidContainerMode;
        }

        const min_len = salt_size + nonce_len + tag_len;
        if (self.payload.len < min_len) return error.CorruptedPayload;

        const salt  = self.payload[0                     .. salt_size];
        const nonce = self.payload[salt_size             .. salt_size + nonce_len];
        const tag   = self.payload[salt_size + nonce_len .. salt_size + nonce_len + tag_len];
        const ciphertext = self.payload[salt_size + nonce_len + tag_len ..];

        var master_key: [32]u8 = undefined;
        try argon2.kdf(
            allocator,
            &master_key,
            password,
            salt[0..salt_size],
            argon2.Params.owasp_2id,
            .argon2id,
            io
        );
        defer crypto.secureZero(u8, &master_key);

        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(plaintext);

        XChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag[0..tag_len].*,
            "",
            nonce[0..nonce_len].*,
            master_key,
        ) catch |err| {
            if (err == error.AuthenticationFailed) {
                std.log.err("MAC verification failed. Wrong password?", .{});
            }
            return err;
        };

        return plaintext;
    }

    pub fn decryptVault(self: *Self, allocator: std.mem.Allocator, vault: Vault) ![]u8 {
        if (self.header.container_type != @intFromEnum(ContainerType.vault_encrypted)) {
            return error.InvalidContainerMode;
        }

        const min_len = nonce_len + tag_len;
        if (self.payload.len < min_len) return error.CorruptedPayload;

        var plaintext = try allocator.dupe(u8, self.payload);
        errdefer allocator.free(plaintext);

        var i: usize = vault.keys.len;
        while (i > 0) {
            i -= 1;
            const key = vault.keys[i];

            if (plaintext.len < nonce_len + tag_len) return error.InvalidCiphertext;

            const nonce      = plaintext[0         ..nonce_len];
            const tag        = plaintext[nonce_len .. nonce_len + tag_len];
            const ciphertext = plaintext[nonce_len + tag_len ..];
            const plain_len  = plaintext.len - nonce_len - tag_len;

            const plain = try allocator.alloc(u8, plain_len);
            errdefer allocator.free(plain);

            try XChaCha20Poly1305.decrypt(
                plain,
                ciphertext,
                tag[0..tag_len].*,
                "",
                nonce.*,
                key
            );

            allocator.free(plaintext);
            plaintext = plain;
        }

        return plaintext;
    }
};

pub fn deriveCoverKey(width: u32, height: u32, entr: u64, entra: []u8, key: *[32]u8) void {
    var ctx = crypto.hash.blake2.Blake2b256.init(.{});
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4],  width,  .little);
    std.mem.writeInt(u32, buf[4..8],  height, .little);
    std.mem.writeInt(u64, buf[8..16], entr,   .little);

    ctx.update(&buf);
    ctx.update(entra);
    ctx.final(key);
}
