const std = @import("std");
const crypto = std.crypto;
const argon2 = crypto.pwhash.argon2;
const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const KEY_SIZE = XChaCha20Poly1305.key_length;
pub const NONCE_SIZE = XChaCha20Poly1305.nonce_length;
pub const MAC_SIZE = XChaCha20Poly1305.tag_length;
pub const SALT_SIZE = 16;

pub const Vault = struct {
    keys: [][KEY_SIZE]u8,

    pub fn deinit(self: *const Vault, allocator: std.mem.Allocator) void {
        for (self.keys) |*key| {
            crypto.secureZero(u8, key);
        }
        allocator.free(self.keys);
    }

    pub fn loadVault(io: std.Io, allocator: std.mem.Allocator, filepath: []const u8, password: []const u8) !Vault {
        const file = try std.Io.Dir.openFileAbsolute(io, filepath, .{});
        defer file.close(io);

        const file_size = try file.length(io);
        const header_size = SALT_SIZE + NONCE_SIZE;
        if (file_size < header_size + MAC_SIZE + 4) return error.InvalidVault;

        var buf: [4096]u8 = undefined;
        var reader_wrap = file.reader(io, &buf);
        const reader = &reader_wrap.interface;

        var salt: [SALT_SIZE]u8 = undefined;
        try reader.readSliceAll(&salt);

        var nonce: [NONCE_SIZE]u8 = undefined;
        try reader.readSliceAll(&nonce);

        var master_key: [KEY_SIZE]u8 = undefined;
        try argon2.kdf(allocator, &master_key, password, &salt, argon2.Params.owasp_2id, .argon2id, io);
        defer crypto.secureZero(u8, &master_key);

        const cipher_len = file_size - header_size;
        const ciphertext = try allocator.alloc(u8, cipher_len);
        defer allocator.free(ciphertext);
        try reader.readSliceAll(ciphertext);

        const plain_len = cipher_len - MAC_SIZE;
        const plaintext = try allocator.alloc(u8, plain_len);
        errdefer allocator.free(plaintext);

        try XChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext[0..plain_len],
            ciphertext[plain_len..][0..MAC_SIZE].*,
            "",
            nonce,
            master_key,
        );

        var r = std.Io.Reader.fixed(plaintext);

        const num_keys = try r.takeInt(u32, .little);
        const keys = try allocator.alloc([KEY_SIZE]u8, num_keys);
        errdefer allocator.free(keys);

        for (keys) |*key| {
            try r.readSliceAll(key);
        }

        crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);

        return Vault{ .keys = keys };
    }
};


