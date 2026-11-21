const std = @import("std");
const crypto = std.crypto;
const argon2 = crypto.pwhash.argon2;

const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;

const header = @import("header.zig");
const v1 = @import("v1.zig");
const v2 = @import("v2.zig");

pub const ContainerType = header.ContainerType;
pub const HeaderAuth = header.HeaderAuth;
pub const ContainerHeader = header.ContainerHeader;

pub const V1_VERSION = header.V1_VERSION;
pub const V2_VERSION = header.V2_VERSION;
pub const V1_HEADER_SIZE = header.V1_HEADER_SIZE;
pub const V2_HEADER_SIZE = header.V2_HEADER_SIZE;

/// Derives the fast, unsalted key used by v1 password headers. New
/// containers never use it; it only exists for reading v1 files.
pub const deriveCoverKey = v1.deriveCoverKey;

pub const Container = struct {
    header: ContainerHeader,
    payload: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }

    pub fn initPassword(io: std.Io, allocator: std.mem.Allocator, plaintext: []const u8, password: []const u8) !Self {
        const payload_len = header.salt_size + header.nonce_len + header.tag_len + plaintext.len;
        const payload = try allocator.alloc(u8, payload_len);
        errdefer allocator.free(payload);

        const salt  = payload[0                                   .. header.salt_size];
        const nonce = payload[header.salt_size                    .. header.salt_size + header.nonce_len];
        const tag   = payload[header.salt_size + header.nonce_len .. header.salt_size + header.nonce_len + header.tag_len];
        const ciphertext = payload[header.salt_size + header.nonce_len + header.tag_len ..];

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
            tag[0..header.tag_len],
            plaintext,
            "",
            nonce[0..header.nonce_len].*,
            master_key,
        );

        const data_length = std.math.cast(u32, payload.len) orelse return error.PayloadTooLarge;
        return Self {
            .header  = v2.initHeader(.password_encrypted, data_length),
            .payload = payload,
        };
    }

    pub fn initVault(io: std.Io, allocator: std.mem.Allocator, plaintext: []const u8, keys: []const [32]u8) !Self {
        if (keys.len == 0) return error.EmptyVault;

        var payload = try allocator.dupe(u8, plaintext);
        errdefer allocator.free(payload);

        for (keys, 0..) |key, i| {
            const out_len = header.nonce_len + payload.len + header.tag_len;
            const out = try allocator.alloc(u8, out_len);
            errdefer allocator.free(out);

            const nonce      = out[0                        .. header.nonce_len];
            const tag        = out[header.nonce_len         .. header.nonce_len + header.tag_len];
            const ciphertext = out[header.nonce_len + header.tag_len ..];

            try io.randomSecure(nonce);

            XChaCha20Poly1305.encrypt(
                ciphertext,
                tag[0..header.tag_len],
                payload,
                "",
                nonce.*,
                key
            );

            if (i == 0) crypto.secureZero(u8, payload);
            allocator.free(payload);
            payload = out;
        }

        const data_length = std.math.cast(u32, payload.len) orelse return error.PayloadTooLarge;
        return Self {
            .header  = v2.initHeader(.vault_encrypted, data_length),
            .payload = payload,
        };
    }

    pub fn serialize(self: *const Self, io: std.Io, allocator: std.mem.Allocator, auth: HeaderAuth) ![]u8 {
        return v2.serialize(io, allocator, self.header, self.payload, auth);
    }

    /// Reads either an authenticated v2 container or a v1 one.
    /// There is no plaintext marker, so header authentication decides the format.
    pub fn deserialize(io: std.Io, allocator: std.mem.Allocator, blob: []const u8, auth: HeaderAuth, v1_key: ?*const [32]u8) !Self {
        var v2_err: ?anyerror = null;
        if (blob.len >= V2_HEADER_SIZE) {
            if (v2.deserialize(io, allocator, blob, auth)) |frame| {
                return .{ .header = frame.header, .payload = frame.payload };
            } else |err| {
                v2_err = err;
            }
        }

        if (v1_key) |key| {
            if (v1.deserialize(allocator, blob, key)) |frame| {
                return .{ .header = frame.header, .payload = frame.payload };
            } else |err| {
                return v2_err orelse err;
            }
        }

        return v2_err orelse error.InvalidHeader;
    }

    pub fn decryptPassword(self: *const Self, io: std.Io, allocator: std.mem.Allocator, password: []const u8) ![]u8 {
        if (self.header.container_type != @intFromEnum(ContainerType.password_encrypted)) {
            return error.InvalidContainerMode;
        }

        const min_len = header.salt_size + header.nonce_len + header.tag_len;
        if (self.payload.len < min_len) return error.CorruptedPayload;

        const salt  = self.payload[0                                   .. header.salt_size];
        const nonce = self.payload[header.salt_size                    .. header.salt_size + header.nonce_len];
        const tag   = self.payload[header.salt_size + header.nonce_len .. header.salt_size + header.nonce_len + header.tag_len];
        const ciphertext = self.payload[header.salt_size + header.nonce_len + header.tag_len ..];

        var master_key: [32]u8 = undefined;
        try argon2.kdf(
            allocator,
            &master_key,
            password,
            salt[0..header.salt_size],
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
            tag[0..header.tag_len].*,
            "",
            nonce[0..header.nonce_len].*,
            master_key,
        ) catch |err| {
            if (err == error.AuthenticationFailed) {
                std.log.err("MAC verification failed. Wrong password?", .{});
            }
            return err;
        };

        return plaintext;
    }

    pub fn decryptVault(self: *Self, allocator: std.mem.Allocator, keys: []const [32]u8) ![]u8 {
        if (self.header.container_type != @intFromEnum(ContainerType.vault_encrypted)) {
            return error.InvalidContainerMode;
        }

        const min_len = header.nonce_len + header.tag_len;
        if (self.payload.len < min_len) return error.CorruptedPayload;

        var plaintext = try allocator.dupe(u8, self.payload);
        errdefer allocator.free(plaintext);

        var i: usize = keys.len;
        while (i > 0) {
            i -= 1;
            const key = keys[i];

            if (plaintext.len < header.nonce_len + header.tag_len) return error.InvalidCiphertext;

            const nonce      = plaintext[0                .. header.nonce_len];
            const tag        = plaintext[header.nonce_len .. header.nonce_len + header.tag_len];
            const ciphertext = plaintext[header.nonce_len + header.tag_len ..];
            const plain_len  = plaintext.len - header.nonce_len - header.tag_len;

            const plain = try allocator.alloc(u8, plain_len);
            errdefer allocator.free(plain);

            try XChaCha20Poly1305.decrypt(
                plain,
                ciphertext,
                tag[0..header.tag_len].*,
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

test "password container round-trips and rejects wrong credentials" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const password = "correct horse battery staple";
    const plaintext = "header authentication";

    var con = try Container.initPassword(io, allocator, plaintext, password);
    defer con.deinit(allocator);

    const blob = try con.serialize(io, allocator, .{ .password = password });
    defer allocator.free(blob);

    try std.testing.expectEqual(V2_HEADER_SIZE + con.payload.len, blob.len);

    var restored = try Container.deserialize(io, allocator, blob, .{ .password = password }, null);
    defer restored.deinit(allocator);

    const decrypted = try restored.decryptPassword(io, allocator, password);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted);

    try std.testing.expectError(
        error.HeaderAuthenticationFailed,
        v2.deserialize(io, allocator, blob, .{ .password = "wrong password" }),
    );

    const dummy_key: [32]u8 = @splat(0);
    try std.testing.expectError(
        error.HeaderAuthenticationFailed,
        v2.deserialize(io, allocator, blob, .{ .key = &dummy_key }),
    );
    try std.testing.expectError(
        error.InvalidContainerMode,
        con.serialize(io, allocator, .{ .key = &dummy_key }),
    );
}

test "container header rejects salt, ciphertext, and tag tampering" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const password = "tamper test";

    var con = try Container.initPassword(io, allocator, "payload", password);
    defer con.deinit(allocator);

    const blob = try con.serialize(io, allocator, .{ .password = password });
    defer allocator.free(blob);

    const tampered_salt = try allocator.dupe(u8, blob);
    defer allocator.free(tampered_salt);
    tampered_salt[header.salt_offset] ^= 0x01;
    try std.testing.expectError(
        error.HeaderAuthenticationFailed,
        v2.deserialize(io, allocator, tampered_salt, .{ .password = password }),
    );

    const tampered_header = try allocator.dupe(u8, blob);
    defer allocator.free(tampered_header);
    tampered_header[header.envelope_size] ^= 0x01;
    try std.testing.expectError(
        error.HeaderAuthenticationFailed,
        v2.deserialize(io, allocator, tampered_header, .{ .password = password }),
    );

    const tampered_tag = try allocator.dupe(u8, blob);
    defer allocator.free(tampered_tag);
    tampered_tag[V2_HEADER_SIZE - 1] ^= 0x01;
    try std.testing.expectError(
        error.HeaderAuthenticationFailed,
        v2.deserialize(io, allocator, tampered_tag, .{ .password = password }),
    );
}

test "key-authenticated vault header round-trips" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const plaintext = "vault payload";

    var keys = [_][32]u8{@splat(0x42)};

    var con = try Container.initVault(io, allocator, plaintext, &keys);
    defer con.deinit(allocator);

    const blob = try con.serialize(io, allocator, .{ .key = &keys[0] });
    defer allocator.free(blob);

    var restored = try Container.deserialize(io, allocator, blob, .{ .key = &keys[0] }, &keys[0]);
    defer restored.deinit(allocator);

    const decrypted = try restored.decryptVault(allocator, &keys);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted);

    var wrong_keys = [_][32]u8{@splat(0x43)};
    try std.testing.expectError(
        error.HeaderAuthenticationFailed,
        v2.deserialize(io, allocator, blob, .{ .key = &wrong_keys[0] }),
    );
}

test "container parser rejects blobs that are too short" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var short: [V2_HEADER_SIZE - 1]u8 = undefined;
    @memset(&short, 0);

    try std.testing.expectError(
        error.InvalidHeader,
        v2.deserialize(io, allocator, &short, .{ .password = "pw" }),
    );
}

test "container headers have no fixed plaintext fields" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key: [32]u8 = @splat(0x45);

    var keys = [_][32]u8{key};

    var con = try Container.initVault(io, allocator, "", &keys);
    defer con.deinit(allocator);

    const sample_count = 8;
    var headers: [sample_count][V2_HEADER_SIZE]u8 = undefined;
    for (&headers) |*sample| {
        const blob = try con.serialize(io, allocator, .{ .key = &key });
        @memcpy(sample[0..], blob[0..V2_HEADER_SIZE]);
        allocator.free(blob);
    }

    // A magic value or a plaintext KDF/auth byte would be constant here. With
    // eight random samples, a random byte position is constant by chance with
    // probability 256^-7.
    for (0..V2_HEADER_SIZE) |offset| {
        var varies = false;
        for (headers[1..]) |sample| {
            if (sample[offset] != headers[0][offset]) {
                varies = true;
                break;
            }
        }
        try std.testing.expect(varies);
    }
}

test "auto detection reads v2 and v1 containers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key: [32]u8 = @splat(0x42);
    const plaintext = "detected payload";

    var v1_header = v1.initHeader(.vault_encrypted, @intCast(plaintext.len));
    const v1_blob = try allocator.alloc(u8, V1_HEADER_SIZE + plaintext.len);
    defer allocator.free(v1_blob);
    try v1.encryptHeader(&v1_header, io, v1_blob[0..V1_HEADER_SIZE], &key);
    @memcpy(v1_blob[V1_HEADER_SIZE..], plaintext);

    var v1_con = try Container.deserialize(io, allocator, v1_blob, .{ .key = &key }, &key);
    defer v1_con.deinit(allocator);
    try std.testing.expectEqual(V1_VERSION, v1_con.header.version);
    try std.testing.expectEqualStrings(plaintext, v1_con.payload);

    var keys = [_][32]u8{key};

    var con = try Container.initVault(io, allocator, plaintext, &keys);
    defer con.deinit(allocator);

    const blob = try con.serialize(io, allocator, .{ .key = &key });
    defer allocator.free(blob);

    var restored = try Container.deserialize(io, allocator, blob, .{ .key = &key }, &key);
    defer restored.deinit(allocator);
    try std.testing.expectEqual(V2_VERSION, restored.header.version);

    const decrypted = try restored.decryptVault(allocator, &keys);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted);
}
