const std = @import("std");
const crypto = std.crypto;
const argon2 = crypto.pwhash.argon2;
const header = @import("header.zig");

const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;

pub fn initHeader(container_type: header.ContainerType, data_length: u32) header.ContainerHeader {
    var hdr = header.ContainerHeader{
        .version = header.V2_VERSION,
        .container_type = @intFromEnum(container_type),
        .data_length = data_length,
        .data_offset = header.V2_HEADER_SIZE,
        .checksum = 0,
    };
    hdr.checksum = hdr.getChecksum();
    return hdr;
}

fn deriveKey(io: std.Io, allocator: std.mem.Allocator, auth: header.HeaderAuth, salt: []const u8) ![32]u8 {
    switch (auth) {
        .password => |password| {
            var key: [32]u8 = undefined;
            try argon2.kdf(
                allocator,
                &key,
                password,
                salt,
                argon2.Params.owasp_2id,
                .argon2id,
                io
            );
            return key;
        },
        .key => |key| return key.*,
    }
}

pub fn encryptHeader(hdr: *const header.ContainerHeader, io: std.Io, allocator: std.mem.Allocator, out: *[header.V2_HEADER_SIZE]u8, auth: header.HeaderAuth) !void {
    const envelope = out[0..header.envelope_size];
    try io.randomSecure(envelope);

    var header_key = try deriveKey(io, allocator, auth, envelope[header.salt_offset..][0..header.salt_size]);
    defer crypto.secureZero(u8, &header_key);

    var plain: [header.ContainerHeader.header_size]u8 = undefined;
    hdr.toBytes(&plain);

    const ciphertext = out[header.envelope_size .. header.envelope_size + header.ContainerHeader.header_size];
    const tag        = out[header.V2_HEADER_SIZE - header.tag_len .. header.V2_HEADER_SIZE];

    XChaCha20Poly1305.encrypt(
        ciphertext,
        tag[0..header.tag_len],
        &plain,
        envelope,
        envelope[header.nonce_offset..][0..header.nonce_len].*,
        header_key,
    );
}

pub fn decryptHeader(io: std.Io, allocator: std.mem.Allocator, data: []const u8, out: *[header.ContainerHeader.header_size]u8, auth: header.HeaderAuth) !void {
    if (data.len < header.V2_HEADER_SIZE) return error.InvalidHeader;

    const envelope = data[0..header.envelope_size];
    var header_key = try deriveKey(io, allocator, auth, envelope[header.salt_offset..][0..header.salt_size]);
    defer crypto.secureZero(u8, &header_key);

    const ciphertext = data[header.envelope_size .. header.envelope_size + header.ContainerHeader.header_size];
    const tag        = data[header.V2_HEADER_SIZE - header.tag_len .. header.V2_HEADER_SIZE];

    XChaCha20Poly1305.decrypt(
        out,
        ciphertext,
        tag[0..header.tag_len].*,
        envelope,
        envelope[header.nonce_offset..][0..header.nonce_len].*,
        header_key,
    ) catch return error.HeaderAuthenticationFailed;
}

pub fn deserialize(io: std.Io, allocator: std.mem.Allocator, blob: []const u8, auth: header.HeaderAuth) !header.Frame {
    if (blob.len < header.V2_HEADER_SIZE) return error.InvalidHeader;

    var plain: [header.ContainerHeader.header_size]u8 = undefined;
    try decryptHeader(io, allocator, blob, &plain, auth);

    const hdr = try header.ContainerHeader.fromBytes(&plain);
    if (hdr.version != header.V2_VERSION) return error.IncompatibleHeaderVersion;
    if (hdr.data_offset != header.V2_HEADER_SIZE) return error.InvalidHeader;

    try header.validateAuth(hdr.container_type, auth);

    return .{
        .header = hdr,
        .payload = try header.copyPayload(allocator, blob, hdr),
    };
}

pub fn serialize(io: std.Io, allocator: std.mem.Allocator, hdr: header.ContainerHeader, payload: []const u8, auth: header.HeaderAuth) ![]u8 {
    try header.validateAuth(hdr.container_type, auth);

    const blob = try allocator.alloc(u8, header.V2_HEADER_SIZE + payload.len);
    errdefer allocator.free(blob);

    try encryptHeader(&hdr, io, allocator, blob[0..header.V2_HEADER_SIZE], auth);
    @memcpy(blob[header.V2_HEADER_SIZE..], payload);

    return blob;
}

test "v2 container rejects headers that point outside the blob" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key: [32]u8 = @splat(0x44);

    var hdr = initHeader(.vault_encrypted, std.math.maxInt(u32));
    var blob: [header.V2_HEADER_SIZE + 16]u8 = undefined;
    try encryptHeader(&hdr, io, allocator, blob[0..header.V2_HEADER_SIZE], .{ .key = &key });
    @memset(blob[header.V2_HEADER_SIZE..], 0);

    try std.testing.expectError(error.PayloadTruncated, deserialize(io, allocator, &blob, .{ .key = &key }));

    hdr.data_offset = 0;
    hdr.data_length = 16;
    hdr.checksum = hdr.getChecksum();
    try encryptHeader(&hdr, io, allocator, blob[0..header.V2_HEADER_SIZE], .{ .key = &key });

    try std.testing.expectError(error.InvalidHeader, deserialize(io, allocator, &blob, .{ .key = &key }));
}
