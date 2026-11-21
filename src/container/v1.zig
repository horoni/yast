const std = @import("std");
const crypto = std.crypto;
const header = @import("header.zig");

const XChaCha20IETF = crypto.stream.chacha.XChaCha20IETF;

pub fn initHeader(container_type: header.ContainerType, data_length: u32) header.ContainerHeader {
    var hdr = header.ContainerHeader{
        .version = header.V1_VERSION,
        .container_type = @intFromEnum(container_type),
        .data_length = data_length,
        .data_offset = header.V1_HEADER_SIZE,
        .checksum = 0,
    };
    hdr.checksum = hdr.getChecksum();
    return hdr;
}

pub fn encryptHeader(hdr: *const header.ContainerHeader, io: std.Io, out: *[header.V1_HEADER_SIZE]u8, key: *const [32]u8) !void {
    var plain: [header.ContainerHeader.header_size]u8 = undefined;
    hdr.toBytes(&plain);

    const nonce = out[0..header.nonce_len];
    try io.randomSecure(nonce);

    const ciphertext = out[header.nonce_len..header.V1_HEADER_SIZE];

    XChaCha20IETF.xor(
        ciphertext,
        &plain,
        0,
        key.*,
        nonce.*,
    );
}

pub fn decryptHeader(data: []const u8, out: *[header.ContainerHeader.header_size]u8, key: *const [32]u8) !void {
    if (data.len < header.V1_HEADER_SIZE) return error.InvalidHeader;

    const nonce = data[0..header.nonce_len];
    const ciphertext = data[header.nonce_len..header.V1_HEADER_SIZE];

    XChaCha20IETF.xor(
        &out.*,
        ciphertext,
        0,
        key.*,
        nonce.*,
    );
}

pub fn deserialize(allocator: std.mem.Allocator, blob: []const u8, key: *const [32]u8) !header.Frame {
    if (blob.len < header.V1_HEADER_SIZE) return error.BlobTooSmall;

    var plain: [header.ContainerHeader.header_size]u8 = undefined;
    try decryptHeader(blob[0..header.V1_HEADER_SIZE], &plain, key);

    const hdr = try header.ContainerHeader.fromBytes(&plain);
    if (hdr.version != header.V1_VERSION) return error.IncompatibleHeaderVersion;
    if (hdr.data_offset != header.V1_HEADER_SIZE) return error.InvalidHeader;

    return .{
        .header = hdr,
        .payload = try header.copyPayload(allocator, blob, hdr),
    };
}

/// Derives the v1 header key. It is fast and unsalted, so it must only
/// be used to read v1 containers.
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

test "v1 container rejects headers that point outside the blob" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key: [32]u8 = @splat(0x41);

    var hdr = initHeader(.password_encrypted, std.math.maxInt(u32));
    var blob: [header.V1_HEADER_SIZE + 16]u8 = undefined;
    try encryptHeader(&hdr, io, blob[0..header.V1_HEADER_SIZE], &key);
    @memset(blob[header.V1_HEADER_SIZE..], 0);

    try std.testing.expectError(error.PayloadTruncated, deserialize(allocator, &blob, &key));

    hdr.data_offset = 0;
    hdr.data_length = 16;
    hdr.checksum = hdr.getChecksum();
    try encryptHeader(&hdr, io, blob[0..header.V1_HEADER_SIZE], &key);

    try std.testing.expectError(error.InvalidHeader, deserialize(allocator, &blob, &key));
}
