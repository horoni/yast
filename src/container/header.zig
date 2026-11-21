const std = @import("std");
const crypto = std.crypto;

const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const nonce_len = XChaCha20Poly1305.nonce_length;
pub const tag_len = XChaCha20Poly1305.tag_length;
pub const salt_size = 16;

pub const V1_VERSION = 1;
pub const V2_VERSION = 2;

pub const salt_offset = 0;
pub const nonce_offset = salt_offset + salt_size;
pub const envelope_size = nonce_offset + nonce_len;

pub const ContainerType = enum(u8) {
    raw = 0,
    vault_encrypted = 1,
    password_encrypted = 2,
};

pub const HeaderAuth = union(enum) {
    password: []const u8,
    key: *const [32]u8,
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
        const info = @typeInfo(Self).@"struct";
        for (info.field_types) |FieldType| size += @sizeOf(FieldType);
        break :blk size;
    };

    pub fn toBytes(self: *const Self, out: *[header_size]u8) void {
        const info = @typeInfo(Self).@"struct";
        inline for (info.field_names, info.field_types) |field_name, FieldType| {
            const offset = @offsetOf(Self, field_name);
            const size   = @sizeOf(FieldType);
            const val    = @field(self, field_name);
            std.mem.writeInt(FieldType, out[offset..][0..size], val, .little);
        }
    }

    pub fn fromBytes(bytes: *const [header_size]u8) !Self {
        var result: Self = undefined;
        const info = @typeInfo(Self).@"struct";

        inline for (info.field_names, info.field_types) |field_name, FieldType| {
            const offset = @offsetOf(Self, field_name);
            const size   = @sizeOf(FieldType);
            const val    = std.mem.readInt(FieldType, bytes[offset..][0..size], .little);
            @field(result, field_name) = val;
        }

        if (result.getChecksum() != result.checksum) return error.HeaderChecksumMismatch;
        if (result.version > V2_VERSION) return error.IncompatibleHeaderVersion;

        return result;
    }

    /// Calculates checksum of struct
    pub fn getChecksum(self: *Self) u32 {
        var crc = std.hash.Crc32.init();

        const info = @typeInfo(Self).@"struct";
        inline for (info.field_names, info.field_types) |field_name, FieldType| {
            if (comptime std.mem.eql(u8, field_name, "checksum")) continue;
            const val = @field(self, field_name);
            var buf: [@sizeOf(FieldType)]u8 = undefined;
            std.mem.writeInt(FieldType, &buf, val, .little);
            crc.update(&buf);
        }
        return crc.final();
    }
};

/// v1 header: nonce || encrypted header.
pub const V1_HEADER_SIZE = nonce_len + ContainerHeader.header_size;

/// v2 header: salt || nonce || encrypted header || tag.
pub const V2_HEADER_SIZE = envelope_size + ContainerHeader.header_size + tag_len;

/// Decoded header and payload, before wrapping in the public Container type.
pub const Frame = struct {
    header: ContainerHeader,
    payload: []const u8,
};

pub fn validateAuth(container_type: u8, auth: HeaderAuth) !void {
    const expected: ContainerType = switch (auth) {
        .password => .password_encrypted,
        .key      => .vault_encrypted,
    };
    if (container_type != @intFromEnum(expected)) return error.InvalidContainerMode;
}

/// Copies the payload after an overflow-safe bounds check.
pub fn copyPayload(allocator: std.mem.Allocator, blob: []const u8, hdr: ContainerHeader) ![]const u8 {
    const offset: usize = hdr.data_offset;
    const length: usize = hdr.data_length;
    if (offset > blob.len or length > blob.len - offset) {
        return error.PayloadTruncated;
    }

    return allocator.dupe(u8, blob[offset .. offset + length]);
}
