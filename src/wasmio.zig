const std = @import("std");

pub fn Io() std.Io {
    return .{
        .userdata = null,
        .vtable = &wasmVtable,
    };
}

const wasmVtable = std.Io.VTable{
    .random = wasmRandom,
    .randomSecure = wasmRandomSecure,
};

fn wasmRandom(userdata: ?*anyopaque, buffer: []u8) void {
    _ = userdata;
    @memset(buffer, 0);
}

fn wasmRandomSecure(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    _ = userdata;
    _ = buffer;
    return error.EntropyUnavailable;
}
