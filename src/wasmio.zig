const std = @import("std");

extern "env" fn jsRandomSecure(ptr: [*]u8, len: usize) void;

pub fn Io() std.Io {
    return .{
        .userdata = null,
        .vtable = &wasmVtable,
    };
}

fn getVtable(sets: anytype) std.Io.VTable {
    var vt = std.Io.failing.vtable.*;
    inline for (std.meta.fields(@TypeOf(sets))) |f| {
        @field(vt, f.name) = @field(sets, f.name);
    }
    return vt;
}

const wasmVtable = getVtable(.{
    .random = wasmRandom,
    .randomSecure = wasmRandomSecure,
});

fn wasmRandom(userdata: ?*anyopaque, buffer: []u8) void {
    wasmRandomSecure(userdata, buffer) catch { return; };
}

fn wasmRandomSecure(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    _ = userdata;
    jsRandomSecure(buffer.ptr, buffer.len);
}
