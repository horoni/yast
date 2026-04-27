const std = @import("std");
const clap = @import("clap");
const crypto = std.crypto;
const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;
const argon2 = crypto.pwhash.argon2;

pub const KEY_SIZE = XChaCha20Poly1305.key_length;
pub const NONCE_SIZE = XChaCha20Poly1305.nonce_length;
pub const MAC_SIZE = XChaCha20Poly1305.tag_length;
pub const SALT_SIZE = 16;
pub const VAULT_HEADER_SIZE = SALT_SIZE + NONCE_SIZE;

pub const Vault = struct {
    keys:[][KEY_SIZE]u8,

    pub fn deinit(self: *Vault, allocator: std.mem.Allocator) void {
        for (self.keys) |*key| {
            crypto.secureZero(u8, key);
        }
        allocator.free(self.keys);
    }
};

fn readPassword(io: std.Io, allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    var stdout_buf: [4096]u8 = undefined;
    var stdin_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
    const stdout = &stdout_writer.interface;
    const stdin = &stdin_reader.interface;

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

    const line = std.mem.trimEnd(u8, input, "\r");
    return try allocator.dupe(u8, line);
}

fn loadVault(io: std.Io, allocator: std.mem.Allocator, filepath: []const u8, password:[]const u8) !Vault {
    const file = std.Io.Dir.cwd().openFile(io, filepath, .{}) catch |err| {
        std.log.err("Failed to open vault: {any}", .{err});
        return error.VaultNotFound;
    };
    defer file.close(io);

    const f_size = try file.length(io);
    if (f_size < VAULT_HEADER_SIZE + MAC_SIZE + 4) return error.InvalidVault;

    const raw = try allocator.alloc(u8, f_size);
    defer allocator.free(raw);
    _ = try file.readPositionalAll(io, raw, 0);

    const salt = raw[0..SALT_SIZE];
    const nonce = raw[SALT_SIZE .. SALT_SIZE + NONCE_SIZE];
    const cipher_len = f_size - VAULT_HEADER_SIZE;
    const cipher_with_mac = raw[VAULT_HEADER_SIZE..];

    var master_key: [KEY_SIZE]u8 = undefined;
    try argon2.kdf(
        allocator,
        &master_key,
        password,
        salt[0..SALT_SIZE],
        argon2.Params.owasp_2id,
        .argon2id,
        io
    );
    defer crypto.secureZero(u8, &master_key);

    const plain_len = cipher_len - MAC_SIZE;
    const plain = try allocator.alloc(u8, plain_len);
    defer allocator.free(plain);

    XChaCha20Poly1305.decrypt(
        plain,
        cipher_with_mac[0..plain_len],
        cipher_with_mac[plain_len..][0..MAC_SIZE].*,
        "",
        nonce[0..NONCE_SIZE].*,
        master_key,
    ) catch {
        std.log.err("MAC verification failed. Wrong password?", .{});
        return error.AuthenticationFailed;
    };

    var num_keys_buf: [4]u8 = undefined;
    @memcpy(&num_keys_buf, plain[0..4]);
    const num_keys = std.mem.readInt(u32, &num_keys_buf, .little);

    const keys = try allocator.alloc([KEY_SIZE]u8, num_keys);
    errdefer allocator.free(keys);

    if (num_keys > 0) {
        const expected_len = 4 + num_keys * KEY_SIZE;
        if (plain_len < expected_len) {
            std.log.err("Size mismatch: expected {} keys", .{num_keys});
            return error.CorruptedPayload;
        }
        for (keys, 0..) |*key, i| {
            @memcpy(key, plain[4 + i * KEY_SIZE .. 4 + (i + 1) * KEY_SIZE]);
        }
    }

    return Vault{ .keys = keys };
}

fn saveVault(io: std.Io, allocator: std.mem.Allocator, filepath: []const u8, password:[]const u8, vault: Vault) !void {
    const plain_len = 4 + vault.keys.len * KEY_SIZE;
    const plain = try allocator.alloc(u8, plain_len);
    defer allocator.free(plain);

    std.mem.writeInt(u32, plain[0..4], @intCast(vault.keys.len), .little);
    for (vault.keys, 0..) |key, i| {
        @memcpy(plain[4 + i * KEY_SIZE .. 4 + (i + 1) * KEY_SIZE], &key);
    }

    const out_size = VAULT_HEADER_SIZE + plain_len + MAC_SIZE;
    const out_buf = try allocator.alloc(u8, out_size);
    defer allocator.free(out_buf);

    const salt = out_buf[0..SALT_SIZE];
    const nonce = out_buf[SALT_SIZE .. VAULT_HEADER_SIZE];

    try io.randomSecure(salt);
    try io.randomSecure(nonce);

    var master_key:[KEY_SIZE]u8 = undefined;
    try argon2.kdf(
        allocator,
        &master_key,
        password,
        salt[0..SALT_SIZE],
        argon2.Params.owasp_2id,
        .argon2id,
        io
    );
    defer crypto.secureZero(u8, &master_key);

    const cipher = out_buf[VAULT_HEADER_SIZE .. out_size - MAC_SIZE];
    const tag = out_buf[out_size - MAC_SIZE ..];

    XChaCha20Poly1305.encrypt(
        cipher,
        tag[0..MAC_SIZE],
        plain,
        "",
        nonce[0..NONCE_SIZE].*,
        master_key,
    );

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{filepath});
    defer allocator.free(tmp_path);

    const file = try std.Io.Dir.cwd().createFile(io, tmp_path, .{});
    try file.writePositionalAll(io, out_buf, 0);
    file.close(io);

    const cwd = std.Io.Dir.cwd();
    try std.Io.Dir.cwd().rename(tmp_path, cwd, filepath, io);
}

fn cmdInit(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8) !void {
    const pwd = try readPassword(io, allocator, "Enter NEW vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    const empty_vault = Vault{ .keys = &[_][KEY_SIZE]u8{} };
    try saveVault(io, allocator, filepath, pwd, empty_vault);
    std.log.info("Vault initialized: {s}", .{filepath});
}

fn cmdList(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8) !void {
    const pwd = try readPassword(io, allocator, "Enter vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    var vault = try loadVault(io, allocator, filepath, pwd);
    defer vault.deinit(allocator);

    std.log.info("Vault contains {d} keys.", .{vault.keys.len});
    for (vault.keys, 0..) |key, i| {
        std.log.info("[{d:0>2}] Fingerprint: {s}", .{ i, std.fmt.bytesToHex(key[0..8], .lower) });
    }
}

fn cmdAdd(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8) !void {
    const pwd = try readPassword(io, allocator, "Enter vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    var vault = try loadVault(io, allocator, filepath, pwd);
    defer vault.deinit(allocator);

    var new_keys = try allocator.alloc([KEY_SIZE]u8, vault.keys.len + 1);
    if (vault.keys.len > 0) @memcpy(new_keys[0..vault.keys.len], vault.keys);

    try io.randomSecure(&new_keys[vault.keys.len]);

    allocator.free(vault.keys);
    vault.keys = new_keys;

    try saveVault(io, allocator, filepath, pwd, vault);
    std.log.info("New key added (Total: {d}).", .{vault.keys.len});
}

fn cmdDel(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8, idx: usize) !void {
    const pwd = try readPassword(io, allocator, "Enter vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    var vault = try loadVault(io, allocator, filepath, pwd);
    defer vault.deinit(allocator);

    if (idx >= vault.keys.len) return error.IndexOutOfBounds;

    var new_keys = try allocator.alloc([KEY_SIZE]u8, vault.keys.len - 1);
    var j: usize = 0;
    for (vault.keys, 0..) |key, i| {
        if (i == idx) continue;
        new_keys[j] = key;
        j += 1;
    }

    allocator.free(vault.keys);
    vault.keys = new_keys;

    try saveVault(io, allocator, filepath, pwd, vault);
    std.log.info("Key [{d}] deleted. Remaining keys: {d}", .{ idx, vault.keys.len });
}

fn cmdSwap(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8, idx1: usize, idx2: usize) !void {
    const pwd = try readPassword(io, allocator, "Enter vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    var vault = try loadVault(io, allocator, filepath, pwd);
    defer vault.deinit(allocator);

    if (idx1 >= vault.keys.len or idx2 >= vault.keys.len) return error.IndexOutOfBounds;

    if (idx1 != idx2) {
        const tmp = vault.keys[idx1];
        vault.keys[idx1] = vault.keys[idx2];
        vault.keys[idx2] = tmp;
        try saveVault(io, allocator, filepath, pwd, vault);
        std.log.info("Swapped key [{d}] with [{d}].", .{ idx1, idx2 });
    }
}

fn cmdExport(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8, idx: usize) !void {
    const pwd = try readPassword(io, allocator, "Enter vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    var vault = try loadVault(io, allocator, filepath, pwd);
    defer vault.deinit(allocator);

    if (idx >= vault.keys.len) return error.IndexOutOfBounds;

    const encoder = std.base64.standard.Encoder;
    var buf:[encoder.calcSize(KEY_SIZE)]u8 = undefined;
    const b64 = encoder.encode(&buf, &vault.keys[idx]);
    
    std.log.info("Base64 Key [{d}]: {s}", .{ idx, b64 });
}

fn cmdImport(io: std.Io, allocator: std.mem.Allocator, filepath:[]const u8, b64_str:[]const u8) !void {
    const decoder = std.base64.standard.Decoder;
    var new_key: [KEY_SIZE]u8 = undefined;
    
    decoder.decode(&new_key, b64_str) catch {
        std.log.err("Invalid base64 payload or incorrect length. Expected exactly 32 bytes encoded.", .{});
        return error.InvalidBase64;
    };

    const pwd = try readPassword(io, allocator, "Enter vault password: ");
    defer {
        crypto.secureZero(u8, pwd);
        allocator.free(pwd);
    }

    var vault = try loadVault(io, allocator, filepath, pwd);
    defer vault.deinit(allocator);

    var new_keys = try allocator.alloc([KEY_SIZE]u8, vault.keys.len + 1);
    if (vault.keys.len > 0) @memcpy(new_keys[0..vault.keys.len], vault.keys);
    new_keys[vault.keys.len] = new_key;

    allocator.free(vault.keys);
    vault.keys = new_keys;

    try saveVault(io, allocator, filepath, pwd, vault);
    std.log.info("Base64 key successfully imported (Total: {d}).", .{vault.keys.len});
}

const SubCommands = enum {
    init,
    list,
    add,
    del,
    swap,
    @"export",
    import,
};

const main_parsers = .{
    .command = clap.parsers.enumeration(SubCommands),
};

const main_params = clap.parseParamsComptime(
    \\-h, --help  Display this help and exit.
    \\<command>
    \\
);

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var iter = try init.minimal.args.iterateAllocator(gpa);
    defer iter.deinit();

    _ = iter.next();

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &main_params, main_parsers, &iter, .{
        .diagnostic = &diag,
        .allocator = gpa,
        .terminating_positional = 0,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        printUsage();
        return;
    }

    const command = res.positionals[0] orelse {
        printUsage();
        return;
    };

    switch (command) {
        .init   => try runInit(io, gpa, &iter),
        .list   => try runList(io, gpa, &iter),
        .add    => try runAdd(io, gpa, &iter),
        .del    => try runDel(io, gpa, &iter),
        .swap   => try runSwap(io, gpa, &iter),
        .@"export" => try runExport(io, gpa, &iter),
        .import => try runImport(io, gpa, &iter),
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: yastkeys <command> [args...]
        \\
        \\Commands:
        \\  init   <vault.dat>              Initialize new vault
        \\  list   <vault.dat>              List keys in vault
        \\  add    <vault.dat>              Generate and append new key
        \\  del    <vault.dat> <usize>      Delete key at index
        \\  swap   <vault.dat> <usize> <usize> Swap two keys by index
        \\  export <vault.dat> <usize>      Export key at index to base64
        \\  import <vault.dat> <str>        Import base64 key
        \\
    , .{});
}

fn runInit(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys init <vault.dat>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    
    try cmdInit(io, gpa, filepath);
}

fn runList(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys list <vault.dat>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    
    try cmdList(io, gpa, filepath);
}

fn runAdd(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys add <vault.dat>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    
    try cmdAdd(io, gpa, filepath);
}

fn runDel(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\<usize>     Index to delete
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys del <vault.dat> <idx>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    const idx = res.positionals[1] orelse return error.MissingIndex;
    
    try cmdDel(io, gpa, filepath, idx);
}

fn runSwap(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\<usize>     First index
        \\<usize>     Second index
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys swap <vault.dat> <idx1> <idx2>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    const idx1 = res.positionals[1] orelse return error.MissingIndex;
    const idx2 = res.positionals[2] orelse return error.MissingIndex;
    
    try cmdSwap(io, gpa, filepath, idx1, idx2);
}

fn runExport(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\<usize>     Index to export
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys export <vault.dat> <idx>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    const idx = res.positionals[1] orelse return error.MissingIndex;
    
    try cmdExport(io, gpa, filepath, idx);
}

fn runImport(io: std.Io, gpa: std.mem.Allocator, iter: *std.process.Args.Iterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help.
        \\<str>       Vault path
        \\<str>       Base64 key string
        \\
    );
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag, .allocator = gpa,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) return std.debug.print("Usage: yastkeys import <vault.dat> <b64_str>\n", .{});
    const filepath = res.positionals[0] orelse return error.MissingVaultPath;
    const b64_str = res.positionals[1] orelse return error.MissingBase64;
    
    try cmdImport(io, gpa, filepath, b64_str);
}
