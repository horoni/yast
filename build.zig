const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zignal = b.dependency("zignal", .{ .target = target, .optimize = optimize });
    const clap = b.dependency("clap", .{});

    // === Main ===
    const exe_main = b.addExecutable(.{
        .name = "yast",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe_main.root_module.addImport("zignal", zignal.module("zignal"));
    exe_main.root_module.addImport("clap", clap.module("clap"));

    b.installArtifact(exe_main);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe_main);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    const exe_tests = b.addTest(.{
        .root_module = exe_main.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);

    // Library tests live in their own modules. Add them as explicit test roots
    // so `zig build test` runs them instead of only compiling the executable.
    const library_test_roots = [_][]const u8{
        "src/bpcs.zig",
        "src/container.zig",
    };
    for (library_test_roots) |root| {
        const library_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(root),
                .target = target,
                .optimize = optimize,
            }),
        });
        const run_library_tests = b.addRunArtifact(library_tests);
        test_step.dependOn(&run_library_tests.step);
    }

    // === Keys ===
    const exe_keys = b.addExecutable(.{
        .name = "yastkeys",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/yastkeys.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe_keys.root_module.addImport("clap", clap.module("clap"));

    b.installArtifact(exe_keys);
}
