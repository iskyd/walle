const std = @import("std");
const Build = std.Build;

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "walle",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/p.zig" },
        .target = target,
        .optimize = optimize,
    });

    const base58 = b.addModule("base58", .{
        .root_source_file = .{ .path = "lib/base58/src/lib.zig" },
    });
    const clap = b.addModule("clap", .{
        .root_source_file = .{ .path = "lib/clap/clap.zig" },
    });
    const crypto = b.addModule("crypto", .{
        .root_source_file = .{ .path = "src/crypto/crypto.zig" },
    });

    exe.root_module.addImport("base58", base58);
    exe.root_module.addImport("clap", clap);
    exe.root_module.addImport("crypto", crypto);

    //exe.addModule("base58", base58);
    //exe.addModule("clap", clap);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");

    const tests: []const []const u8 = if (b.args) |args| args else &.{"unit_test.zig"};
    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    for (tests) |test_file| {
        const unit_tests = b.addTest(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
            // .main_mod_path = .{ .path = "." }, // .main_mod_path in zig 0.12.0
        });
        unit_tests.root_module.addImport("base58", base58);
        unit_tests.root_module.addImport("crypto", crypto);
        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = true; // Always execute test, do not cache
        test_step.dependOn(&run_unit_tests.step);
    }

    // add tests for crypto module
    if (b.args == null) {
        const unit_tests = b.addTest(.{
            .root_source_file = b.path("unit_test_crypto.zig"),
            .target = target,
            .optimize = optimize,
        });
        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = false;
        test_step.dependOn(&run_unit_tests.step);
    }
}
