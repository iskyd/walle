const std = @import("std");
const io = std.io;
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const utils = @import("utils.zig");
const clap = @import("clap");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    const AvailableCommands = enum {
        PvNew,
    };
    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\<CMD>...
        \\
    );

    const parsers = comptime .{
        .CMD = clap.parsers.enumeration(AvailableCommands),
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
    }) catch |err| {
        // Report useful error and exit
        diag.report(io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        return clap.usage(std.io.getStdErr().writer(), clap.Help, &params);
    }

    if (res.positionals.len != 1) {
        std.debug.print("Expected 1 positional argument, got {}\n", .{res.positionals.len});
        return;
    }
    const command: AvailableCommands = res.positionals[0];

    switch (command) {
        .PvNew => {
            var gpa = std.heap.GeneralPurposeAllocator(.{}){};
            const allocator = gpa.allocator();
            const ent = 256;
            var entropy: []u8 = try allocator.alloc(u8, ent / 8);
            defer allocator.free(entropy);
            const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");
            defer wordlist.deinit();
            var mnemonic: [24][]u8 = undefined;
            try bip39.generateMnemonic(allocator, entropy, wordlist, &mnemonic);
            defer for (mnemonic) |word| allocator.free(word);
            var seed: [64]u8 = undefined;
            try bip39.mnemonicToSeed(allocator, &mnemonic, "", &seed);
            var seed_str: [128]u8 = undefined;
            _ = try std.fmt.bufPrint(&seed_str, "{x}", .{std.fmt.fmtSliceHexLower(&seed)});

            std.debug.print("Seed: {s}\n", .{seed_str});
        },
        // else => std.debug.print("Invalid command provided\n"),
    }
}
