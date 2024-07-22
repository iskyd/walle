const std = @import("std");
const io = std.io;
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const utils = @import("utils.zig");
const clap = @import("clap");
const script = @import("script.zig");
const tx = @import("tx.zig");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const Commands = enum {
        scriptdecode,
        txdecode,
    };

    const args = std.process.argsAlloc(allocator) catch {
        std.debug.print("Error while allocating memory for args\n", .{});
        return;
    };
    defer std.process.argsFree(allocator, args);

    const cmd = std.meta.stringToEnum(Commands, args[1]);
    if (cmd == null) {
        std.debug.print("Invalid argument\n", .{});
        return;
    }

    switch (cmd.?) {
        .scriptdecode => {
            const s = script.Script.decode(allocator, args[2]) catch {
                std.debug.print("Invalid script provided\n", .{});
                return;
            };
            defer s.deinit();

            std.debug.print("{}\n", .{s});
        },
        .txdecode => {
            const transaction = tx.decodeRawTx(allocator, args[2]) catch {
                std.debug.print("Invalid rawtx provided\n", .{});
                return;
            };
            defer transaction.deinit();
            std.debug.print("{}\n", .{transaction});
        },
    }
}
