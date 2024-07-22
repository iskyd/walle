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
        epknew,
        epktopublic,
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
        .seedtoec => {
            const seed = args[2][0..args[2].len];
            const bytes: []u8 = allocator.alloc(u8, seed.len / 2) catch {
                std.debug.print("Error while allocating memory", .{});
                return;
            };
            defer allocator.free(bytes);
            _ = try std.fmt.hexToBytes(bytes, seed);
            const epk = bip32.generateExtendedMasterPrivateKey(bytes);
            const addr = epk.address(0, [4]u8{ 0, 0, 0, 0 }, 0) catch {
                std.debug.print("Error while generating address", .{});
                return;
            };
            std.debug.print("Master private key: {s}\n", .{addr});
        },
        .epktopublic => {
            const epk = bip32.ExtendedPrivateKey.fromAddress(args[2][0..111]) catch {
                std.debug.print("Invalid extended private key address", .{});
                return;
            };

            const public = bip32.generatePublicKey(epk.privatekey);
            const compressed = public.toStrCompressed() catch {
                std.debug.print("Error while compressing public key", .{});
                return;
            };
            std.debug.print("Compressed public key {s}\n", .{compressed});
        },
    }
}
