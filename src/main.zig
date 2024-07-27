const std = @import("std");
const io = std.io;
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const utils = @import("utils.zig");
const clap = @import("clap");
const script = @import("script.zig");
const tx = @import("tx.zig");
const deriveP2WPKHAddress = @import("address.zig").deriveP2WPKHAddress;

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const Commands = enum {
        scriptdecode,
        txdecode,
        epknew,
        epktopublic,
        hdderivation,
        addr,
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
        .epknew => {
            if (args.len > 2) {
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
            } else {
                const ent: u16 = 256;
                const entropy = try allocator.alloc(u8, ent / 8);
                defer allocator.free(entropy);
                bip39.generateEntropy(entropy, ent);
                var mnemonic: [24][]u8 = undefined;
                const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");
                defer wordlist.deinit();
                try bip39.generateMnemonic(allocator, entropy, wordlist, &mnemonic);
                std.debug.print("Mnemonic: ", .{});
                for (mnemonic) |w| {
                    std.debug.print("{s} ", .{w});
                }
                std.debug.print("\n", .{});

                var seed: [64]u8 = undefined;
                try bip39.mnemonicToSeed(allocator, &mnemonic, "", &seed);

                const epk = bip32.generateExtendedMasterPrivateKey(&seed);
                const addr = epk.address(0, [4]u8{ 0, 0, 0, 0 }, 0) catch {
                    std.debug.print("Error while generating address", .{});
                    return;
                };
                std.debug.print("Master private key: {s}\n", .{addr});
            }
        },
        .epktopublic => {
            const epk = bip32.ExtendedPrivateKey.fromAddress(args[2][0..111].*) catch {
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
        .hdderivation => {
            const epk = bip32.ExtendedPrivateKey.fromAddress(args[2][0..111].*) catch {
                std.debug.print("Invalid extended private key address", .{});
                return;
            };
            const path = args[3];
            var it = std.mem.split(u8, path, "/");

            var current = epk;
            var depth: u8 = 0;
            var lastindex: u32 = 0;
            while (it.next()) |v| {
                if (v[v.len - 1] == '\'') {
                    // hardened derivation
                    const index = std.fmt.parseInt(u32, v[0 .. v.len - 1], 10) catch {
                        std.debug.print("Invalid path provided", .{});
                        return;
                    };
                    current = bip32.deriveHardenedChild(current, index + 2147483648) catch {
                        std.debug.print("Error while hardening derive child", .{});
                        return;
                    };
                    lastindex = index + 2147483648;
                } else {
                    const index = std.fmt.parseInt(u32, v, 10) catch {
                        std.debug.print("Invalid path provided", .{});
                        return;
                    };
                    current = bip32.deriveChildFromExtendedPrivateKey(current, index) catch {
                        std.debug.print("Error while derive child", .{});
                        return;
                    };
                    lastindex = index;
                }

                depth += 1;
            }

            const strprivate = current.toStrPrivate() catch {
                return;
            };
            const public = bip32.generatePublicKey(epk.privatekey);
            const compressedpublic = public.toStrCompressed() catch {
                std.debug.print("Error while generating parent public key\n", .{});
                return;
            };

            var bytes: [33]u8 = undefined;
            _ = try std.fmt.hexToBytes(&bytes, &compressedpublic);
            const fingerprint = utils.hash160(&bytes)[0..4].*;
            const addr = current.address(.SEGWIT_MAINNET, depth, fingerprint, lastindex) catch {
                std.debug.print("Error while converting to address\n", .{});
                return;
            };
            std.debug.print("private key: {s}\n", .{strprivate});
            std.debug.print("addr: {s}\n", .{addr});
        },
        .addr => {
            const compressed = args[2][0..66].*;
            const public = bip32.PublicKey.fromStrCompressed(compressed) catch {
                std.debug.print("Invalid compressed public key\n", .{});
                return;
            };
            const hash = public.toHashHex() catch {
                std.debug.print("Error while hashing public key\n", .{});
                return;
            };

            const s = script.p2wpkh(allocator, &hash) catch {
                std.debug.print("Error while generating script\n", .{});
                return;
            };
            defer s.deinit();

            const addr = deriveP2WPKHAddress(allocator, s, .MAINNET) catch {
                std.debug.print("Error while generating address\n", .{});
                return;
            };
            defer addr.deinit();

            std.debug.print("Address {s}\n", .{addr.val});
        },
    }
}
