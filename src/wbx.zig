const std = @import("std");
const io = std.io;
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const utils = @import("utils.zig");
const script = @import("script.zig");
const tx = @import("tx.zig");
const deriveP2WPKHAddress = @import("address.zig").deriveP2WPKHAddress;
const Network = @import("const.zig").Network;

fn showHelp() void {
    std.debug.print("Valid commands:\nscriptdecode\ntxdecode\nepknew\nepktopublic\nhdderivation\naddr\nFor more information use wbx <cmd> help", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const Commands = enum {
        scriptdecode,
        txdecode,
        epknew,
        epktopublic,
        derivation,
        addr,
    };

    const args = std.process.argsAlloc(allocator) catch {
        std.debug.print("Error while allocating memory for args\n", .{});
        return;
    };
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) {
        showHelp();
        return;
    }

    const cmd = std.meta.stringToEnum(Commands, args[1]);
    if (cmd == null) {
        showHelp();
        return;
    }

    switch (cmd.?) {
        .scriptdecode => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Decode hex script\nwbx scriptdecode <hex script>\n", .{});
                return;
            }
            const s = script.Script.decode(allocator, args[2]) catch {
                std.debug.print("Invalid script provided\n", .{});
                return;
            };
            defer s.deinit();

            std.debug.print("{}\n", .{s});
        },
        .txdecode => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Decode raw transaction\nwbx txdecode <raw transaction>\n", .{});
                return;
            }
            const transaction = tx.decodeRawTx(allocator, args[2]) catch {
                std.debug.print("Invalid rawtx provided\n", .{});
                return;
            };
            defer transaction.deinit();
            std.debug.print("{}\n", .{transaction});
        },
        .epknew => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Generate new private key. You can specify an existing seed or a random one will be used\nwbx epknew <mainnet/testnet> <?existing seed>\n", .{});
                return;
            }
            const addr_version: bip32.SerializedPrivateKeyVersion = if (std.mem.eql(u8, args[2], "mainnet")) .segwit_mainnet else .segwit_testnet;
            if (args.len > 3) {
                const seed = args[3][0..args[3].len];
                const bytes: []u8 = allocator.alloc(u8, seed.len / 2) catch {
                    std.debug.print("Error while allocating memory", .{});
                    return;
                };
                defer allocator.free(bytes);
                _ = try std.fmt.hexToBytes(bytes, seed);
                const epk = bip32.ExtendedPrivateKey.fromSeed(bytes);
                const addr = epk.address(addr_version, 0, [4]u8{ 0, 0, 0, 0 }, 0) catch {
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

                const epk = bip32.ExtendedPrivateKey.fromSeed(&seed);
                const addr = epk.address(addr_version, 0, [4]u8{ 0, 0, 0, 0 }, 0) catch {
                    std.debug.print("Error while generating address", .{});
                    return;
                };
                std.debug.print("Master private key: {s}\n", .{addr});
            }
        },
        .epktopublic => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Derive public key from a given private key in address form.\nwbx epktopublic <private key addr>\n", .{});
                return;
            }
            const epk = bip32.ExtendedPrivateKey.fromAddress(args[2][0..111].*) catch {
                std.debug.print("Invalid extended private key address", .{});
                return;
            };

            const public = try bip32.PublicKey.fromPrivateKey(epk.privatekey);
            const compressed = public.toCompressed();
            std.debug.print("Compressed public key {s}\n", .{compressed});
        },
        .derivation => {
            if (args.len < 5 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Bip32 derivation. Use ' to indicate hardened derivation.\nwbx hdderivation <private key addr> <path> <mainnet/testnet>\n", .{});
                return;
            }
            const addr_version: bip32.SerializedPrivateKeyVersion = if (std.mem.eql(u8, args[2], "mainnet")) .segwit_mainnet else .segwit_testnet;
            const epk = bip32.ExtendedPrivateKey.fromAddress(args[2][0..111].*) catch {
                std.debug.print("Invalid extended private key address", .{});
                return;
            };
            const path = args[3];
            var it = std.mem.tokenizeScalar(u8, path, '/');

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
            const public = try bip32.PublicKey.fromPrivateKey(epk.privatekey);
            const compressedpublic = public.toStrCompressed() catch {
                std.debug.print("Error while generating parent public key\n", .{});
                return;
            };

            var bytes: [33]u8 = undefined;
            _ = try std.fmt.hexToBytes(&bytes, &compressedpublic);
            const fingerprint = utils.hash160(&bytes)[0..4].*;
            const addr = current.address(addr_version, depth, fingerprint, lastindex) catch {
                std.debug.print("Error while converting to address\n", .{});
                return;
            };
            std.debug.print("private key: {s}\n", .{strprivate});
            std.debug.print("addr: {s}\n", .{addr});
        },
        .addr => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Generate Pay To Witness Public Key Address.\nwbx addr <compressed public key> <mainnet/testnet>\n", .{});
                return;
            }
            const network: Network = if (std.mem.eql(u8, args[3], "mainnet")) .mainnet else .testnet;
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

            const addr = deriveP2WPKHAddress(allocator, s, network) catch {
                std.debug.print("Error while generating address\n", .{});
                return;
            };
            defer addr.deinit();

            std.debug.print("Address {s}\n", .{addr.val});
        },
    }
}
