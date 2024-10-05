const std = @import("std");
const db = @import("db/db.zig");
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const bip44 = @import("bip44.zig");
const Network = @import("const.zig").Network;
const utils = @import("utils.zig");
const address = @import("address.zig");
const script = @import("script.zig");

fn showHelp() void {
    std.debug.print("Valid commands: walletcreate, walletimport\nFor more information use walle <cmd> help", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const Commands = enum {
        walletcreate,
        addrnew,
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

    var database = try db.openDB();
    defer db.closeDB(database);
    try db.initDB(&database);

    switch (cmd.?) {
        .walletcreate => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Create new wallet\nwalle walletcreate <mainnet/testnet>\n", .{});
                return;
            }

            const network: Network = if (std.mem.eql(u8, args[2], "mainnet")) .mainnet else .testnet;

            const total_descriptors = try db.countDescriptors(&database);
            if (total_descriptors > 0) {
                std.debug.print("Wallet already exists. Delete it before creating a new one.\n", .{});
                return;
            }

            const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");
            // defer wordlist.deinit();
            var entropy: [16]u8 = undefined;
            bip39.generateEntropy(&entropy, 128);
            var mnemonic: [12][]u8 = undefined;
            try bip39.generateMnemonic(allocator, &entropy, wordlist, &mnemonic);
            std.debug.print("This is your mnemonic. Save it offline and dont forget it, otherwise you will loose your funds\n", .{});
            for (mnemonic) |word| {
                std.debug.print("{s}    ", .{word});
            }
            std.debug.print("\n", .{});

            var seed: [64]u8 = undefined;
            try bip39.mnemonicToSeed(allocator, &mnemonic, "", &seed);
            const master_extended_privkey: bip32.ExtendedPrivateKey = bip32.generateExtendedMasterPrivateKey(&seed);

            const cointype: u32 = if (network == .mainnet) bip44.bitcoin_coin_type else bip44.bitcoin_testnet_coin_type;
            const descriptor_privkey = try bip44.generateDescriptorPrivate(master_extended_privkey, bip44.bip_84_purpose, cointype, 0);
            const pubkey = bip32.generatePublicKey(descriptor_privkey.privatekey);
            const pubkey_compressed = try pubkey.compress();

            const privkey_version: bip32.SerializedPrivateKeyVersion = if (network == .mainnet) .segwit_mainnet else .segwit_testnet;
            const pubkey_version: bip32.SerializedPublicKeyVersion = if (network == .mainnet) .segwit_mainnet else .segwit_testnet;
            const fingerprint = utils.hash160(&pubkey_compressed)[0..4].*;
            const addr_privkey = try descriptor_privkey.address(privkey_version, 3, fingerprint, 2147483648);
            const descriptor_priv = bip44.Descriptor{ .extended_key = addr_privkey, .keypath = bip44.KeyPath(3){ .path = [3]u32{ bip44.bip_84_purpose, cointype, 0 } }, .private = true };
            try db.saveDescriptor(allocator, &database, descriptor_priv);

            const extended_pubkey = bip32.ExtendedPublicKey{ .key = pubkey, .chaincode = descriptor_privkey.chaincode };
            const addr_pubkey = try extended_pubkey.address(pubkey_version, 3, fingerprint, 2147483648);
            const descriptor_pub = bip44.Descriptor{ .extended_key = addr_pubkey, .keypath = bip44.KeyPath(3){ .path = [3]u32{ bip44.bip_84_purpose, cointype, 0 } }, .private = false };
            try db.saveDescriptor(allocator, &database, descriptor_pub);

            std.debug.print("Wallet initialized\n", .{});
        },
        .addrnew => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Create new wallet\nwalle addrnew <mainnet/testnet>\n", .{});
                return;
            }

            const network: Network = if (std.mem.eql(u8, args[2], "mainnet")) .mainnet else .testnet;
            const res = try db.getLastUsedIndexFromOutputs(&database);
            var next_index: u32 = 0;
            if (res != null) {
                next_index = res.?;
            }

            var descriptor_path = "84'/1'/0'".*;
            const descriptor = try db.getDescriptor(allocator, &database, &descriptor_path, false);
            if (descriptor == null) {
                std.debug.print("A wallet do not exists. Please create it using walletcreate\n", .{});
                return;
            }
            // Generate index with change = 1 for external address
            const account_pubkey = try bip32.ExtendedPublicKey.fromAddress(descriptor.?.extended_key);
            const pubkey = try bip44.generatePublicFromAccountPublicKey(account_pubkey, bip44.change_external_chain, next_index);
            const pubkey_hash = try pubkey.toHashHex();
            const s = try script.p2wpkh(allocator, &pubkey_hash);
            const addr = try address.deriveP2WPKHAddress(allocator, s, network);
            defer addr.deinit();
            std.debug.print("addr {s}\n", .{addr.val});
        },
    }
}
