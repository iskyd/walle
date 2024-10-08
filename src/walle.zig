const std = @import("std");
const db = @import("db/db.zig");
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const bip44 = @import("bip44.zig");
const Network = @import("const.zig").Network;
const utils = @import("utils.zig");
const address = @import("address.zig");
const script = @import("script.zig");
const Output = @import("tx.zig").Output;
const tx = @import("tx.zig");
const sqlite = @import("sqlite");
const crypto = @import("crypto");

fn showHelp() void {
    std.debug.print("Valid commands: createwallet, newaddr, listoutputs, send\nFor more information use walle <cmd> help", .{});
}

fn generateNextAvailableAddress(allocator: std.mem.Allocator, database: *sqlite.Db, descriptor: bip44.Descriptor, change: u8, network: Network) !address.Address {
    const descriptor_path = try descriptor.keypath.toStr(allocator, null);
    const base_path = try allocator.alloc(u8, descriptor_path.len + 4);
    defer allocator.free(base_path);
    _ = try std.fmt.bufPrint(base_path, "{s}/{d}/%", .{ descriptor_path, change });
    const res = try db.getLastUsedIndexFromOutputs(database, base_path);
    var next_index: u32 = 0;
    if (res != null) {
        next_index = res.?;
    }

    // Generate index with change = 1 for external address
    const account_pubkey = try bip32.ExtendedPublicKey.fromAddress(descriptor.extended_key);
    const pubkey = try bip44.generatePublicFromAccountPublicKey(account_pubkey, change, next_index);
    const pubkey_hash = try pubkey.toHashHex();
    const s = try script.p2wpkh(allocator, &pubkey_hash);
    const addr = try address.deriveP2WPKHAddress(allocator, s, network);
    return addr;
}

fn getDescriptorPath(network: Network) ![9]u8 {
    var descriptor_path: [9]u8 = undefined;
    const cointype: u8 = if (network == .mainnet) bip44.bitcoin_coin_type else bip44.bitcoin_testnet_coin_type;
    _ = try std.fmt.bufPrint(&descriptor_path, "{d}'/{d}'/{d}'", .{ bip44.bip_84_purpose, cointype, 0 });

    return descriptor_path;
}

fn addressToScript(allocator: std.mem.Allocator, addr: []const u8) ![]u8 {
    var pubkey_hash: [20]u8 = undefined;
    _ = try crypto.Bech32Decoder.decode(&pubkey_hash, addr);
    var pubkey_hash_hex: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&pubkey_hash_hex, "{x}", .{std.fmt.fmtSliceHexLower(&pubkey_hash)});
    const s = try script.p2wpkh(allocator, &pubkey_hash_hex);
    defer s.deinit();
    const cap = s.hexCap();
    const buffer = try allocator.alloc(u8, cap);
    try s.toHex(buffer);
    return buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const Commands = enum {
        createwallet,
        newaddr,
        listoutputs,
        send,
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
        .createwallet => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Create new wallet\nwalle createwallet <mainnet/testnet>\n", .{});
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
        .newaddr => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Create new wallet\nwalle newaddr <mainnet/testnet>\n", .{});
                return;
            }

            const network: Network = if (std.mem.eql(u8, args[2], "mainnet")) .mainnet else .testnet;
            const descriptor_path = try getDescriptorPath(network);
            const descriptor = try db.getDescriptor(allocator, &database, &descriptor_path, false);
            if (descriptor == null) {
                std.debug.print("A wallet do not exists. Please create it using walletcreate\n", .{});
                return;
            }
            const addr = try generateNextAvailableAddress(allocator, &database, descriptor.?, bip44.change_external_chain, network);
            defer addr.deinit();
            std.debug.print("addr {s}\n", .{addr.val});
        },
        .listoutputs => {
            if (args.len > 2) {
                std.debug.print("List all the outputs\n", .{});
                return;
            }

            const outputs = try db.getUnspentOutputs(allocator, &database);
            defer allocator.free(outputs);

            var balance: usize = 0;
            std.debug.print("Available outputs\n", .{});
            for (outputs) |output| {
                std.debug.print("Output txid={s} vout={d} -> amount = {d}\n", .{ output.txid, output.vout, output.amount });
                balance += output.amount;
            }
            std.debug.print("Avaiable balance = {d}\n", .{balance});
        },
        .send => {
            // TODO: change 3 to 7
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Send BTC to an address (support only segwit address)\nwalle send <network> <segwit addr> <amount> <total outputs to use> [<output n txid> <output n vout>]\n", .{});
                return;
            }

            const network: Network = if (std.mem.eql(u8, args[2], "mainnet")) .mainnet else .testnet;
            const destination_address = args[3];
            const amount = try std.fmt.parseInt(usize, args[4], 10);
            const total_outputs = try std.fmt.parseInt(usize, args[5], 10);

            std.debug.print("Sending to {s} an amount of {d} using {d} outputs\n", .{ destination_address, amount, total_outputs });

            const outputs = try allocator.alloc(Output, total_outputs);
            var total_available_amount: usize = 0;
            for (0..total_outputs) |i| {
                const txid: [64]u8 = args[6 + (i * 2)][0..64].*;
                const vout = try std.fmt.parseInt(u32, args[7 + (i * 2)], 10);

                const output = try db.getOutput(allocator, &database, txid, vout);
                if (output == null) {
                    std.debug.print("Specified output with txid {s} and vout {d} does not exist\n", .{ txid, vout });
                    return;
                }
                if (output.?.unspent.? != true) {
                    std.debug.print("Specified output with txid {s} and vout {d} is already spent\n", .{ txid, vout });
                    return;
                }
                total_available_amount += output.?.amount;
                outputs[i] = output.?;
            }

            const mining_fee = 100;
            if (total_available_amount < amount - mining_fee) {
                std.debug.print("Specified outputs amount is {d} while the amount you're trying to spend is {d}.\n", .{ total_available_amount, amount });
                return;
            }

            const descriptor_path = try getDescriptorPath(network);
            const descriptor = try db.getDescriptor(allocator, &database, &descriptor_path, false);
            if (descriptor == null) {
                std.debug.print("A wallet do not exists. Please create it using walletcreate\n", .{});
                return;
            }

            var pubkeys = std.AutoHashMap([72]u8, bip32.PublicKey).init(allocator);
            var privkeys = std.AutoHashMap([72]u8, [32]u8).init(allocator);
            const tx_inputs = try allocator.alloc(tx.TxInput, outputs.len);
            for (outputs, 0..) |output, i| {
                tx_inputs[i] = try tx.TxInput.init(allocator, output, "", 4294967293); // This sequence will enable both locktime and rbf
                var map_key: [72]u8 = undefined;
                var vout_hex: [8]u8 = undefined;
                try utils.intToHexStr(u32, @byteSwap(output.vout), &vout_hex);
                _ = try std.fmt.bufPrint(&map_key, "{s}{s}", .{ output.txid, vout_hex });

                const output_descriptor_path = try output.keypath.?.toStr(allocator, 3);

                const public_descriptor = try db.getDescriptor(allocator, &database, output_descriptor_path, false);
                const private_descriptor = try db.getDescriptor(allocator, &database, output_descriptor_path, true);

                const extended_pubkey = try bip32.ExtendedPublicKey.fromAddress(public_descriptor.?.extended_key);
                const pubkey = try bip44.generatePublicFromAccountPublicKey(extended_pubkey, output.keypath.?.path[3], output.keypath.?.path[4]);

                const extended_privkey = try bip32.ExtendedPrivateKey.fromAddress(private_descriptor.?.extended_key);
                const privkey = try bip44.generatePrivateFromAccountPrivateKey(extended_privkey, output.keypath.?.path[3], output.keypath.?.path[4]);

                try pubkeys.put(map_key, pubkey);
                try privkeys.put(map_key, privkey);
            }
            const change_amount = total_available_amount - amount - mining_fee;
            const tx_outputs_cap: u8 = if (change_amount > 0) 2 else 1;
            const tx_outputs = try allocator.alloc(tx.TxOutput, tx_outputs_cap);
            const script_pubkey_output = try addressToScript(allocator, destination_address);
            tx_outputs[0] = try tx.TxOutput.init(allocator, amount, script_pubkey_output);
            if (change_amount > 0) {
                // Change address
                const change_addr = try generateNextAvailableAddress(allocator, &database, descriptor.?, bip44.change_internal_chain, network);
                const script_pubkey_change = try addressToScript(allocator, change_addr.val);
                tx_outputs[1] = try tx.TxOutput.init(allocator, change_amount, script_pubkey_change);
            }

            var send_transaction = try tx.createTx(allocator, tx_inputs, tx_outputs);

            try tx.signTx(allocator, &send_transaction, privkeys, pubkeys, null);
            std.debug.print("send transaction\n{}\n", .{send_transaction});
        },
    }
}
