const std = @import("std");
const db = @import("db/db.zig");
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const Network = @import("const.zig").Network;
const utils = @import("utils.zig");
const address = @import("address.zig");
const script = @import("script.zig");
const Output = @import("tx.zig").Output;
const tx = @import("tx.zig");
const sqlite = @import("sqlite");
const crypto = @import("crypto");
const rpc = @import("rpc/rpc.zig");
const keypath = @import("keypath.zig");

fn showHelp() void {
    std.debug.print("Valid commands: createwallet, newaddr, listoutputs, send\nFor more information use walle <cmd> help", .{});
}

fn generateNextAvailableAddress(allocator: std.mem.Allocator, database: *sqlite.Db, descriptor: keypath.Descriptor, change: u8, network: Network) !address.Address {
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
    const kp = keypath.KeyPath(2){ .path = [2]keypath.KeyPathElement{ keypath.KeyPathElement{ .value = change, .is_hardened = false }, keypath.KeyPathElement{ .value = next_index, .is_hardened = false } } };
    const pubkey = try bip32.deriveChildFromKeyPath(bip32.ExtendedPublicKey, account_pubkey, 2, kp);
    const pubkey_hash = try pubkey.key.toHashHex();
    const s = try script.p2wpkh(allocator, &pubkey_hash);
    const addr = try address.deriveP2WPKHAddress(allocator, s, network);
    return addr;
}

fn getDescriptorPath(network: Network) ![9]u8 {
    var descriptor_path: [9]u8 = undefined;
    const cointype: u8 = if (network == .mainnet) keypath.bitcoin_coin_type else keypath.bitcoin_testnet_coin_type;
    _ = try std.fmt.bufPrint(&descriptor_path, "{d}'/{d}'/{d}'", .{ keypath.bip_84_purpose, cointype, 0 });

    return descriptor_path;
}

fn addressToScript(allocator: std.mem.Allocator, addr: []const u8) ![]u8 {
    var pubkey_hash: [20]u8 = undefined;
    _ = try crypto.Bech32Decoder.decode(&pubkey_hash, addr);
    var pubkey_hash_hex: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&pubkey_hash_hex, "{x}", .{std.fmt.fmtSliceHexLower(&pubkey_hash)});
    const s = try script.p2wpkh(allocator, &pubkey_hash_hex);
    defer s.deinit();
    const cap = s.hexCapBytes();
    const buffer = try allocator.alloc(u8, cap);
    try s.toBytes(allocator, buffer);
    return buffer;
}

fn getNetworkFromStr(str: []u8) Network {
    const n = std.meta.stringToEnum(Network, str);
    if (n == null) {
        unreachable;
    }

    return n.?;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const Commands = enum {
        createwallet,
        newaddr,
        listoutputs,
        send,
        broadcasttx,
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

            const network = getNetworkFromStr(args[2]);

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
            const master_extended_privkey: bip32.ExtendedPrivateKey = bip32.ExtendedPrivateKey.fromSeed(&seed);

            const cointype: u32 = if (network == .mainnet) keypath.bitcoin_coin_type else keypath.bitcoin_testnet_coin_type;
            const kp = keypath.KeyPath(3){ .path = [3]keypath.KeyPathElement{ keypath.KeyPathElement{ .value = keypath.bip_84_purpose, .is_hardened = true }, keypath.KeyPathElement{ .value = cointype, .is_hardened = true }, keypath.KeyPathElement{ .value = 0, .is_hardened = true } } };
            const descriptor_privkey = try bip32.deriveChildFromKeyPath(bip32.ExtendedPrivateKey, master_extended_privkey, 3, kp);
            const pubkey = try bip32.PublicKey.fromPrivateKey(descriptor_privkey.privatekey);
            const pubkey_compressed = pubkey.toCompressed();

            const privkey_version: bip32.SerializedPrivateKeyVersion = if (network == .mainnet) .segwit_mainnet else .segwit_testnet;
            const pubkey_version: bip32.SerializedPublicKeyVersion = if (network == .mainnet) .segwit_mainnet else .segwit_testnet;
            const fingerprint = utils.hash160(&pubkey_compressed)[0..4].*;
            const addr_privkey = try descriptor_privkey.address(privkey_version, 3, fingerprint, 2147483648);
            const descriptor_priv = keypath.Descriptor{ .extended_key = addr_privkey, .keypath = kp, .private = true };
            try db.saveDescriptor(allocator, &database, descriptor_priv);

            const extended_pubkey = bip32.ExtendedPublicKey{ .key = pubkey, .chaincode = descriptor_privkey.chaincode };
            const addr_pubkey = try extended_pubkey.address(pubkey_version, 3, fingerprint, 2147483648);
            const descriptor_pub = keypath.Descriptor{ .extended_key = addr_pubkey, .keypath = kp, .private = false };
            try db.saveDescriptor(allocator, &database, descriptor_pub);

            std.debug.print("Wallet initialized\n", .{});
        },
        .newaddr => {
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Create new wallet\nwalle newaddr <mainnet/testnet>\n", .{});
                return;
            }

            const network = getNetworkFromStr(args[2]);
            const descriptor_path = try getDescriptorPath(network);
            const descriptor = try db.getDescriptor(allocator, &database, &descriptor_path, false);
            if (descriptor == null) {
                std.debug.print("A wallet do not exists. Please create it using walletcreate\n", .{});
                return;
            }
            const addr = try generateNextAvailableAddress(allocator, &database, descriptor.?, keypath.external_chain, network);
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
                std.debug.print("Output txid={s} vout={d} -> amount = {d}\n", .{ try utils.bytesToHex(64, &output.outpoint.txid), output.outpoint.vout, output.amount });
                balance += output.amount;
            }
            std.debug.print("Available balance = {d}\n", .{balance});
        },
        .send => {
            // TODO: change 3 to 7
            if (args.len < 3 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Send BTC to an address (support only segwit address)\nwalle send <network> <segwit addr> <amount> <total outputs to use> [<output n txid> <output n vout>]\n", .{});
                return;
            }

            const network = getNetworkFromStr(args[2]);
            const destination_address = args[3];
            const amount = try std.fmt.parseInt(usize, args[4], 10);
            const total_utxos = try std.fmt.parseInt(usize, args[5], 10);

            std.debug.print("Sending to {s} an amount of {d} using {d} outputs\n", .{ destination_address, amount, total_utxos });

            const utxos = try allocator.alloc(Output, total_utxos);
            var total_available_amount: usize = 0;
            for (0..total_utxos) |i| {
                const txid: [32]u8 = try utils.hexToBytes(32, args[6 + (i * 2)][0..64]);
                const vout = try std.fmt.parseInt(u32, args[7 + (i * 2)], 10);

                const utxo = try db.getOutput(allocator, &database, txid, vout);
                if (utxo == null) {
                    std.debug.print("Specified output with txid {s} and vout {d} does not exist\n", .{ txid, vout });
                    return;
                }
                if (utxo.?.unspent.? != true) {
                    std.debug.print("Specified output with txid {s} and vout {d} is already spent\n", .{ txid, vout });
                    return;
                }
                total_available_amount += utxo.?.amount;
                utxos[i] = utxo.?;
            }

            const mining_fee = 1000;
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

            const change_amount = total_available_amount - amount - mining_fee;
            const tx_outputs_cap: u8 = if (change_amount > 0) 2 else 1;
            const tx_outputs = try allocator.alloc(tx.TxOutput, tx_outputs_cap);
            const script_pubkey_output = try addressToScript(allocator, destination_address);
            tx_outputs[0] = try tx.TxOutput.init(allocator, amount, script_pubkey_output);
            if (change_amount > 0) {
                // Change address
                const change_addr = try generateNextAvailableAddress(allocator, &database, descriptor.?, keypath.internal_chain, network);
                const script_pubkey_change = try addressToScript(allocator, change_addr.val);
                tx_outputs[1] = try tx.TxOutput.init(allocator, change_amount, script_pubkey_change);
            }

            const tx_inputs = try allocator.alloc(tx.TxInput, utxos.len);
            const all_outpoints = try allocator.alloc(tx.Outpoint, utxos.len);
            const witnesses = try allocator.alloc(tx.TxWitness, utxos.len);
            for (utxos, 0..) |utxo, i| {
                all_outpoints[i] = utxo.outpoint;
            }

            for (utxos, 0..) |utxo, i| {
                const sequence: u32 = 4294967293; // This sequence will enable both locktime and rbf
                tx_inputs[i] = try tx.TxInput.init(allocator, utxo.outpoint, "", sequence);
                const output_descriptor_path = try utxo.keypath.?.toStr(allocator, 3);

                const public_descriptor = try db.getDescriptor(allocator, &database, output_descriptor_path, false);
                const private_descriptor = try db.getDescriptor(allocator, &database, output_descriptor_path, true);

                const extended_pubkey = try bip32.ExtendedPublicKey.fromAddress(public_descriptor.?.extended_key);
                const kp = keypath.KeyPath(2){ .path = [2]keypath.KeyPathElement{ keypath.KeyPathElement{ .value = utxo.keypath.?.path[3].value, .is_hardened = false }, keypath.KeyPathElement{ .value = utxo.keypath.?.path[4].value, .is_hardened = false } } };
                const pubkey: bip32.ExtendedPublicKey = try bip32.deriveChildFromKeyPath(bip32.ExtendedPublicKey, extended_pubkey, 2, kp);

                const extended_privkey = try bip32.ExtendedPrivateKey.fromAddress(private_descriptor.?.extended_key);
                const privkey: bip32.ExtendedPrivateKey = try bip32.deriveChildFromKeyPath(bip32.ExtendedPrivateKey, extended_privkey, 2, kp);

                var scriptcode_hex: [50]u8 = undefined; // scriptcode is 1976a914{publickeyhash}88ac
                const pubkeyhash = try pubkey.key.toHashHex();
                _ = try std.fmt.bufPrint(&scriptcode_hex, "76a914{s}88ac", .{pubkeyhash});
                const scriptcode = try utils.hexToBytes(25, &scriptcode_hex);

                const commitment_hash = try tx.getCommitmentHash(allocator, utxo.outpoint, @as(u32, @intCast(utxo.amount)), &scriptcode, all_outpoints, tx_outputs, 2, sequence, 0, .sighash_all);

                witnesses[i] = try tx.getP2WPKHWitness(allocator, privkey.privatekey, commitment_hash, .sighash_all);
            }

            var send_transaction = try tx.createTx(allocator, tx_inputs, tx_outputs);
            for (witnesses) |witness| {
                try send_transaction.addWitness(witness);
            }

            const raw_tx_cap = tx.encodeTxCap(send_transaction, true);
            const raw_tx = try allocator.alloc(u8, raw_tx_cap);
            const raw_tx_hex = try allocator.alloc(u8, raw_tx_cap * 2);
            try tx.encodeTx(allocator, raw_tx, send_transaction, true);
            _ = try std.fmt.bufPrint(raw_tx_hex, "{x}", .{std.fmt.fmtSliceHexLower(raw_tx)});

            std.debug.print("\n{s}\n", .{raw_tx_hex});
        },
        .broadcasttx => {
            if (args.len < 6 or std.mem.eql(u8, args[2], "help")) {
                std.debug.print("Broadcast tx <rpc location> <rpc user> <rpc password> <raw tx>\n", .{});
                return;
            }
            const rpc_location = args[2];
            const rpc_user = args[3];
            const rpc_password = args[4];
            const raw_tx = args[5];

            std.debug.print("rpc location {s}\n", .{rpc_location});

            const auth = try rpc.generateAuth(allocator, rpc_user, rpc_password);
            defer allocator.free(auth);
            var client = std.http.Client{ .allocator = allocator };
            defer client.deinit();
            try rpc.sendRawTx(allocator, &client, rpc_location, auth, raw_tx);

            std.debug.print("Transaction broadcasted\n", .{});
        },
    }
}
