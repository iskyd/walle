const std = @import("std");
const Block = @import("block.zig").Block;
const tx = @import("tx.zig");
const Output = tx.Output;
const Input = tx.Input;
const ExtendedPublicKey = @import("bip32.zig").ExtendedPublicKey;
const PublicKey = @import("bip32.zig").PublicKey;
const bip44 = @import("bip44.zig");
const KeyPath = bip44.KeyPath;
const Descriptor = bip44.Descriptor;
const Network = @import("const.zig").Network;
const script = @import("script.zig");
const utils = @import("utils.zig");
const clap = @import("clap");
const rpc = @import("rpc/rpc.zig");
const db = @import("db/db.zig");
const sqlite = @import("sqlite");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig.\nIndexer...\n", .{});
    var database = try db.openDB();
    defer db.closeDB(database);
    try db.initDB(&database);

    // use 12 megabyte as fixed buffer. it should be enough for any block.
    var fb: [1024 * 1024 * 12]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fb);
    const fbaallocator = fba.allocator();
    var arena = std.heap.ArenaAllocator.init(fbaallocator);
    const aa = arena.allocator();
    defer arena.deinit();

    // used for everything else
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-u, --user <str>       User
        \\-p, --password <str>   Password
        \\-l, --location <str>   Location
    );

    var diag = clap.Diagnostic{};
    const res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        // Report useful error and exit
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };

    if (res.args.help != 0) {
        return clap.usage(std.io.getStdErr().writer(), clap.Help, &params);
    }

    const auth = try rpc.generateAuth(allocator, res.args.user.?, res.args.password.?);
    defer allocator.free(auth);
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const block_count = try rpc.getBlockCount(allocator, &client, res.args.location.?, auth);
    std.debug.print("Total blocks {d}\n", .{block_count});
    const current_block_count = try db.getCurrentBlockHeigth(&database);
    std.debug.print("Current blocks {?d}\n", .{current_block_count});
    if (current_block_count != null and block_count == current_block_count) {
        std.debug.print("Already indexed, do nothing\n", .{});
        const balance = try db.getBalance(&database, current_block_count.?);
        std.debug.print("Current balance: {d}\n", .{balance});
        return;
    }

    // Load descriptors
    const descriptors = try db.getDescriptors(allocator, &database);
    defer allocator.free(descriptors);

    for (descriptors) |descriptor| {
        std.debug.print("Descriptor: extended key = {s}, path = {d}'/{d}'/{d}'\n", .{ descriptor.extended_key, descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2] });
    }

    std.debug.print("init key generation\n", .{});
    // use hashmap to store public key hash for fast check
    var pubkeys = std.AutoHashMap([40]u8, KeyPath(5)).init(allocator);
    defer pubkeys.deinit();
    var keypaths = std.AutoHashMap(KeyPath(5), Descriptor).init(allocator);
    defer keypaths.deinit();
    var descriptors_map = std.AutoHashMap(KeyPath(3), [111]u8).init(allocator);
    defer descriptors_map.deinit();
    for (descriptors) |descriptor| {
        try descriptors_map.put(descriptor.keypath, descriptor.extended_key);
    }

    const account_pubkeys = try allocator.alloc(ExtendedPublicKey, descriptors.len);
    defer allocator.free(account_pubkeys);
    const keypaths_used = try db.getUsedKeyPaths(allocator, &database);
    defer allocator.free(keypaths_used);

    for (keypaths_used) |keypath| {
        const existing = keypaths.get(keypath);
        if (existing != null) {
            continue;
        }

        const d = KeyPath(3){ .path = [3]u32{ keypath.path[0], keypath.path[1], keypath.path[3] } };
        const pubkey_addr = descriptors_map.get(d);
        if (pubkey_addr == null) {
            std.debug.print("descriptor not found for path {d}'/{d}'/{d}'\n", .{ d.path[0], d.path[1], d.path[2] });
            continue;
        }

        // Generate the current used keypath and public key
        const extended_pubkey = try ExtendedPublicKey.fromAddress(pubkey_addr.?);
        try keypaths.put(keypath, Descriptor{ .extended_key = pubkey_addr.?, .keypath = d, .private = false });
        const pubkey = try bip44.generatePublicFromAccountPublicKey(extended_pubkey, keypath.path[3], keypath.path[4]);
        const pubkey_hash = try pubkey.toHashHex();
        try pubkeys.put(pubkey_hash, keypath);

        // Generate the next one
        const next_pubkey = try bip44.generatePublicFromAccountPublicKey(extended_pubkey, keypath.path[3], keypath.path[4] + 1);
        const next_pubkey_hash = try next_pubkey.toHashHex();
        try pubkeys.put(next_pubkey_hash, keypath.getNext(1));
    }

    for (descriptors) |descriptor| {
        const account_pubkey = try ExtendedPublicKey.fromAddress(descriptor.extended_key);

        const keypath_internal = KeyPath(5){ .path = [5]u32{ descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2], bip44.change_internal_chain, 0 } };
        if (keypaths.get(keypath_internal) == null) {
            const internal_pubkey = try bip44.generatePublicFromAccountPublicKey(account_pubkey, bip44.change_internal_chain, 0);
            const internal_pubkey_hash = try internal_pubkey.toHashHex();
            try keypaths.put(keypath_internal, descriptor);
            try pubkeys.put(internal_pubkey_hash, keypath_internal);
        }

        const keypath_external = KeyPath(5){ .path = [5]u32{ descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2], bip44.change_external_chain, 0 } };
        if (keypaths.get(keypath_external) == null) {
            const external_pubkey = try bip44.generatePublicFromAccountPublicKey(account_pubkey, bip44.change_external_chain, 0);
            const external_pubkey_hash = try external_pubkey.toHashHex();
            try keypaths.put(keypath_external, descriptor);
            try pubkeys.put(external_pubkey_hash, keypath_external);
        }
    }

    std.debug.print("keys generated\n", .{});

    var progress = std.Progress.start(.{});
    const progressbar = progress.start("indexing", block_count);
    defer progressbar.end();

    const start: usize = if (current_block_count == null) 0 else current_block_count.?;

    for (start..block_count + 1) |i| {
        // [72]u8 is for txid + vout in hex format
        var outputs = std.AutoHashMap([72]u8, Output).init(aa);
        // [64]u8 is for txid, bool is for isCoinbase
        var relevant_transactions = std.AutoHashMap([64]u8, bool).init(aa);
        const blockhash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);

        const raw_transactions = try rpc.getBlockRawTx(aa, &client, res.args.location.?, auth, blockhash);
        var raw_transactions_map = std.AutoHashMap([64]u8, []u8).init(aa);

        const block_transactions = try aa.alloc(tx.Transaction, raw_transactions.len);
        for (raw_transactions, 0..) |tx_raw, j| {
            const transaction = try tx.decodeRawTx(aa, tx_raw);
            block_transactions[j] = transaction;
        }

        // Following BIP44 a wallet must not allow the derivation of a new address if the previous one is not used
        // So we start by creating 1 new key (both internal and external)
        // Everytime we found a new output we need to generate the next key and re-index the same block to be sure all outputs are included
        while (true) blk: {
            for (block_transactions, 0..) |transaction, k| {
                const raw = raw_transactions[k];
                const txid = try transaction.getTXID();
                try raw_transactions_map.put(txid, raw);

                const txoutputs = try getOutputsFor(aa, transaction, pubkeys);
                if (txoutputs.items.len == 0) {
                    break;
                }

                _ = try relevant_transactions.getOrPutValue(txid, transaction.isCoinbase());

                for (0..txoutputs.items.len) |j| {
                    const txoutput = txoutputs.items[j];
                    // We need to generate the key with idx + n if it doesnt already exists
                    const keypath = txoutput.keypath.?;
                    const next = keypath.getNext(1);
                    const existing = keypaths.get(next);

                    // If we are generating a new key and the output is new we start re-indexing the block
                    // This ensure the fact that we collect all the outputs since the new key could have been used in previous tx in the same block
                    var vout_hex: [8]u8 = undefined;
                    try utils.intToHexStr(u32, txoutput.vout, &vout_hex);
                    var key: [72]u8 = undefined;
                    _ = try std.fmt.bufPrint(&key, "{s}{s}", .{ txoutput.txid, vout_hex });

                    const o = try outputs.getOrPut(key);
                    o.value_ptr.* = txoutput;
                    if (existing == null) {
                        const descriptor = keypaths.get(keypath);
                        // Generate the next key
                        const account_pubkey = try ExtendedPublicKey.fromAddress(descriptor.?.extended_key);
                        const next_pubkey = try bip44.generatePublicFromAccountPublicKey(account_pubkey, next.path[3], next.path[4]);
                        const next_pubkey_hash = try next_pubkey.toHashHex();
                        try pubkeys.put(next_pubkey_hash, next);
                        try keypaths.put(next, descriptor.?);

                        if (o.found_existing == false) {
                            break :blk;
                        }
                    }
                }
            }

            break;
        }

        const tx_inputs = try getInputsFor(aa, &database, block_transactions);
        defer tx_inputs.deinit();
        for (0..tx_inputs.items.len) |k| {
            const tx_input = tx_inputs.items[k];
            _ = try relevant_transactions.getOrPutValue(tx_input.txid, false); // false because if we are using inputs then the current tx is not coinbase
        }

        if (outputs.count() > 0) {
            try db.saveOutputs(aa, &database, outputs);
        }
        if (tx_inputs.items.len > 0) {
            try db.saveInputsAndMarkOutputs(&database, tx_inputs);
        }
        if (relevant_transactions.count() > 0) {
            var it = relevant_transactions.keyIterator();
            while (it.next()) |txid| {
                const raw = raw_transactions_map.get(txid.*).?;
                const is_coinbase = relevant_transactions.get(txid.*).?;
                try db.saveTransaction(&database, txid.*, raw, is_coinbase, i);
            }
        }
        // Since db writes are not in a single transaction we commit block as lastest so that if we restart we dont't risk loosing informations, once block is persisted we are sure outputs, inputs and relevant transactions in that block are persisted too. We can recover from partial commit simply reindexing the block.
        try db.saveBlock(&database, blockhash, i);

        progressbar.completeOne();
        _ = arena.reset(.free_all);
    }

    std.debug.print("indexing completed\n", .{});
}

// return hex value of pubkey hash
// Memory ownership to the caller
fn outputToPubkeysHash(allocator: std.mem.Allocator, output: tx.TxOutput) ![][40]u8 {
    const s = try script.Script.decode(allocator, output.script_pubkey);
    const pubkey_hash = try s.getValues(allocator);
    return pubkey_hash;
}

fn getOutputsFor(allocator: std.mem.Allocator, transaction: tx.Transaction, pubkeys: std.AutoHashMap([40]u8, KeyPath(5))) !std.ArrayList(Output) {
    var outputs = std.ArrayList(Output).init(allocator);
    for (0..transaction.outputs.items.len) |i| {
        const tx_output = transaction.outputs.items[i];
        const output_pubkeys_hash = try outputToPubkeysHash(allocator, tx_output);
        for (output_pubkeys_hash) |output_pubkey_hash| {
            const pubkey = pubkeys.get(output_pubkey_hash);
            if (pubkey != null) {
                const txid = try transaction.getTXID();
                const vout = @as(u32, @intCast(i));
                const output = Output{ .txid = txid, .vout = vout, .keypath = pubkey.?, .amount = tx_output.amount, .unspent = true };
                try outputs.append(output);
                break;
            }
        }
    }
    return outputs;
}

fn getInputsFor(allocator: std.mem.Allocator, database: *sqlite.Db, transactions: []tx.Transaction) !std.ArrayList(Input) {
    var inputs = std.ArrayList(Input).init(allocator);
    for (transactions) |transaction| {
        for (0..transaction.inputs.items.len) |i| {
            //coinbase tx does not refer to any prev output
            if (transaction.isCoinbase()) {
                continue;
            }
            const input = transaction.inputs.items[i];
            const existing = try db.getOutput(database, input.prevout.?.txid, input.prevout.?.vout);
            if (existing != null) {
                const txid = try transaction.getTXID();
                try inputs.append(.{ .txid = txid, .output_txid = existing.?.txid, .output_vout = existing.?.vout });
            }
        }
    }
    return inputs;
}
