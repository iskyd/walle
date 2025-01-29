const std = @import("std");
const tx = @import("tx.zig");
const Output = tx.Output;
const Outpoint = tx.Outpoint;
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
    const rpc_location = res.args.location.?;

    // Manage fork.
    const last_block = try db.getLastBlock(&database);
    var current_block_height: ?usize = if (last_block != null) last_block.?.height else null;
    std.debug.print("last block {?d}\n", .{current_block_height});

    if (current_block_height != null) {
        while (current_block_height.? > 0) {
            const b = try db.getBlock(&database, current_block_height.?);
            const node_block_hash = try rpc.getBlockHash(allocator, &client, rpc_location, auth, current_block_height.?);
            if (std.mem.eql(u8, &b.hash, &try utils.hexToBytes(32, &node_block_hash))) {
                break;
            }
            current_block_height.? -= 1;
        }

        // Fork happened. Delete everything we have next to the current_height block
        if (current_block_height.? < last_block.?.height) {
            try db.deleteOutputsFromBlockHeight(&database, current_block_height.?);
            try db.deleteInputsFromBlockHeight(&database, current_block_height.?);
            try db.deleteTransactionsFromBlockHeight(&database, current_block_height.?);

            // Blocks need to be the last one since this db transactions are not atomic.
            try db.deleteBlocksFromBlockHeight(&database, current_block_height.?);
        }
    }

    const block_height = try rpc.getBlockCount(allocator, &client, rpc_location, auth);
    std.debug.print("Total blocks {d}\n", .{block_height});
    std.debug.print("Current blocks {?d}\n", .{current_block_height});
    if (current_block_height != null and block_height == current_block_height.?) {
        std.debug.print("Already indexed, do nothing\n", .{});
        const balance = try db.getBalance(&database, current_block_height.?);
        std.debug.print("Current balance: {d}\n", .{balance});
        return;
    }

    // Load descriptors
    const descriptors = try db.getDescriptors(allocator, &database, false); // only public descriptors
    defer allocator.free(descriptors);

    for (descriptors) |descriptor| {
        std.debug.print("Descriptor: extended key = {s}, path = {d}'/{d}'/{d}'\n", .{ descriptor.extended_key, descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2] });
    }

    std.debug.print("init key generation\n", .{});
    // use hashmap to store public key hash for fast check
    var pubkeys = std.AutoHashMap([20]u8, KeyPath(5)).init(allocator);
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

    // For every descriptor we get the latest used index (if one) and generate all the keys to this latest index + 1
    // Otherwise we only derive the first keypath (.../0)
    for (descriptors) |descriptor| {
        const keypath_cap = descriptor.keypath.getStrCap(null) + 2; // + 2 for /0 or /1 (internal / external)
        const keypath_internal_str = try allocator.alloc(u8, keypath_cap);
        defer allocator.free(keypath_internal_str);
        const keypath_external_str = try allocator.alloc(u8, keypath_cap);
        defer allocator.free(keypath_external_str);
        const partial_keypath_str = try descriptor.keypath.toStr(allocator, null);
        defer allocator.free(partial_keypath_str);
        _ = try std.fmt.bufPrint(keypath_internal_str, "{s}/{d}", .{ partial_keypath_str, bip44.change_internal_chain });
        _ = try std.fmt.bufPrint(keypath_external_str, "{s}/{d}", .{ partial_keypath_str, bip44.change_external_chain });

        const last_internal_index = try db.getLastUsedIndexFromOutputs(&database, keypath_internal_str);
        const last_external_index = try db.getLastUsedIndexFromOutputs(&database, keypath_internal_str);
        var last_indexes: [2]i64 = [2]i64{ -1, -1 };
        if (last_internal_index != null) {
            last_indexes[0] = last_internal_index.?;
        }
        if (last_external_index != null) {
            last_indexes[1] = last_external_index.?;
        }

        for (last_indexes, 0..) |last_index, t| {
            // This depends on the order specified above. Improve this behaviour pls.
            const change_type: u32 = if (t == 0) bip44.change_internal_chain else bip44.change_external_chain;
            for (0..@as(usize, @intCast(last_index + 2))) |i| {
                const pubkey_addr = descriptors_map.get(descriptor.keypath);
                if (pubkey_addr == null) {
                    std.debug.print("descriptor not found for path {d}'/{d}'/{d}'\n", .{ descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2] });
                    continue;
                }

                const keypath = KeyPath(5){ .path = [5]u32{ descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2], change_type, @as(u32, @intCast(i)) } };

                const extended_pubkey = try ExtendedPublicKey.fromAddress(pubkey_addr.?);
                try keypaths.put(keypath, Descriptor{ .extended_key = pubkey_addr.?, .keypath = descriptor.keypath, .private = false });
                const pubkey = try bip44.generatePublicFromAccountPublicKey(extended_pubkey, keypath.path[3], keypath.path[4]);
                const pubkey_hash = try pubkey.toHash();
                try pubkeys.put(pubkey_hash, keypath);
            }
        }
    }

    std.debug.print("keys generated\n", .{});

    var progress = std.Progress.start(.{});
    const progressbar = progress.start("indexing", block_height);
    defer progressbar.end();

    const start: usize = if (current_block_height == null) 0 else current_block_height.? + 1;

    for (start..block_height + 1) |i| {
        // [72]u8 is for txid + vout in hex format
        var outputs = std.ArrayList(Output).init(aa);
        // [64]u8 is for txid, bool is for isCoinbase
        var relevant_transactions = std.AutoHashMap([32]u8, bool).init(aa);
        const blockhash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);

        const raw_transactions = try rpc.getBlockRawTx(aa, &client, res.args.location.?, auth, blockhash);
        var raw_transactions_map = std.AutoHashMap([32]u8, []u8).init(aa);

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
                const txid = try transaction.txid();
                try raw_transactions_map.put(txid, raw);

                const txoutputs = try getOutputsFor(aa, transaction, pubkeys);
                if (txoutputs.items.len == 0) {
                    continue;
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
                    //var vout_hex: [8]u8 = undefined;
                    //try utils.intToHexStr(u32, txoutput.outpoint.vout, &vout_hex);
                    //var key: [72]u8 = undefined;
                    //_ = try std.fmt.bufPrint(&key, "{s}{s}", .{ try utils.bytesToHex(64, &txoutput.outpoint.txid), vout_hex });
                    if (existing == null) {
                        const descriptor = keypaths.get(keypath);
                        // Generate the next key
                        const account_pubkey = try ExtendedPublicKey.fromAddress(descriptor.?.extended_key);
                        const next_pubkey = try bip44.generatePublicFromAccountPublicKey(account_pubkey, next.path[3], next.path[4]);
                        const next_pubkey_hash = try next_pubkey.toHash();
                        try pubkeys.put(next_pubkey_hash, next);
                        try keypaths.put(next, descriptor.?);
                        break :blk;
                    }
                }

                for (0..txoutputs.items.len) |j| {
                    try outputs.append(txoutputs.items[j]);
                }
            }
            break;
        }

        const tx_inputs = try getInputsFor(aa, block_transactions, pubkeys);
        defer tx_inputs.deinit();

        if (outputs.items.len > 0) {
            try db.saveOutputs(aa, &database, outputs.items);
        }
        if (tx_inputs.items.len > 0) {
            try db.saveInputsAndMarkOutputs(&database, tx_inputs.items);
        }
        if (relevant_transactions.count() > 0) {
            var it = relevant_transactions.keyIterator();
            while (it.next()) |txid| {
                const raw = raw_transactions_map.get(txid.*).?;
                const is_coinbase = relevant_transactions.get(txid.*).?;
                try db.saveTransaction(&database, txid.*, raw, is_coinbase, i);
            }
        }
        // Since db writes are not in a single transaction we commit block as latest so that if we restart we dont't risk loosing information, once block is persisted we are sure outputs, inputs and relevant transactions in that block are persisted too. We can recover from partial commit simply reindexing the block.
        try db.saveBlock(&database, try utils.hexToBytes(32, &blockhash), i);

        progressbar.completeOne();
        _ = arena.reset(.free_all);
    }

    std.debug.print("indexing completed\n", .{});
}

// return bytes value of pubkey hash
fn scriptPubkeyToPubkeyHash(allocator: std.mem.Allocator, output: tx.TxOutput) !?[20]u8 {
    const s = try script.Script.decode(allocator, output.script_pubkey);
    if (s.stack.items.len == 3 and s.stack.items[0] == script.ScriptOp.op and s.stack.items[0].op == script.Opcode.op_false and s.stack.items[1] == script.ScriptOp.push_bytes and s.stack.items[1].push_bytes == 20 and s.stack.items[2] == script.ScriptOp.v and s.stack.items[2].v.len == 20) {
        return s.stack.items[2].v[0..20].*;
    }

    return null;
}

fn getOutputsFor(allocator: std.mem.Allocator, transaction: tx.Transaction, pubkeys: std.AutoHashMap([20]u8, KeyPath(5))) !std.ArrayList(Output) {
    var outputs = std.ArrayList(Output).init(allocator);
    for (0..transaction.outputs.items.len) |i| {
        const tx_output = transaction.outputs.items[i];
        const output_pubkey_hash = try scriptPubkeyToPubkeyHash(allocator, tx_output);
        if (output_pubkey_hash == null) {
            break;
        }

        const pubkey = pubkeys.get(output_pubkey_hash.?);
        if (pubkey != null) {
            const txid = try transaction.txid();
            const vout = @as(u32, @intCast(i));
            const output = Output{ .outpoint = Outpoint{ .txid = txid, .vout = vout }, .keypath = pubkey.?, .amount = tx_output.amount, .unspent = true };
            try outputs.append(output);
        }
    }
    return outputs;
}

fn getInputsFor(allocator: std.mem.Allocator, transactions: []tx.Transaction, pubkeys: std.AutoHashMap([20]u8, KeyPath(5))) !std.ArrayList(Input) {
    var inputs = std.ArrayList(Input).init(allocator);
    for (transactions) |transaction| {
        if (transaction.witness.items.len == 0) {
            // No segwit, skip
            return inputs;
        }

        if (transaction.inputs.items.len != transaction.witness.items.len) {
            // Is it possible?
            return inputs;
        }

        for (0..transaction.inputs.items.len) |i| {
            //coinbase tx does not refer to any prev output
            if (transaction.isCoinbase()) {
                continue;
            }
            const input = transaction.inputs.items[i];
            const witness = transaction.witness.items[i];
            if (witness.stack_items.items.len != 2 and witness.stack_items.items[1].item.len != 33) {
                // Not a p2wpkh, skip
                break;
            }

            const compressed_pubkey = witness.stack_items.items[1].item[0..33].*;
            const pubkey = try PublicKey.fromCompressed(compressed_pubkey);
            const pubkey_hash = try pubkey.toHash();
            const existing = pubkeys.get(pubkey_hash);
            if (existing != null) {
                const txid = try transaction.txid();
                try inputs.append(.{ .txid = txid, .outpoint = Outpoint{ .txid = input.prevout.?.txid, .vout = input.prevout.?.vout } });
            }
        }
    }

    return inputs;
}
