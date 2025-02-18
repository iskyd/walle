const std = @import("std");
const tx = @import("tx.zig");
const Output = tx.Output;
const Outpoint = tx.Outpoint;
const Input = tx.Input;
const bip32 = @import("bip32.zig");
const PublicKey = bip32.PublicKey;
const ExtendedPublicKey = bip32.ExtendedPublicKey;
const keypath = @import("keypath.zig");
const Network = @import("const.zig").Network;
const script = @import("script.zig");
const utils = @import("utils.zig");
const clap = @import("clap");
const rpc = @import("rpc/rpc.zig");
const db = @import("db/db.zig");
const sqlite = @import("sqlite");
const zzmq = @import("zzmq");

// const KEYS_GAP = 100;
const KEYS_GAP = 5;

fn generateKeys(pubkeys: *std.AutoHashMap([20]u8, keypath.KeyPath(5)), kp: keypath.KeyPath(4), extended_pubkey: bip32.ExtendedPublicKey, start: usize, end: usize) !void {
    for (start..end) |i| {
        const index = @as(u32, @intCast(i));
        const pubkey = try bip32.deriveChildFromExtendedPublicKey(extended_pubkey, index);
        const pubkey_hash = try pubkey.key.toHash();
        try pubkeys.put(pubkey_hash, kp.extendPath(index, false));
    }
}

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
    // defer std.debug.assert(gpa.deinit() == .ok);

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
    const rpc_location = res.args.location.?;

    // Manage fork.
    const last_block = try db.getLastBlock(&database);
    const current_block_height: ?usize = if (last_block != null) last_block.?.height else null;
    std.debug.print("last block {?d}\n", .{current_block_height});

    if (current_block_height != null) {
        const last_valid_block_height = try getLastValidBlockHeight(allocator, &client, rpc_location, auth, &database);
        if (last_valid_block_height != current_block_height) {
            try deleteEverythingAfterBlock(last_valid_block_height, &database);
        }
    }

    var block_height = try rpc.getBlockCount(allocator, &client, rpc_location, auth);
    std.debug.print("Total blocks {d}\n", .{block_height});
    std.debug.print("Current blocks {?d}\n", .{current_block_height});

    // Load descriptors
    const descriptors = try db.getDescriptors(allocator, &database, false); // only public descriptors
    defer allocator.free(descriptors);

    for (descriptors) |descriptor| {
        std.debug.print("keypath.Descriptor: extended key = {s}, path = {d}'/{d}'/{d}'\n", .{ descriptor.extended_key, descriptor.keypath.path[0].value, descriptor.keypath.path[1].value, descriptor.keypath.path[2].value });
    }

    std.debug.print("init key generation\n", .{});
    // use hashmap to store public key hash for fast check
    var pubkeys = std.AutoHashMap([20]u8, keypath.KeyPath(5)).init(allocator);
    defer pubkeys.deinit();

    // remove, useless
    var keypaths = std.AutoHashMap(keypath.KeyPath(5), keypath.Descriptor).init(allocator);
    defer keypaths.deinit();

    // this is used to store the last used index for every keypath (both internal and external) for every descriptor.
    // it is necessary to keep track of the gap between the last generated key and the last used index
    // if gap < KEYS_GAP, generate missing keys
    var keypath_last_used_index = std.AutoHashMap(keypath.KeyPath(4), u32).init(allocator);
    defer keypath_last_used_index.deinit();

    var descriptors_map = std.AutoHashMap(keypath.KeyPath(3), [111]u8).init(allocator);
    defer descriptors_map.deinit();
    for (descriptors) |descriptor| {
        try descriptors_map.put(descriptor.keypath, descriptor.extended_key);
    }

    const account_pubkeys = try allocator.alloc(ExtendedPublicKey, descriptors.len);
    defer allocator.free(account_pubkeys);

    // For every descriptor we get the latest used index (if one) and generate all the keys to this latest index + 1
    // Otherwise we only derive the first keypath (.../0)
    for (descriptors) |descriptor| {
        const internal_keypath = descriptor.keypath.extendPath(keypath.internal_chain, false);
        const external_keypath = descriptor.keypath.extendPath(keypath.external_chain, false);
        const internal_keypath_str = try internal_keypath.toStr(allocator, null);
        defer allocator.free(internal_keypath_str);
        const external_keypath_str = try external_keypath.toStr(allocator, null);
        defer allocator.free(external_keypath_str);

        const last_internal_index = try db.getLastUsedIndexFromOutputs(&database, internal_keypath_str);
        const last_external_index = try db.getLastUsedIndexFromOutputs(&database, external_keypath_str);

        const descriptor_pubkey_addr = descriptors_map.get(descriptor.keypath).?;
        const descriptor_pubkey = try ExtendedPublicKey.fromAddress(descriptor_pubkey_addr);
        const internal_pubkey = try bip32.deriveChildFromExtendedPublicKey(descriptor_pubkey, keypath.internal_chain);
        const external_pubkey = try bip32.deriveChildFromExtendedPublicKey(descriptor_pubkey, keypath.external_chain);

        const new_internal_last_index = if (last_internal_index == null) KEYS_GAP else last_internal_index.? + KEYS_GAP;
        const new_external_last_index = if (last_external_index == null) KEYS_GAP else last_external_index.? + KEYS_GAP;

        // 100 gap
        try generateKeys(&pubkeys, internal_keypath, internal_pubkey, 0, new_internal_last_index);
        try generateKeys(&pubkeys, external_keypath, external_pubkey, 0, new_external_last_index);

        try keypath_last_used_index.put(internal_keypath, new_internal_last_index);
        try keypath_last_used_index.put(external_keypath, new_external_last_index);
    }

    std.debug.print("keys generated\n", .{});

    var progress = std.Progress.start(.{});

    const start: usize = if (current_block_height == null) 0 else current_block_height.? + 1;
    const progressbar = progress.start("indexing", if (block_height >= start) block_height - start else 0);

    // align to the current block
    var i: usize = start;
    while (true) {
        // During the indexes new block can be added. Be sure we are aligned
        if (i > block_height) {
            block_height = try rpc.getBlockCount(allocator, &client, res.args.location.?, auth);
            if (i > block_height) {
                break;
            }
        }

        const block_hash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);
        if (i == 0) {
            // genesis block
            try db.saveBlock(&database, try utils.hexToBytes(32, &block_hash), 0);
        } else {
            try manageBlock(aa, block_hash, &client, res.args.location.?, auth, &pubkeys, &keypath_last_used_index, descriptors_map, &database);
        }

        progressbar.completeOne();
        _ = arena.reset(.free_all);

        i += 1;
    }
    progressbar.end();

    std.debug.print("indexing completed starting zmq\n", .{});

    const zmq_port = 28332;
    const zmq_host = "127.0.0.1";
    var context = try zzmq.ZContext.init(allocator);
    defer context.deinit();

    var socket = try zzmq.ZSocket.init(zzmq.ZSocketType.Sub, &context);
    defer socket.deinit();

    const endpoint = try std.fmt.allocPrint(allocator, "tcp://{s}:{d}", .{ zmq_host, zmq_port });
    defer allocator.free(endpoint);

    try socket.connect(endpoint);
    try socket.setSocketOption(.{ .Subscribe = @constCast("hashblock") });

    while (true) {
        var topic = try socket.receive(.{});
        var body = try socket.receive(.{});
        var seq = try socket.receive(.{});

        defer topic.deinit();
        defer body.deinit();
        defer seq.deinit();

        const data = try body.data();
        const block_hash = try utils.bytesToHex(64, data[0..32]);
        std.debug.print("block hash {s}\n", .{block_hash});

        manageBlock(aa, block_hash, &client, res.args.location.?, auth, &pubkeys, &keypath_last_used_index, descriptors_map, &database) catch |err| {
            switch (err) {
                error.ForkHappened => {
                    // align blocks
                    const last_valid_block_height = try getLastValidBlockHeight(allocator, &client, rpc_location, auth, &database);
                    try deleteEverythingAfterBlock(last_valid_block_height, &database);
                    const new_block_height = try rpc.getBlockCount(allocator, &client, rpc_location, auth);
                    for (last_valid_block_height..new_block_height + 1) |h| {
                        const new_block_hash = try rpc.getBlockHash(allocator, &client, rpc_location, auth, h);
                        try manageBlock(aa, new_block_hash, &client, rpc_location, auth, &pubkeys, &keypath_last_used_index, descriptors_map, &database);
                    }
                },
                else => unreachable,
            }
        };
        _ = arena.reset(.free_all);
    }
}

fn getLastValidBlockHeight(allocator: std.mem.Allocator, client: *std.http.Client, rpc_location: []const u8, rpc_auth: []const u8, database: *sqlite.Db) !usize {
    const last_block = try db.getLastBlock(database);
    if (last_block == null) {
        return 0;
    }
    var current_block_height = last_block.?.height;
    while (current_block_height > 0) {
        const b = try db.getBlock(database, current_block_height);
        const node_block_hash = try rpc.getBlockHash(allocator, client, rpc_location, rpc_auth, current_block_height);
        if (std.mem.eql(u8, &b.hash, &try utils.hexToBytes(32, &node_block_hash))) {
            break;
        }
        current_block_height -= 1;
    }

    return current_block_height;
}

fn deleteEverythingAfterBlock(from: usize, database: *sqlite.Db) !void {
    try db.deleteOutputsFromBlockHeight(database, from);
    try db.deleteInputsFromBlockHeight(database, from);
    try db.deleteTransactionsFromBlockHeight(database, from);

    // Blocks need to be the last one since this db transactions are not atomic.
    try db.deleteBlocksFromBlockHeight(database, from);
}

fn manageBlock(aa: std.mem.Allocator, block_hash: [64]u8, client: *std.http.Client, rpc_location: []const u8, rpc_auth: []const u8, pubkeys: *std.AutoHashMap([20]u8, keypath.KeyPath(5)), keypath_last_used_index: *std.AutoHashMap(keypath.KeyPath(4), u32), descriptors_map: std.AutoHashMap(keypath.KeyPath(3), [111]u8), database: *sqlite.Db) anyerror!void {
    // Manage possible forks. If block.previous_hash is not the same we have in db we need to go back until we find the last valid block
    const block = try rpc.getBlock(aa, client, rpc_location, rpc_auth, block_hash);
    defer block.deinit();

    const prev_block = try db.getBlock(database, block.height - 1); // if this block does not exist, an error will be thrown
    if (std.mem.eql(u8, &prev_block.hash, &block.previous_hash) == false) {
        // A fork happened.
        return error.ForkHappened;
    }

    const raw_transactions = block.raw_transactions;

    var raw_transactions_map = std.AutoHashMap([32]u8, []u8).init(aa);
    defer raw_transactions_map.deinit();

    var block_transactions = std.AutoHashMap([32]u8, tx.Transaction).init(aa);
    defer block_transactions.deinit();
    for (raw_transactions) |tx_raw| {
        const transaction = try tx.decodeRawTx(aa, tx_raw);
        try raw_transactions_map.put(try transaction.txid(), tx_raw);
        try block_transactions.put(try transaction.txid(), transaction);
    }

    const tx_outputs = try getOutputsFor(aa, block_transactions, pubkeys.*);
    const tx_inputs = try getInputsFor(aa, block_transactions, pubkeys.*);

    for (tx_outputs.items) |tx_output| {
        const kp = tx_output.keypath.?.truncPath(4);
        const current_last_used = keypath_last_used_index.get(kp).?;
        // Generate new keys if needed
        if (tx_output.keypath.?.path[4].value > current_last_used) {
            const current_descriptor = descriptors_map.get(tx_output.keypath.?.truncPath(3)).?;
            const extended_pubkey = try ExtendedPublicKey.fromAddress(current_descriptor);
            try generateKeys(pubkeys, tx_output.keypath.?.truncPath(4), extended_pubkey, current_last_used + 1, tx_output.keypath.?.path[4].value + 1);
            try keypath_last_used_index.put(kp, tx_output.keypath.?.path[4].value);
        }
    }

    if (tx_outputs.items.len > 0) {
        try db.saveOutputs(aa, database, tx_outputs.items);
    }
    if (tx_inputs.items.len > 0) {
        try db.saveInputsAndMarkOutputs(database, tx_inputs.items);
    }
    for (tx_outputs.items) |tx_output| {
        const transaction = block_transactions.get(tx_output.txid).?;
        const raw_tx = raw_transactions_map.get(tx_output.txid).?;
        try db.saveTransaction(database, tx_output.txid, raw_tx, transaction.isCoinbase(), block.height);
    }

    // Since db writes are not in a single transaction we commit block as latest so that if we restart we dont't risk loosing information, once block is persisted we are sure outputs, inputs and relevant transactions in that block are persisted too. We can recover from partial commit simply reindexing the block.
    try db.saveBlock(database, try utils.hexToBytes(32, &block_hash), block.height);
}

// return bytes value of pubkey hash
fn scriptPubkeyToPubkeyHash(allocator: std.mem.Allocator, output: tx.TxOutput) !?[20]u8 {
    const s = try script.Script.decode(allocator, output.script_pubkey);
    if (s.stack.items.len == 3 and s.stack.items[0] == script.ScriptOp.op and s.stack.items[0].op == script.Opcode.op_false and s.stack.items[1] == script.ScriptOp.push_bytes and s.stack.items[1].push_bytes == 20 and s.stack.items[2] == script.ScriptOp.v and s.stack.items[2].v.len == 20) {
        return s.stack.items[2].v[0..20].*;
    }

    return null;
}

fn getOutputsFor(allocator: std.mem.Allocator, transactions: std.AutoHashMap([32]u8, tx.Transaction), pubkeys: std.AutoHashMap([20]u8, keypath.KeyPath(5))) !std.ArrayList(Output) {
    var outputs = std.ArrayList(Output).init(allocator);
    var it = transactions.valueIterator();
    while (it.next()) |transaction| {
        for (0..transaction.outputs.items.len) |i| {
            const tx_output = transaction.outputs.items[i];
            const output_pubkey_hash = try scriptPubkeyToPubkeyHash(allocator, tx_output);
            if (output_pubkey_hash == null) {
                continue;
            }

            const pubkey = pubkeys.get(output_pubkey_hash.?);
            if (pubkey != null) {
                const txid = try transaction.txid();
                const vout = @as(u32, @intCast(i));
                const output = Output{ .outpoint = Outpoint{ .txid = txid, .vout = vout }, .txid = txid, .keypath = pubkey.?, .amount = tx_output.amount, .unspent = true };
                try outputs.append(output);
            }
        }
    }
    return outputs;
}

fn getInputsFor(allocator: std.mem.Allocator, transactions: std.AutoHashMap([32]u8, tx.Transaction), pubkeys: std.AutoHashMap([20]u8, keypath.KeyPath(5))) !std.ArrayList(Input) {
    var inputs = std.ArrayList(Input).init(allocator);
    var it = transactions.valueIterator();
    while (it.next()) |transaction| {
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
