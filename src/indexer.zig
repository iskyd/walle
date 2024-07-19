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

const TOTAL_STARTING_KEYS = 5; // 20

const P2WPKH_SCRIPT_PREFIX = "0014".*;

pub fn outputToUniqueHash(txid: [64]u8, n: u32) ![64]u8 {
    var h1: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&txid, &h1, .{});
    var h2: [32]u8 = undefined;
    var nhex: [8]u8 = undefined;
    try utils.intToHexStr(u32, n, &nhex);
    std.crypto.hash.sha2.Sha256.hash(&nhex, &h2, .{});
    const nh1 = std.mem.readInt(u256, &h1, .big);
    const nh2 = std.mem.readInt(u256, &h2, .big);
    const res: u256 = nh1 ^ (nh2 << 1);
    var hex: [64]u8 = undefined;
    try utils.intToHexStr(u256, res, &hex);
    return hex;
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
    const blockcount = try rpc.getBlockCount(allocator, &client, res.args.location.?, auth);
    std.debug.print("Total blocks {d}\n", .{blockcount});
    const currentblockcount = try db.getCurrentBlockHeigth(&database);
    std.debug.print("Current blocks {?d}\n", .{currentblockcount});
    if (currentblockcount != null and blockcount == currentblockcount) {
        std.debug.print("Already indexed, do nothing\n", .{});
        const balance = try db.getBalance(&database, currentblockcount.?);
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
    var publickeys = std.AutoHashMap([40]u8, KeyPath(5)).init(allocator);
    defer publickeys.deinit();
    var keypaths = std.AutoHashMap(KeyPath(5), Descriptor).init(allocator);
    defer keypaths.deinit();
    var descriptorsmap = std.AutoHashMap(KeyPath(3), [111]u8).init(allocator);
    for (descriptors) |descriptor| {
        try descriptorsmap.put(descriptor.keypath, descriptor.extended_key);
    }

    const accountpublickeys = try allocator.alloc(ExtendedPublicKey, descriptors.len);
    defer allocator.free(accountpublickeys);
    const usedkeypaths = try db.getUsedKeyPaths(allocator, &database);
    defer allocator.free(usedkeypaths);

    for (usedkeypaths) |keypath| {
        const existing = keypaths.get(keypath);
        if (existing != null) {
            continue;
        }

        const d = KeyPath(3){ .path = [3]u32{ keypath.path[0], keypath.path[1], keypath.path[3] } };
        const extendedaddr = descriptorsmap.get(d);
        if (extendedaddr == null) {
            std.debug.print("descriptor not found for path {d}'/{d}'/{d}'\n", .{ d.path[0], d.path[1], d.path[2] });
            continue;
        }

        // Generate the current used keypath and public key
        const extended = try ExtendedPublicKey.fromAddress(extendedaddr.?);
        try keypaths.put(keypath, Descriptor{ .extended_key = extendedaddr.?, .keypath = d });
        const public = try bip44.generatePublicFromAccountPublicKey(extended, keypath.path[3], keypath.path[4]);
        const publichash = try public.toHashHex();
        try publickeys.put(publichash, keypath);

        // Generate the next one
        const nextpublic = try bip44.generatePublicFromAccountPublicKey(extended, keypath.path[3], keypath.path[4] + 1);
        const nextpublichash = try nextpublic.toHashHex();
        try publickeys.put(nextpublichash, keypath.getNext(1));
    }

    for (descriptors) |descriptor| {
        const accountpublickey = try ExtendedPublicKey.fromAddress(descriptor.extended_key);

        const keypathinternal = KeyPath(5){ .path = [5]u32{ descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2], bip44.CHANGE_INTERNAL_CHAIN, 0 } };
        const existinginternal = keypaths.get(keypathinternal);
        if (existinginternal == null) {
            const internal = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_INTERNAL_CHAIN, 0);
            const internalhash = try internal.toHashHex();
            try keypaths.put(keypathinternal, descriptor);
            try publickeys.put(internalhash, keypathinternal);
        }

        const keypathexternal = KeyPath(5){ .path = [5]u32{ descriptor.keypath.path[0], descriptor.keypath.path[1], descriptor.keypath.path[2], bip44.CHANGE_EXTERNAL_CHAIN, 0 } };
        const existingexternal = keypaths.get(keypathexternal);
        if (existingexternal == null) {
            const external = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_EXTERNAL_CHAIN, 0);
            const externalhash = try external.toHashHex();
            try keypaths.put(keypathexternal, descriptor);
            try publickeys.put(externalhash, keypathexternal);
        }
    }

    std.debug.print("keys generated\n", .{});

    var progress = std.Progress{};
    const progressbar = progress.start("indexing", blockcount);
    defer progressbar.end();

    const start: usize = if (currentblockcount == null) 0 else currentblockcount.?;

    for (start..blockcount + 1) |i| {
        var outputs = std.AutoHashMap([64]u8, Output).init(aa);
        // [64]u8 is for txid, bool is for isCoinbase
        var relevanttransactions = std.AutoHashMap([64]u8, bool).init(aa);
        const blockhash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);

        const rawtransactions = try rpc.getBlockRawTx(aa, &client, res.args.location.?, auth, blockhash);
        var rawtransactionsmap = std.AutoHashMap([64]u8, []u8).init(aa);

        const blocktransactions = try aa.alloc(tx.Transaction, rawtransactions.len);
        for (rawtransactions, 0..) |raw, j| {
            const transaction = try tx.decodeRawTx(aa, raw);
            blocktransactions[j] = transaction;
        }

        // Following BIP44 a wallet must not allow the derivation of a new address if the previous one is not used
        // So we start by creating 1 new key (both internal and external)
        // Everytime we found a new output we need to generate the next key and re-index the same block to be sure all outputs are included
        while (true) blk: {
            for (blocktransactions, 0..) |transaction, k| {
                const raw = rawtransactions[k];
                const txid = try transaction.getTXID();
                try rawtransactionsmap.put(txid, raw);

                const txoutputs = try getOutputsFor(aa, transaction, publickeys);
                if (txoutputs.items.len == 0) {
                    break;
                }

                _ = try relevanttransactions.getOrPutValue(txid, transaction.isCoinbase());

                for (0..txoutputs.items.len) |j| {
                    const txoutput = txoutputs.items[j];
                    // We need to generate the key with idx + n if it doesnt already exists
                    const keypath = txoutput.keypath.?;
                    const next = keypath.getNext(1);
                    const existing = keypaths.get(next);

                    // If we are generating a new key and the output is new we start re-indexing the block
                    // This ensure the fact that we collect all the outputs since the new key could have been used in previous tx in the same block
                    const uniquehash = try outputToUniqueHash(txoutput.txid, txoutput.n);
                    const o = try outputs.getOrPut(uniquehash);
                    o.value_ptr.* = txoutput;
                    if (existing == null) {
                        const descriptor = keypaths.get(keypath);
                        // Generate the next key
                        const accountpublickey = try ExtendedPublicKey.fromAddress(descriptor.?.extended_key);
                        const key = try bip44.generatePublicFromAccountPublicKey(accountpublickey, next.path[3], next.path[4]);
                        const keyhash = try key.toHashHex();
                        try publickeys.put(keyhash, next);
                        try keypaths.put(next, descriptor.?);

                        if (o.found_existing == false) {
                            break :blk;
                        }
                    }
                }
            }

            break;
        }

        const txinputs = try getInputsFor(aa, &database, blocktransactions);
        defer txinputs.deinit();
        for (0..txinputs.items.len) |k| {
            const txinput = txinputs.items[k];
            _ = try relevanttransactions.getOrPutValue(txinput.txid, false); // false because if we are using inputs then the current tx is not coinbase
        }

        if (outputs.count() > 0) {
            try db.saveOutputs(aa, &database, outputs);
        }
        if (txinputs.items.len > 0) {
            try db.saveInputs(&database, txinputs);
        }
        if (relevanttransactions.count() > 0) {
            try db.saveTransaction(&database, i, relevanttransactions, rawtransactionsmap);
        }
        // Since db writes are not in a single transaction we commit block as lastest so that if we restart we dont't risk loosing informations, once block is persisted we are sure outputs, inputs and relevant transactions in that block are persisted too. We can recover from partial commit simply reindexing the block.
        try db.saveBlock(&database, blockhash, i);

        progressbar.completeOne();
        _ = arena.reset(.free_all);
    }

    std.debug.print("indexing completed\n", .{});
}

// Returns last derivation index used
fn generateAndAddKeys(publickeys: *std.AutoHashMap([40]u8, KeyPath(5)), accountpublickey: ExtendedPublicKey, start: usize, end: usize) !u32 {
    std.debug.assert(start != end);
    var lastderivationindex: u32 = 0;
    for (start..end) |i| {
        const index = @as(u32, @intCast(i));
        const pkchange = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_INTERNAL_CHAIN, index);
        const pkexternal = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_EXTERNAL_CHAIN, index);
        try publickeys.put(try pkchange.toHashHex(), KeyPath(5){ .path = [5]u32{ 84, bip44.BITCOIN_TESTNET_COIN_TYPE, 0, bip44.CHANGE_INTERNAL_CHAIN, index } });
        try publickeys.put(try pkexternal.toHashHex(), KeyPath(5){ .path = [5]u32{ 84, bip44.BITCOIN_TESTNET_COIN_TYPE, 0, bip44.CHANGE_EXTERNAL_CHAIN, index } });
        lastderivationindex = index;
    }

    return lastderivationindex;
}

// return hex value of pubkey hash
fn outputToPublicKeyHash(output: tx.TxOutput) ![40]u8 {
    if (std.mem.eql(u8, output.script_pubkey[0..4], &P2WPKH_SCRIPT_PREFIX)) {
        return output.script_pubkey[4..44].*;
    }
    return error.UnsupportedScriptPubKey;
}

fn getOutputsFor(allocator: std.mem.Allocator, transaction: tx.Transaction, publickeys: std.AutoHashMap([40]u8, KeyPath(5))) !std.ArrayList(Output) {
    var outputs = std.ArrayList(Output).init(allocator);
    for (0..transaction.outputs.items.len) |i| {
        const txoutput = transaction.outputs.items[i];
        const outputpubkeyhash = outputToPublicKeyHash(txoutput) catch continue; // TODO: is this the best we can do?
        const pubkey = publickeys.get(outputpubkeyhash);
        if (pubkey == null) {
            break;
        }

        const txid = try transaction.getTXID();
        const n = @as(u32, @intCast(i));
        const output = Output{ .txid = txid, .n = n, .keypath = pubkey.?, .amount = txoutput.amount, .unspent = true };
        try outputs.append(output);
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
            const existing = try db.getOutput(database, input.prevout.?.txid, input.prevout.?.n);
            if (existing != null) {
                const txid = try transaction.getTXID();
                try inputs.append(.{ .txid = txid, .outputtxid = existing.?.txid, .outputn = existing.?.n });
            }
        }
    }
    return inputs;
}
