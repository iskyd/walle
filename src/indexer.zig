const std = @import("std");
const Block = @import("block.zig").Block;
const tx = @import("tx.zig");
const Output = tx.Output;
const Input = tx.Input;
const ExtendedPublicKey = @import("bip32.zig").ExtendedPublicKey;
const PublicKey = @import("bip32.zig").PublicKey;
const bip44 = @import("bip44.zig");
const KeyPath = bip44.KeyPath;
const Network = @import("const.zig").Network;
const script = @import("script.zig");
const utils = @import("utils.zig");
const clap = @import("clap");
const rpc = @import("rpc/rpc.zig");
const db = @import("db/db.zig");
const sqlite = @import("sqlite");

const TOTAL_NEW_KEYS_GAP = 5; // 20

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

    // Get the public key of the user
    // We start from the account public key so that we can derive both change and index from that following bip44
    // A new index for both internal and external address should be generated everytime we find an output from the previous key
    // We start with 20 keys (and try to always keep 20 new keys) and hopefully we never need to parse a transaction twice
    const pkaddress = "tpubDCqjeTSmMEVcovTXiEJ8xNCZXobYFckihB9M6LsRMF9XNPX87ndZkLvGmY2z6PguGJDyUdzpF7tc1EtmqK1zJmPuJkfvutYGTz15JE7QW2Y".*;
    const accountpublickey = try ExtendedPublicKey.fromAddress(pkaddress);
    // use hashmap to store public key hash for fast check
    var publickeys = std.AutoHashMap([40]u8, KeyPath).init(allocator);
    defer publickeys.deinit();

    const auth = try rpc.generateAuth(allocator, res.args.user.?, res.args.password.?);
    defer allocator.free(auth);
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const blockcount = try rpc.getBlockCount(allocator, &client, res.args.location.?, auth);
    std.debug.print("Total blocks {d}\n", .{blockcount});
    const currentblockcount = try db.getCurrentBlockHeigth(&database);
    std.debug.print("Current blocks {?d}\n", .{currentblockcount});
    if (currentblockcount != null and blockcount == currentblockcount) {
        std.debug.print("Already indexed, do nothing", .{});
        return;
    }

    std.debug.print("init key generation", .{});
    // Generate first 20 keys
    var lastderivationindex: u32 = try generateAndAddKeys(&publickeys, accountpublickey, 0, TOTAL_NEW_KEYS_GAP);
    std.debug.print("keys generated\n", .{});

    var progress = std.Progress{};
    const progressbar = progress.start("indexing", blockcount);
    defer progressbar.end();

    const start: usize = if (currentblockcount == null) 0 else currentblockcount.?;

    for (start..blockcount + 1) |i| {
        var outputs = std.AutoHashMap([64]u8, Output).init(aa);
        var relevanttransactions = std.AutoHashMap([64]u8, bool).init(aa);
        const blockhash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);

        const rawtransactions = try rpc.getBlockRawTx(aa, &client, res.args.location.?, auth, blockhash);
        var rawtransactionsmap = std.AutoHashMap([64]u8, []u8).init(aa);

        const blocktransactions = try aa.alloc(tx.Transaction, rawtransactions.len);
        for (rawtransactions, 0..) |raw, j| {
            const transaction = try tx.decodeRawTx(aa, raw);
            blocktransactions[j] = transaction;
        }

        var maxindex: u32 = 0; // max public key index found with outputs
        while (true) blk: {
            for (blocktransactions, 0..) |transaction, k| {
                const raw = rawtransactions[k];
                const txid = try transaction.getTXID();
                try rawtransactionsmap.put(txid, raw);

                const txoutputs = try getOutputsFor(aa, transaction, publickeys);
                defer txoutputs.deinit();
                if (txoutputs.items.len == 0) {
                    break;
                }

                _ = try relevanttransactions.getOrPutValue(txid, true);

                for (0..txoutputs.items.len) |j| {
                    const txoutput = txoutputs.items[j];
                    if (txoutput.keypath.?.index > maxindex) {
                        maxindex = txoutput.keypath.?.index;
                    }
                }

                // We need to parse all the transactions in the block again
                // Because we might have loose some outputs
                if (maxindex == lastderivationindex) {
                    break :blk;
                }

                // Generate new keys so that we always have 20 unused keys
                const newkeys = maxindex + TOTAL_NEW_KEYS_GAP - lastderivationindex;
                if (newkeys > 0) {
                    lastderivationindex = try generateAndAddKeys(&publickeys, accountpublickey, lastderivationindex + 1, lastderivationindex + 1 + newkeys);
                }

                for (0..txoutputs.items.len) |j| {
                    const txoutput = txoutputs.items[j];
                    const uniquehash = try outputToUniqueHash(txoutput.txid, txoutput.n);
                    try outputs.put(uniquehash, txoutput);
                }
            }

            break;
        }

        const txinputs = try getInputsFor(aa, &database, blocktransactions);
        defer txinputs.deinit();
        for (0..txinputs.items.len) |k| {
            const txinput = txinputs.items[k];
            _ = try relevanttransactions.getOrPutValue(txinput.txid, true);
        }

        try db.saveBlock(&database, blockhash, i);
        if (outputs.count() > 0) {
            try db.saveOutputs(aa, &database, outputs);
        }
        if (txinputs.items.len > 0) {
            try db.saveInputs(&database, txinputs);
        }
        if (relevanttransactions.count() > 0) {
            try db.saveTransaction(&database, i, relevanttransactions, rawtransactionsmap);
        }

        progressbar.completeOne();
        _ = arena.reset(.free_all);
    }
    std.debug.print("indexing completed\n", .{});
}

// Returns last derivation index used
fn generateAndAddKeys(publickeys: *std.AutoHashMap([40]u8, KeyPath), accountpublickey: ExtendedPublicKey, start: usize, end: usize) !u32 {
    std.debug.assert(start != end);
    var lastderivationindex: u32 = 0;
    for (start..end) |i| {
        const index = @as(u32, @intCast(i));
        const pkchange = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_INTERNAL_CHAIN, index);
        const pkexternal = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_EXTERNAL_CHAIN, index);
        try publickeys.put(try pkchange.toHashHex(), KeyPath{ .purpose = 84, .cointype = bip44.BITCOIN_TESTNET_COIN_TYPE, .account = 0, .change = bip44.CHANGE_INTERNAL_CHAIN, .index = index });
        try publickeys.put(try pkexternal.toHashHex(), KeyPath{ .purpose = 84, .cointype = bip44.BITCOIN_TESTNET_COIN_TYPE, .account = 0, .change = bip44.CHANGE_EXTERNAL_CHAIN, .index = index });
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

fn getOutputsFor(allocator: std.mem.Allocator, transaction: tx.Transaction, publickeys: std.AutoHashMap([40]u8, KeyPath)) !std.ArrayList(Output) {
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
