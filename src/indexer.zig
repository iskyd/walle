const std = @import("std");
const Block = @import("block.zig").Block;
const tx = @import("tx.zig");
const ExtendedPublicKey = @import("bip32.zig").ExtendedPublicKey;
const PublicKey = @import("bip32.zig").PublicKey;
const bip44 = @import("bip44.zig");
const Network = @import("const.zig").Network;
const script = @import("script.zig");
const utils = @import("utils.zig");
const clap = @import("clap");
const rpc = @import("rpc/rpc.zig");

const P2WPKH_SCRIPT_PREFIX = "0014".*;

const KeyPath = struct {
    change: u32,
    index: u32,
};

const Output = struct {
    txid: [64]u8,
    n: u32,
    keypath: KeyPath,
    unspent: bool,
    amount: u64,
};

const Input = struct {
    txid: [64]u8,
    outputhash: [64]u8,
};

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

const RelevantTransaction = struct {
    allocator: std.mem.Allocator,
    txid: [64]u8,
    blockhash: [64]u8,
    rawtx: []u8,

    pub fn init(allocator: std.mem.Allocator, txid: [64]u8, blockhash: [64]u8, rawtx: []u8) !RelevantTransaction {
        return .{ .allocator = allocator, .txid = txid, .blockhash = blockhash, .rawtx = try allocator.dupe(u8, rawtx) };
    }

    pub fn deinit(self: RelevantTransaction) void {
        self.allocator.free(self.rawtx);
    }
};

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig.\nIndexer...\n", .{});

    // used for transactions to easily reset all the memory after each loop
    //var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    //const aa = arena.allocator();
    //defer arena.deinit();

    // used for everything else
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-b, --block <usize>      Start indexing from block
        \\-u, --user <str>         User
        \\-p, --password <str>     Password
        \\-l, --location <str>     Location
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

    std.debug.print("init key generation", .{});
    // Generate first 20 keys
    var lastderivationindex: u32 = try generateAndAddKeys(&publickeys, accountpublickey, 0, 20);
    std.debug.print("keys generated\n", .{});

    const auth = try rpc.generateAuth(allocator, res.args.user.?, res.args.password.?);
    defer allocator.free(auth);
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const blockcount = try rpc.getBlockCount(allocator, &client, res.args.location.?, auth);
    std.debug.print("Total blocks {d}\n", .{blockcount});

    var blocks = std.AutoHashMap([64]u8, usize).init(allocator); // blockhash: heigth
    defer blocks.deinit();
    var outputs = std.AutoHashMap([64]u8, Output).init(allocator);
    defer outputs.deinit();
    // key is the hash of the output it uses and the value is the tx where it is used
    var inputs = std.AutoHashMap([64]u8, [64]u8).init(allocator);
    defer inputs.deinit();
    var relevanttransactions = std.AutoHashMap([64]u8, RelevantTransaction).init(allocator);
    defer {
        var it = relevanttransactions.valueIterator();
        while (it.next()) |relevanttx| {
            relevanttx.deinit();
        }
        relevanttransactions.deinit();
    }
    for (res.args.block.?..blockcount) |i| {
        const blockhash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);
        try blocks.put(blockhash, i);

        const rawtransactions = try rpc.getBlockRawTx(allocator, &client, res.args.location.?, auth, blockhash);
        defer {
            for (rawtransactions) |raw| {
                allocator.free(raw);
            }
            allocator.free(rawtransactions);
        }

        const blocktransactions = try allocator.alloc(tx.Transaction, rawtransactions.len);
        for (rawtransactions, 0..) |raw, j| {
            const transaction = try tx.decodeRawTx(allocator, raw);
            blocktransactions[j] = transaction;
        }
        defer {
            for (blocktransactions) |blocktx| {
                blocktx.deinit();
            }
            allocator.free(blocktransactions);
        }

        while (true) blk: {
            for (blocktransactions, 0..) |transaction, k| {
                const raw = rawtransactions[k];
                const txid = try transaction.getTXID();
                const txoutputs = try getOutputsFor(allocator, transaction, publickeys);
                std.debug.print("found {d} outputs for block {d}\n", .{ txoutputs.items.len, i });
                defer txoutputs.deinit();
                if (txoutputs.items.len == 0) {
                    break;
                }

                var maxindex: u32 = 0;
                for (0..txoutputs.items.len) |j| {
                    const txoutput = txoutputs.items[j];
                    if (txoutput.keypath.index > maxindex) {
                        maxindex = txoutput.keypath.index;
                    }
                }

                // We need to parse all the transactions in the block again
                // Because we might have loose some outputs
                if (maxindex == lastderivationindex) {
                    break :blk;
                }

                // Generate new keys so that we always have 20 unused keys
                const newkeys = maxindex + 20 - lastderivationindex;
                if (newkeys > 0) {
                    lastderivationindex = try generateAndAddKeys(&publickeys, accountpublickey, lastderivationindex + 1, lastderivationindex + 1 + newkeys);
                }

                try relevanttransactions.put(txid, try RelevantTransaction.init(allocator, txid, blockhash, raw));

                for (0..txoutputs.items.len) |j| {
                    const txoutput = txoutputs.items[j];
                    const uniquehash = try outputToUniqueHash(txoutput.txid, txoutput.n);
                    try outputs.put(uniquehash, txoutput);
                }
            }

            break;
        }

        const txinputs = try getInputsFor(allocator, outputs, blocktransactions);
        defer txinputs.deinit();
        for (0..txinputs.items.len) |k| {
            const txinput = txinputs.items[k];
            try inputs.put(txinput.outputhash, txinput.txid);
        }
    }
    std.debug.print("indexing completed\n", .{});
    std.debug.print("find a total of {d} outputs and a total of {d} inputs\n", .{ outputs.count(), inputs.count() });
    std.debug.print("total balance: {d}\n", .{try getBalance(allocator, outputs, relevanttransactions, blocks, blockcount)});
}

// Returns last derivation index used
fn generateAndAddKeys(publickeys: *std.AutoHashMap([40]u8, KeyPath), accountpublickey: ExtendedPublicKey, start: usize, end: usize) !u32 {
    std.debug.assert(start != end);
    var lastderivationindex: u32 = 0;
    for (start..end) |i| {
        const index = @as(u32, @intCast(i));
        const pkchange = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_INTERNAL_CHAIN, index);
        const pkexternal = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_EXTERNAL_CHAIN, index);
        try publickeys.put(try pkchange.toHashHex(), KeyPath{ .change = bip44.CHANGE_INTERNAL_CHAIN, .index = index });
        try publickeys.put(try pkexternal.toHashHex(), KeyPath{ .change = bip44.CHANGE_EXTERNAL_CHAIN, .index = index });
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

fn getInputsFor(allocator: std.mem.Allocator, outputs: std.AutoHashMap([64]u8, Output), transactions: []tx.Transaction) !std.ArrayList(Input) {
    var inputs = std.ArrayList(Input).init(allocator);
    for (transactions) |transaction| {
        for (0..transaction.inputs.items.len) |i| {
            //coinbase tx does not refer to any prev output
            if (transaction.isCoinbase()) {
                continue;
            }
            const input = transaction.inputs.items[i];

            const hash: [64]u8 = try outputToUniqueHash(input.prevout.?.txid, input.prevout.?.n);
            const existing = outputs.get(hash);
            if (existing != null) {
                const txid = try transaction.getTXID();
                try inputs.append(.{ .txid = txid, .outputhash = hash });
            }
        }
    }
    return inputs;
}

fn getBalance(allocator: std.mem.Allocator, outputs: std.AutoHashMap([64]u8, Output), transactions: std.AutoHashMap([64]u8, RelevantTransaction), blocks: std.AutoHashMap([64]u8, usize), currentheight: usize) !u64 {
    var balance: u64 = 0;
    var it = outputs.valueIterator();
    while (it.next()) |output| {
        if (output.unspent == false) {
            std.debug.print("setting output as unspent=false\n", .{});
            continue;
        }
        const relevant = transactions.get(output.txid);
        if (relevant == null) {
            unreachable;
        }

        const transaction = try tx.decodeRawTx(allocator, relevant.?.rawtx);
        defer transaction.deinit();

        if (transaction.isCoinbase() == true) {
            // Can't spend coinbase transaction before 100 blocks, can't add to balance
            const blockheight = blocks.get(relevant.?.blockhash);
            if (currentheight > blockheight.? + 100) {
                break;
            }
        }
        balance += output.amount;
    }
    return balance;
}
