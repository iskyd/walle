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

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig.\nIndexer...\n", .{});

    // used for transactions to easily reset all the memory after each loop
    //var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    //const aa = arena.allocator();
    //defer arena.deinit();

    // used for everything else
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

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
    const pkaddress = "tpubDCqjeTSmMEVcovTXiEJ8xNCZXobYFckihB9M6LsRMF9XNPX87ndZkLvGmY2z6PguGJDyUdzpF7tc1EtmqK1zJmPuJkfvutYGTz15JE7QW2Y".*;
    const accountpublickey = try ExtendedPublicKey.fromAddress(pkaddress);
    // use hashmap to store public key hash for fast check
    var publickeys = std.AutoHashMap([40]u8, KeyPath).init(allocator);

    // Generate first 20 keys
    var lastderivationindex: u32 = 0;
    for (0..20) |i| {
        const pkchange = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_INTERNAL_CHAIN, 0);
        const pkexternal = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_EXTERNAL_CHAIN, 0);
        try publickeys.put(try pkchange.toHashHex(), KeyPath{ .change = bip44.CHANGE_INTERNAL_CHAIN, .index = 0 });
        try publickeys.put(try pkexternal.toHashHex(), KeyPath{ .change = bip44.CHANGE_EXTERNAL_CHAIN, .index = 0 });
        lastderivationindex = i;
    }

    const auth = try rpc.generateAuth(allocator, res.args.user.?, res.args.password.?);
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const blockcount = try rpc.getBlockCount(allocator, &client, res.args.location.?, auth);
    std.debug.print("Total blocks {d}\n", .{blockcount});
    const balance: usize = 0;
    for (res.args.block.?..blockcount) |i| {
        const blockhash = try rpc.getBlockHash(allocator, &client, res.args.location.?, auth, i);
        const rawtransactions = try rpc.getBlockRawTx(allocator, &client, res.args.location.?, auth, blockhash);

        var totaloutputs: usize = 0;
        var j: usize = 0;
        while (j < rawtransactions.len) : (j += 1) {
            const raw = rawtransactions[j];
            const transaction = try tx.decodeRawTx(allocator, raw);
            const totaltxoutputs = totalOutputsFor(transaction, publickeys);

            if (totaltxoutputs.n > 0 and totaltxoutputs.maxindex == lastderivationindex) {
                // derive new keys, set totaloutputs to 0 and restart
                totaloutputs = 0;
                j = 0;
                const newpkchange = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_INTERNAL_CHAIN, lastderivationindex + 1);
                const newpkexternal = try bip44.generatePublicFromAccountPublicKey(accountpublickey, bip44.CHANGE_EXTERNAL_CHAIN, lastderivationindex + 1);
                try publickeys.put(try newpkchange.toHashHex(), .{ .change = bip44.CHANGE_INTERNAL_CHAIN, .index = lastderivationindex + 1 });
                try publickeys.put(try newpkexternal.toHashHex(), .{ .change = bip44.CHANGE_EXTERNAL_CHAIN, .index = lastderivationindex + 1 });
                lastderivationindex += 1;
            }
        }

        // totaloutputs is now equal to the total outputs in the current block
        // allocate memory and get all outputs
    }
    std.debug.print("total balance: {d}\n", .{balance});
}

// return hex value of pubkey hash
fn outputToPublicKeyHash(output: tx.TxOutput) ![40]u8 {
    if (std.mem.eql(u8, output.script_pubkey[0..4], &P2WPKH_SCRIPT_PREFIX)) {
        return output.script_pubkey[4..44].*;
    }
    return error.UnsupportedScriptPubKey;
}

const TotalOutputs = struct {
    n: usize,
    maxindex: usize,
};

// publickeys key is the hex hash of the public key
fn totalOutputsFor(transaction: tx.Transaction, publickeys: std.AutoHashMap([40]u8, KeyPath)) TotalOutputs {
    var total: usize = 0;
    var maxindex: usize = 0;
    for (0..transaction.outputs.items.len) |i| {
        const o = transaction.outputs.items[i];
        const outputpubkeyhash = outputToPublicKeyHash(o) catch continue; // TODO: is this the best we can do?
        const res = publickeys.get(outputpubkeyhash);
        if (res == null) {
            break;
        }

        total += 1;
        maxindex = if (maxindex >= res.?.index) maxindex else res.?.index;
    }
    return .{ .n = total, .maxindex = maxindex };
}

// memory ownership to the caller
fn getOutputsFor(allocator: std.mem.Allocator, transaction: tx.Transaction, pubkeyhash: [40]u8) !?[]tx.TxOutput {
    const cap = totalOutputsFor(transaction, pubkeyhash);
    if (cap == 0) {
        return null;
    }

    const outputs = try allocator.alloc(tx.TxOutput, cap);
    errdefer comptime unreachable; // no more errors
    var cur: usize = 0;
    for (0..transaction.outputs.items.len) |i| {
        const o = transaction.outputs.items[i];
        const outputpubkeyhash = outputToPublicKeyHash(o) catch null;
        if (outputpubkeyhash != null and std.mem.eql(u8, &pubkeyhash, &outputpubkeyhash.?)) {
            outputs[cur] = o;
            cur += 1;
            if (cur == cap) {
                return outputs;
            }
        }
    }
    return outputs;
}

test "index" {
    const allocator = std.testing.allocator;
    var rawtx: [444]u8 = "0200000000010126db029d0ea5d71b4db2e791f40bf3e185069ea2a39a1aab6bf0c783ec8f00300000000000fdffffff020065cd1d0000000016001456606c27faea9b9d0e8e6137787b8a93c733d41f7e87380c0100000016001418ce541f2d276cc58e9e07ecd2c1fcbe2a1801e50247304402203391560059819dbe991e09f34e767ae3cdc21805d87df3e80bad00d2a906c269022032edfdff0b6967b0add9b019a7e664bcf95f59ba7847d06614e49143b08b1e7e0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a400000000".*;
    const transaction = try tx.decodeRawTx(allocator, &rawtx);
    defer transaction.deinit();
    std.debug.print("Total outputs={d}\n", .{transaction.outputs.items.len});
    const outputs = transaction.outputs;
    for (0..outputs.items.len) |i| {
        const output = outputs.items[i];
        std.debug.print("Tx amount={d}, output pubkey={s}\n", .{ output.amount, output.script_pubkey });
    }
    const pk = try PublicKey.fromStrCompressed("03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed".*);
    const hash = try pk.toHash();
    var hashhex: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&hashhex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});

    const s = try script.p2wpkh(allocator, &hashhex);
    defer s.deinit();
    const scripthexcap = s.hexCap();
    const scripthex = try allocator.alloc(u8, scripthexcap);
    defer allocator.free(scripthex);
    try s.toHex(scripthex);
    std.debug.print("scripthex :{s}\n", .{scripthex});
}

test "outputToPublicKeyHash" {
    const allocator = std.testing.allocator;
    var rawtx: [444]u8 = "0200000000010126db029d0ea5d71b4db2e791f40bf3e185069ea2a39a1aab6bf0c783ec8f00300000000000fdffffff020065cd1d0000000016001456606c27faea9b9d0e8e6137787b8a93c733d41f7e87380c0100000016001418ce541f2d276cc58e9e07ecd2c1fcbe2a1801e50247304402203391560059819dbe991e09f34e767ae3cdc21805d87df3e80bad00d2a906c269022032edfdff0b6967b0add9b019a7e664bcf95f59ba7847d06614e49143b08b1e7e0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a400000000".*;
    const transaction = try tx.decodeRawTx(allocator, &rawtx);
    defer transaction.deinit();
    const outputs = transaction.outputs;
    const expectedPublicKeyHash = "56606c27faea9b9d0e8e6137787b8a93c733d41f".*;
    try std.testing.expectEqualStrings(&expectedPublicKeyHash, &try outputToPublicKeyHash(outputs.items[0]));

    const fakescript = "001556606c27faea9b9d0e8e6137787b8a93c733d41f".*;
    const fakeoutput = tx.TxOutput{ .allocator = allocator, .amount = 10, .script_pubkey = &fakescript };
    const res = outputToPublicKeyHash(fakeoutput);
    try std.testing.expectError(error.UnsupportedScriptPubKey, res);
}

test "totalOutputsFor" {
    const allocator = std.testing.allocator;
    var rawtx: [444]u8 = "0200000000010126db029d0ea5d71b4db2e791f40bf3e185069ea2a39a1aab6bf0c783ec8f00300000000000fdffffff020065cd1d0000000016001456606c27faea9b9d0e8e6137787b8a93c733d41f7e87380c0100000016001418ce541f2d276cc58e9e07ecd2c1fcbe2a1801e50247304402203391560059819dbe991e09f34e767ae3cdc21805d87df3e80bad00d2a906c269022032edfdff0b6967b0add9b019a7e664bcf95f59ba7847d06614e49143b08b1e7e0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a400000000".*;
    const transaction = try tx.decodeRawTx(allocator, &rawtx);
    defer transaction.deinit();
    var transactions: [1]tx.Transaction = [1]tx.Transaction{transaction};
    const pk = try PublicKey.fromStrCompressed("03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed".*);
    const hash = try pk.toHash();
    var hashhex: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&hashhex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
    const total = totalOutputsFor(&transactions, hashhex);
    try std.testing.expectEqual(1, total);
}

test "getOutputsFor" {
    const allocator = std.testing.allocator;
    var rawtx: [444]u8 = "0200000000010126db029d0ea5d71b4db2e791f40bf3e185069ea2a39a1aab6bf0c783ec8f00300000000000fdffffff020065cd1d0000000016001456606c27faea9b9d0e8e6137787b8a93c733d41f7e87380c0100000016001418ce541f2d276cc58e9e07ecd2c1fcbe2a1801e50247304402203391560059819dbe991e09f34e767ae3cdc21805d87df3e80bad00d2a906c269022032edfdff0b6967b0add9b019a7e664bcf95f59ba7847d06614e49143b08b1e7e0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a400000000".*;
    const transaction = try tx.decodeRawTx(allocator, &rawtx);
    defer transaction.deinit();
    var transactions: [1]tx.Transaction = [1]tx.Transaction{transaction};
    const pk = try PublicKey.fromStrCompressed("03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed".*);
    const hash = try pk.toHash();
    var hashhex: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&hashhex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
    const outputs = try getOutputsFor(allocator, &transactions, hashhex);
    defer allocator.free(outputs.?);
    try std.testing.expectEqual(1, outputs.?.len);
}
