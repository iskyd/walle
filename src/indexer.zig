const std = @import("std");
const Block = @import("block.zig").Block;
const tx = @import("tx/tx.zig");
const ExtendedPublicKey = @import("bip32/bip32.zig").ExtendedPublicKey;
const PublicKey = @import("bip32/bip32.zig").PublicKey;
const Network = @import("const.zig").Network;
const script = @import("script/script.zig");
const utils = @import("utils.zig");

const P2WPKH_SCRIPT_PREFIX = "0014".*;

// getBlockCount(): usize
// getBlockHash(n: usize): [64]u8
// getBlock(hash: [64]u8): Block
// getRawTransaction(txid: [64]u8): []u8

pub fn main() void {
    std.debug.print("indexer main\n", .{});
}

pub fn getBlockCount() usize {
    return 0;
}

pub fn getBlockHash(n: usize) [64]u8 {
    _ = n;
    return "7611c4b983395fc76a516a185c0d31399cd34a71cbec913b17f816836d50d4b3".*;
}

pub fn getBlock(hash: [64]u8) Block {
    _ = hash;
}

pub fn getRawTransaction(txid: [64]u8) []u8 {
    _ = txid;
}

//pub fn index(allocator: std.mem.Allocator, heigth: usize) void {
//    const currentheigth = getBlockCount();
//    std.debug.print("test\n", .{});
//    for (heigth..currentheigth) |i| {
//        const blockhash = getBlockHash(i);
//        const block = getBlock(blockhash);
//        for (0..block.totalTransactions) |j| {
//            const txid = block.transactions.items[j];
//            const rawtx = getRawTransaction(txid);
//            const transaction = try tx.decodeRawTx(allocator, rawtx);
//
//            const outputs = transaction.outputs;
//            for (0..outputs.items.len) |z| {
//                const output = outputs.items[z];
//                const opubkeyhash = outputToPublicKeyHash(output);
//                const amount = output.amount;
//                _ = amount;
//                const pubkey = output.script_pubkey;
//                _ = pubkey;
//                // check if pubkey match and save output informations
//            }
//
//            const inputs = transaction.inputs;
//            for (0..inputs.items.len) |z| {
//                const input = inputs.items[z];
//                const prevout = input.prevout;
//                if (prevout != null) {
//                    // check if prevout belongs to wallet
//                }
//            }
//        }
//    }
//}

// return hex value of pubkey hash
fn outputToPublicKeyHash(output: tx.TxOutput) ![40]u8 {
    if (std.mem.eql(u8, output.script_pubkey[0..4], &P2WPKH_SCRIPT_PREFIX)) {
        return output.script_pubkey[4..44].*;
    }
    return error.UnsupportedScriptPubKey;
}

fn totalOutputsFor(transactions: []tx.Transaction, pubkeyhash: [40]u8) usize {
    var total: usize = 0;
    for (transactions) |transaction| {
        for (0..transaction.outputs.items.len) |i| {
            const o = transaction.outputs.items[i];
            const outputpubkeyhash = outputToPublicKeyHash(o) catch null;
            if (outputpubkeyhash != null and std.mem.eql(u8, &pubkeyhash, &outputpubkeyhash.?)) {
                total += 1;
            }
        }
    }
    return total;
}

// memory ownership to the caller
fn getOutputsFor(allocator: std.mem.Allocator, transactions: []tx.Transaction, pubkeyhash: [40]u8) !?[]tx.TxOutput {
    const cap = totalOutputsFor(transactions, pubkeyhash);
    if (cap == 0) {
        return null;
    }

    const outputs = try allocator.alloc(tx.TxOutput, cap);
    errdefer comptime unreachable; // no more errors
    var cur: usize = 0;
    for (transactions) |transaction| {
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
    try std.testing.expectEqual()
}
