const std = @import("std");

pub const Block = struct {
    hash: [64]u8,
    confirmations: usize,
    heigth: usize,
    version: usize,
    merkleroot: [64]u8,
    time: usize,
    mediantime: usize,
    nonce: usize,
    bits: [8]u8,
    difficulty: usize,
    chainwork: [64]u8,
    totalTransactions: usize,
    prevblockhash: [64]u8,
    nextblockhash: ?[64]u8,
    strippedsize: usize,
    size: usize,
    weigth: usize,
    transactions: std.ArrayList([64]u8),
};
