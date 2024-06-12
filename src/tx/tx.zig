const std = @import("std");
const script = @import("../script/script.zig");
const utils = @import("../utils.zig");

const TxError = error{
    AmountTooLowError,
};

// Output represented by transaction hash and index n to its vout
const Output = struct {
    txid: [64]u8,
    n: u32,
    amount: u32,
};

// Input of a transaction
const TxInput = struct {
    allocator: std.mem.Allocator,
    prevout: ?Output, // nullable due to coinbase transaction
    scriptsig: []u8,
    sequence: u32,

    // scriptsig in bytes
    pub fn init(allocator: std.mem.Allocator, prevout: ?Output, scriptsig: []u8, sequence: u32) !TxInput {
        var scriptsighex = try allocator.alloc(u8, scriptsig.len * 2);
        _ = try std.fmt.bufPrint(scriptsighex, "{x}", .{std.fmt.fmtSliceHexLower(scriptsig)});
        return TxInput{ .allocator = allocator, .prevout = prevout, .scriptsig = scriptsighex, .sequence = sequence };
    }

    pub fn deinit(self: TxInput) void {
        self.allocator.free(self.scriptsig);
    }
};

// Output of a transaction
const TxOutput = struct {
    allocator: std.mem.Allocator,
    amount: u64,
    script_pubkey: []const u8,

    // script_pubkey in bytes
    pub fn init(allocator: std.mem.Allocator, amount: u64, script_pubkey: []const u8) !TxOutput {
        var scriptpubkeyhex = try allocator.alloc(u8, script_pubkey.len * 2);
        _ = try std.fmt.bufPrint(scriptpubkeyhex, "{x}", .{std.fmt.fmtSliceHexLower(script_pubkey)});
        return TxOutput{ .allocator = allocator, .amount = amount, .script_pubkey = scriptpubkeyhex };
    }

    pub fn deinit(self: TxOutput) void {
        self.allocator.free(self.script_pubkey);
    }
};

pub const WitnessItem = struct {
    allocator: std.mem.Allocator,
    item: []const u8,

    // item in bytes
    pub fn init(allocator: std.mem.Allocator, item: []const u8) !WitnessItem {
        var itemhex = try allocator.alloc(u8, item.len * 2);
        _ = try std.fmt.bufPrint(itemhex, "{x}", .{std.fmt.fmtSliceHexLower(item)});
        return WitnessItem{ .allocator = allocator, .item = itemhex };
    }

    pub fn deinit(self: WitnessItem) void {
        self.allocator.free(self.item);
    }
};

pub const TxWitness = struct {
    allocator: std.mem.Allocator,
    stackitems: std.ArrayList(WitnessItem),

    pub fn init(allocator: std.mem.Allocator) TxWitness {
        return TxWitness{ .allocator = allocator, .stackitems = std.ArrayList(WitnessItem).init(allocator) };
    }

    pub fn deinit(self: TxWitness) void {
        for (self.stackitems.items) |i| {
            i.deinit();
        }
        self.stackitems.deinit();
    }

    // Item in byte
    pub fn addItem(self: *TxWitness, item: []const u8) !void {
        const witnessitem = try WitnessItem.init(self.allocator, item);
        try self.stackitems.append(witnessitem);
    }
};

// Transaction
pub const Transaction = struct {
    allocator: std.mem.Allocator,
    vin: std.ArrayList(TxInput),
    vout: std.ArrayList(TxOutput),
    witness: std.ArrayList(TxWitness),
    version: u32,
    locktime: u32,
    marker: u8,
    flag: u8,

    pub fn init(allocator: std.mem.Allocator, version: u32, locktime: u32, marker: u8, flag: u8) Transaction {
        return Transaction{ .allocator = allocator, .locktime = locktime, .version = version, .marker = marker, .flag = flag, .vin = std.ArrayList(TxInput).init(allocator), .vout = std.ArrayList(TxOutput).init(allocator), .witness = std.ArrayList(TxWitness).init(allocator) };
    }

    pub fn deinit(self: Transaction) void {
        for (self.vin.items) |vin| {
            vin.deinit();
        }
        for (self.vout.items) |vout| {
            vout.deinit();
        }
        for (self.witness.items) |witness| {
            witness.deinit();
        }
        self.vin.deinit();
        self.vout.deinit();
        self.witness.deinit();
    }

    pub fn addInput(self: *Transaction, input: TxInput) !void {
        try self.vin.append(input);
    }

    pub fn addOutput(self: *Transaction, output: TxOutput) !void {
        try self.vout.append(output);
    }

    pub fn addWitness(self: *Transaction, witness: TxWitness) !void {
        try self.witness.append(witness);
    }

    pub fn isCoinbase(self: Transaction) bool {
        if (self.vin.items.len == 1 and self.vin.items[0].prevout == null) {
            return true;
        }
        return false;
    }

    pub fn getOutputValue(self: Transaction) u64 {
        var v: u64 = 0;
        for (self.vout.items) |output| {
            v += output.amount;
        }
        return v;
    }
};

pub fn createTx(inputs: []Output, amount: u32) TxError!void {
    var total: u32 = 0;
    for (inputs) |input| {
        total += input.amount;
    }
    if (total <= amount) {
        return TxError.AmountTooLowError;
    }
}

pub fn decodeRawTx(allocator: std.mem.Allocator, raw: []u8) !Transaction {
    var bytes: []u8 = try allocator.alloc(u8, raw.len / 2);
    _ = try std.fmt.hexToBytes(bytes, raw);
    defer allocator.free(bytes);
    const v = bytes[0..4]; // Little Endian
    const version = std.mem.readIntLittle(u32, v);
    const marker = bytes[4]; // used to indicate segwit tx. Must be 00
    const flag = bytes[5]; // used to indicate segwit tx. Must be gte 01

    const l = bytes[bytes.len - 4 ..][0..4].*;
    const locktime = std.mem.readIntLittle(u32, &l);

    var transaction = Transaction.init(allocator, version, locktime, marker, flag);

    // Compact Size
    // This byte indicates which bytes encode the integer representing the numbers of inputs.
    // <= FC then this byte, FD then the next two bytes, FE the next four bytes, FF the next eight bytes.
    // Compact Size Input
    const csi = utils.calculateCompactSize(bytes[6..15]);
    var currentByte: u64 = 6 + csi.totalBytes;
    for (0..csi.n) |_| {
        const txid = bytes[currentByte .. currentByte + 32];
        var txidhex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txidhex, "{x}", .{std.fmt.fmtSliceHexLower(txid)});
        currentByte += 32;
        const vo: [4]u8 = bytes[currentByte .. currentByte + 4][0..4].*;
        const vout = std.mem.readIntLittle(u32, &vo);
        const prevout = Output{ .txid = txidhex, .n = vout, .amount = 0 };
        currentByte += 4;
        const scriptsigsize = bytes[currentByte];
        currentByte += 1;
        const scriptsig = bytes[currentByte .. currentByte + scriptsigsize];
        currentByte += scriptsigsize;
        const s = bytes[currentByte .. currentByte + 4][0..4].*;
        const sequence = std.mem.readIntLittle(u32, &s);
        currentByte += 4;

        const input = try TxInput.init(allocator, prevout, scriptsig, sequence);
        try transaction.addInput(input);
    }

    // Compat size output
    const cso = utils.calculateCompactSize(bytes[currentByte .. currentByte + 9]);
    currentByte += cso.totalBytes;
    for (0..cso.n) |_| {
        const a = bytes[currentByte .. currentByte + 8][0..8].*;
        currentByte += 8;
        const amount = std.mem.readIntLittle(u64, &a);
        const scriptpubkeysize = bytes[currentByte];
        currentByte += 1;
        const scriptpubkey = bytes[currentByte .. currentByte + scriptpubkeysize];
        currentByte += scriptpubkeysize;
        const output = try TxOutput.init(allocator, amount, scriptpubkey);
        try transaction.addOutput(output);
    }

    // 1 witness for every input
    for (0..csi.n) |_| {
        // Compat size, same as ic and oc
        var witness = TxWitness.init(allocator);
        // compact size stack items
        const cssi = utils.calculateCompactSize(bytes[currentByte .. currentByte + 9]);
        currentByte += cssi.totalBytes;
        for (0..cssi.n) |_| {
            // compact size item
            const s = utils.calculateCompactSize(bytes[currentByte .. currentByte + 9]);
            currentByte += s.totalBytes;
            const item = bytes[currentByte .. currentByte + s.n];
            currentByte += s.n;
            try witness.addItem(item);
        }
        try transaction.addWitness(witness);
    }

    return transaction;
}

test "getOutputValue" {
    const allocator = std.testing.allocator;
    const o = Output{ .txid = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .n = 0, .amount = 0 };
    var r: [64]u8 = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*;
    const public: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var tx = Transaction.init(allocator, 0, 1, 0, 1);
    defer tx.deinit();
    var txin = try TxInput.init(allocator, o, &r, 0);
    try tx.addInput(txin);
    var txout1 = try TxOutput.init(allocator, 130000, &public);
    var txout2 = try TxOutput.init(allocator, 37000, &public);
    try tx.addOutput(txout1);
    try tx.addOutput(txout2);
    const outputv = tx.getOutputValue();
    try std.testing.expectEqual(outputv, 167000);
}

test "createTx" {
    const o1 = Output{ .txid = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .n = 0, .amount = 10000 };
    const o2 = Output{ .txid = "cabfe93aaa1d0ddb1c9faf1da80d902a693a9c84b9673f5524abf1fa3ce46349".*, .n = 1, .amount = 20000 };

    var outputs: [2]Output = [2]Output{ o1, o2 };
    try std.testing.expectError(TxError.AmountTooLowError, createTx(&outputs, 31000));
}

test "decodeRawTxCoinbase" {
    const allocator = std.testing.allocator;
    var raw: [334]u8 = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a01000000160014dd3d4b7d821d44331e31a818d15f583302e8e1c00000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    try std.testing.expectEqual(tx.version, 2);
    try std.testing.expectEqual(tx.marker, 0);
    try std.testing.expectEqual(tx.flag, 1);
    try std.testing.expectEqual(tx.locktime, 0);
    try std.testing.expectEqual(tx.vin.items.len, 1);
    try std.testing.expectEqual(tx.vin.items[0].sequence, 4294967295);
    try std.testing.expectEqual(tx.vin.items[0].prevout.?.n, 4294967295);
    var expectedPrevoutTxId = "0000000000000000000000000000000000000000000000000000000000000000".*;
    try std.testing.expectEqualStrings(&expectedPrevoutTxId, &tx.vin.items[0].prevout.?.txid);
    var expectedScriptSig = "5100".*;
    try std.testing.expectEqualStrings(&expectedScriptSig, tx.vin.items[0].scriptsig);
    try std.testing.expectEqual(tx.vout.items.len, 2);
    try std.testing.expectEqual(tx.vout.items[0].amount, 5000000000);
    var expectedPubKeyScript1 = "0014dd3d4b7d821d44331e31a818d15f583302e8e1c0".*;
    try std.testing.expectEqualStrings(&expectedPubKeyScript1, tx.vout.items[0].script_pubkey);
    try std.testing.expectEqual(tx.vout.items[1].amount, 0);
    var expectedPubKeyScript2 = "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9".*;
    try std.testing.expectEqualStrings(&expectedPubKeyScript2, tx.vout.items[1].script_pubkey);
    try std.testing.expectEqual(tx.witness.items.len, 1);
    var expectedWitness = "0000000000000000000000000000000000000000000000000000000000000000".*;
    try std.testing.expectEqualStrings(&expectedWitness, tx.witness.items[0].stackitems.items[0].item);
}

test "decodeRawTxSimple" {
    const allocator = std.testing.allocator;
    var raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    try std.testing.expectEqual(tx.version, 2);
    try std.testing.expectEqual(tx.marker, 0);
    try std.testing.expectEqual(tx.flag, 1);
    try std.testing.expectEqual(tx.locktime, 200);
    try std.testing.expectEqual(tx.vin.items.len, 3);
    try std.testing.expectEqual(tx.vout.items.len, 2);
    try std.testing.expectEqual(tx.witness.items.len, 3);

    const expectedTxIn1 = "c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec32748673".*;
    try std.testing.expectEqualStrings(&expectedTxIn1, &tx.vin.items[0].prevout.?.txid);

    const expectedTxIn2 = "daf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef33".*;
    try std.testing.expectEqualStrings(&expectedTxIn2, &tx.vin.items[1].prevout.?.txid);

    const expectedTxIn3 = "01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b0".*;
    try std.testing.expectEqualStrings(&expectedTxIn3, &tx.vin.items[2].prevout.?.txid);

    try std.testing.expectEqual(tx.vout.items[0].amount, 10000000000);
    const expectedPubkey1 = "00147218978afd7fd9270bae7595399b6bc1986e7a4e".*;
    try std.testing.expectEqualStrings(&expectedPubkey1, tx.vout.items[0].script_pubkey);

    try std.testing.expectEqual(tx.vout.items[1].amount, 4999999724);
    const expectedPubkey2 = "0014009724e4053330c337bb803eca10071462821246".*;
    try std.testing.expectEqualStrings(&expectedPubkey2, tx.vout.items[1].script_pubkey);

    const expectedWitness1Item1 = "3044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e288701".*;
    const expectedWitness1Item2 = "029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4".*;
    try std.testing.expectEqualStrings(&expectedWitness1Item1, tx.witness.items[0].stackitems.items[0].item);
    try std.testing.expectEqualStrings(&expectedWitness1Item2, tx.witness.items[0].stackitems.items[1].item);

    const expectedWitness2Item1 = "30440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b01".*;
    const expectedWitness2Item2 = "029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4".*;
    try std.testing.expectEqualStrings(&expectedWitness2Item1, tx.witness.items[1].stackitems.items[0].item);
    try std.testing.expectEqualStrings(&expectedWitness2Item2, tx.witness.items[1].stackitems.items[1].item);

    const expectedWitness3Item1 = "304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a861101".*;
    const expectedWitness3Item2 = "029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4".*;
    try std.testing.expectEqualStrings(&expectedWitness3Item1, tx.witness.items[2].stackitems.items[0].item);
    try std.testing.expectEqualStrings(&expectedWitness3Item2, tx.witness.items[2].stackitems.items[1].item);
}
