const std = @import("std");
const script = @import("../script/script.zig");

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

pub const TxWitness = struct {
    allocator: std.mem.Allocator,
    item: []const u8,

    // item in bytes
    pub fn init(allocator: std.mem.Allocator, item: []const u8) !TxWitness {
        var itemhex = try allocator.alloc(u8, item.len * 2);
        _ = try std.fmt.bufPrint(itemhex, "{x}", .{std.fmt.fmtSliceHexLower(item)});
        return TxWitness{ .allocator = allocator, .item = itemhex };
    }

    pub fn deinit(self: TxWitness) void {
        self.allocator.free(self.item);
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

    const l = bytes[bytes.len - 5 ..][0..4].*;
    const locktime = std.mem.readIntLittle(u32, &l);

    var transaction = Transaction.init(allocator, version, locktime, marker, flag);

    // Compat Size
    // This byte indicates which bytes encode the integer representing the numbers of inputs.
    // <= FC then this byte, FD then the next two bytes, FE the next four bytes, FF the next eight bytes.
    // ATM just using this bytes as byte count
    // TODO: add the other scenario
    const ci = bytes[6];
    var currentByte: u32 = 7;
    for (0..ci) |i| {
        const txid = bytes[currentByte .. currentByte + 32];
        var txidhex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txidhex, "{x}", .{std.fmt.fmtSliceHexLower(txid)});
        _ = i;
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

    // Compat size, same as ic
    const oc = bytes[currentByte];
    currentByte += 1;
    for (0..oc) |i| {
        _ = i;
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

    // Compat size, same as ic and oc
    const stackitems = bytes[currentByte];
    currentByte += 1;
    for (0..stackitems) |i| {
        _ = i;
        const size = bytes[currentByte];
        currentByte += 1;
        const item = bytes[currentByte .. currentByte + size];
        currentByte += size;
        const witness = try TxWitness.init(allocator, item);
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

test "decodeRawTx" {
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
    try std.testing.expectEqualStrings(&expectedWitness, tx.witness.items[0].item);
}
