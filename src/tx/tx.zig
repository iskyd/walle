const std = @import("std");
const script = @import("../script/script.zig");
const utils = @import("../utils.zig");

const TxError = error{
    AmountTooLowError,
};

// Output represented by transaction hash and index n to its outputs
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
        const scriptsighex = try allocator.alloc(u8, scriptsig.len * 2);
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
        const scriptpubkeyhex = try allocator.alloc(u8, script_pubkey.len * 2);
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
        const itemhex = try allocator.alloc(u8, item.len * 2);
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
    inputs: std.ArrayList(TxInput),
    outputs: std.ArrayList(TxOutput),
    witness: std.ArrayList(TxWitness),
    version: u32,
    locktime: u32,
    marker: u8,
    flag: u8,

    pub fn init(allocator: std.mem.Allocator, version: u32, locktime: u32, marker: u8, flag: u8) Transaction {
        return Transaction{ .allocator = allocator, .locktime = locktime, .version = version, .marker = marker, .flag = flag, .inputs = std.ArrayList(TxInput).init(allocator), .outputs = std.ArrayList(TxOutput).init(allocator), .witness = std.ArrayList(TxWitness).init(allocator) };
    }

    pub fn deinit(self: Transaction) void {
        for (self.inputs.items) |inputs| {
            inputs.deinit();
        }
        for (self.outputs.items) |outputs| {
            outputs.deinit();
        }
        for (self.witness.items) |witness| {
            witness.deinit();
        }
        self.inputs.deinit();
        self.outputs.deinit();
        self.witness.deinit();
    }

    pub fn addInput(self: *Transaction, input: TxInput) !void {
        try self.inputs.append(input);
    }

    pub fn addOutput(self: *Transaction, output: TxOutput) !void {
        try self.outputs.append(output);
    }

    pub fn addWitness(self: *Transaction, witness: TxWitness) !void {
        try self.witness.append(witness);
    }

    pub fn isCoinbase(self: Transaction) bool {
        if (self.inputs.items.len == 1 and self.inputs.items[0].prevout == null) {
            return true;
        }
        return false;
    }

    pub fn getOutputValue(self: Transaction) u64 {
        var v: u64 = 0;
        for (self.outputs.items) |output| {
            v += output.amount;
        }
        return v;
    }

    pub fn getTXID(self: Transaction) ![64]u8 {
        const totalBytes: usize = encodeTxCap(self, true);
        const encoded = try self.allocator.alloc(u8, totalBytes);
        defer self.allocator.free(encoded);
        try encodeTx(self.allocator, encoded, self, true);
        const txid = utils.doubleSha256(encoded);
        var txidhex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txidhex, "{x}", .{std.fmt.fmtSliceHexLower(&txid)});
        return txidhex;
    }

    pub fn getWTXID(self: Transaction) ![64]u8 {
        const totalBytes: usize = encodeTxCap(self, false);
        const encoded = try self.allocator.alloc(u8, totalBytes);
        defer self.allocator.free(encoded);
        try encodeTx(self.allocator, encoded, self, false);
        const txid = utils.doubleSha256(encoded);
        var txidhex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txidhex, "{x}", .{std.fmt.fmtSliceHexLower(&txid)});
        return txidhex;
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
    const version = std.mem.readInt(u32, v, .little);
    const marker = bytes[4]; // used to indicate segwit tx. Must be 00
    const flag = bytes[5]; // used to indicate segwit tx. Must be gte 01

    const l = bytes[bytes.len - 4 ..][0..4].*;
    const locktime = std.mem.readInt(u32, &l, .little);

    var transaction = Transaction.init(allocator, version, locktime, marker, flag);

    // Compact Size
    // This byte indicates which bytes encode the integer representing the numbers of inputs.
    // <= FC then this byte, FD then the next two bytes, FE the next four bytes, FF the next eight bytes.
    // Compact Size Input
    const inputsize = utils.decodeCompactSize(bytes[6..15]);
    var currentByte: u64 = 6 + inputsize.totalBytes;
    for (0..inputsize.n) |_| {
        const txid = bytes[currentByte .. currentByte + 32];
        var txidhex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txidhex, "{x}", .{std.fmt.fmtSliceHexLower(txid)});
        currentByte += 32;
        const vo: [4]u8 = bytes[currentByte .. currentByte + 4][0..4].*;
        const outputs = std.mem.readInt(u32, &vo, .little);
        const prevout = Output{ .txid = txidhex, .n = outputs, .amount = 0 };
        currentByte += 4;
        const scriptsigsize = bytes[currentByte];
        currentByte += 1;
        const scriptsig = bytes[currentByte .. currentByte + scriptsigsize];
        currentByte += scriptsigsize;
        const s = bytes[currentByte .. currentByte + 4][0..4].*;
        const sequence = std.mem.readInt(u32, &s, .little);
        currentByte += 4;

        const input = try TxInput.init(allocator, prevout, scriptsig, sequence);
        try transaction.addInput(input);
    }

    // Compat size output
    const outputsize = utils.decodeCompactSize(bytes[currentByte .. currentByte + 9]);
    currentByte += outputsize.totalBytes;
    for (0..outputsize.n) |_| {
        const a = bytes[currentByte .. currentByte + 8][0..8].*;
        currentByte += 8;
        const amount = std.mem.readInt(u64, &a, .little);
        const scriptpubkeysize = bytes[currentByte];
        currentByte += 1;
        const scriptpubkey = bytes[currentByte .. currentByte + scriptpubkeysize];
        currentByte += scriptpubkeysize;
        const output = try TxOutput.init(allocator, amount, scriptpubkey);
        try transaction.addOutput(output);
    }

    // 1 witness for every input
    for (0..inputsize.n) |_| {
        // Compat size, same as ic and oc
        var witness = TxWitness.init(allocator);
        // compact size stack items
        const cssi = utils.decodeCompactSize(bytes[currentByte .. currentByte + 9]);
        currentByte += cssi.totalBytes;
        for (0..cssi.n) |_| {
            // compact size item
            const s = utils.decodeCompactSize(bytes[currentByte .. currentByte + 9]);
            currentByte += s.totalBytes;
            const item = bytes[currentByte .. currentByte + s.n];
            currentByte += s.n;
            try witness.addItem(item);
        }
        try transaction.addWitness(witness);
    }

    return transaction;
}

pub fn encodeTx(allocator: std.mem.Allocator, buffer: []u8, tx: Transaction, txid: bool) !void {
    @memcpy(buffer[0..4], std.mem.asBytes(&tx.version));
    var currentByte: u64 = 4;
    if (txid == false) {
        buffer[4] = std.mem.asBytes(&tx.marker)[0];
        buffer[5] = std.mem.asBytes(&tx.flag)[0];
        currentByte += 2;
    }

    // Encoded compact size input
    const inputsize = utils.encodeCompactSize(tx.inputs.items.len);
    buffer[currentByte] = inputsize.compactSizeByte;
    currentByte += 1;
    if (inputsize.totalBytes > 0) {
        @memcpy(buffer[currentByte .. currentByte + inputsize.totalBytes], std.mem.asBytes(&inputsize.n));
        currentByte += inputsize.totalBytes;
    }
    for (0..tx.inputs.items.len) |i| {
        const input = tx.inputs.items[i];
        var txb: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&txb, &input.prevout.?.txid);
        @memcpy(buffer[currentByte .. currentByte + 32], &txb);
        currentByte += 32;
        @memcpy(buffer[currentByte .. currentByte + 4], std.mem.asBytes(&input.prevout.?.n));
        currentByte += 4;
        // encoded compact size script
        const scriptsize = utils.encodeCompactSize(input.scriptsig.len);
        buffer[currentByte] = scriptsize.compactSizeByte;
        currentByte += 1;
        if (scriptsize.totalBytes > 0) {
            @memcpy(buffer[currentByte .. currentByte + scriptsize.totalBytes], std.mem.asBytes(&scriptsize.n));
            currentByte += scriptsize.totalBytes;
        }
        @memcpy(buffer[currentByte .. currentByte + input.scriptsig.len], input.scriptsig);
        currentByte += input.scriptsig.len;
        @memcpy(buffer[currentByte .. currentByte + 4], std.mem.asBytes(&input.sequence));
        currentByte += 4;
    }

    // encoded compact size output
    const outputsize = utils.encodeCompactSize(tx.outputs.items.len);
    buffer[currentByte] = outputsize.compactSizeByte;
    currentByte += 1;
    if (outputsize.totalBytes > 0) {
        @memcpy(buffer[currentByte .. currentByte + outputsize.totalBytes], std.mem.asBytes(&outputsize.n));
        currentByte += outputsize.totalBytes;
    }
    for (0..tx.outputs.items.len) |i| {
        const output = tx.outputs.items[i];
        @memcpy(buffer[currentByte .. currentByte + 8], std.mem.asBytes(&output.amount));
        currentByte += 8;
        // encoded compact size script pubkey
        const scriptsizepubkey = utils.encodeCompactSize(output.script_pubkey.len / 2); // script_pubkey is in hex format, /2 for bytes representation
        buffer[currentByte] = scriptsizepubkey.compactSizeByte;
        currentByte += 1;
        if (scriptsizepubkey.totalBytes > 0) {
            @memcpy(buffer[currentByte .. currentByte + scriptsizepubkey.totalBytes], std.mem.asBytes(&scriptsizepubkey.n));
            currentByte += scriptsizepubkey.totalBytes;
        }
        const bytes: []u8 = try allocator.alloc(u8, output.script_pubkey.len / 2);
        defer allocator.free(bytes);
        _ = try std.fmt.hexToBytes(bytes, output.script_pubkey);
        @memcpy(buffer[currentByte .. currentByte + output.script_pubkey.len / 2], bytes);
        currentByte += output.script_pubkey.len / 2;
    }

    if (txid == false) {
        // 1 witness for every input
        for (0..tx.inputs.items.len) |i| {
            const witness = tx.witness.items[i];
            // encoded compact size stack
            const witnessstacksize = utils.encodeCompactSize(witness.stackitems.items.len);
            buffer[currentByte] = witnessstacksize.compactSizeByte;
            currentByte += 1;
            if (witnessstacksize.totalBytes > 0) {
                @memcpy(buffer[currentByte .. currentByte + witnessstacksize.totalBytes], std.mem.asBytes(&witnessstacksize.n));
                currentByte += witnessstacksize.totalBytes;
            }
            for (0..witness.stackitems.items.len) |j| {
                const stackitem = witness.stackitems.items[j];
                const stackitemsize = utils.encodeCompactSize(stackitem.item.len / 2);
                buffer[currentByte] = stackitemsize.compactSizeByte;
                currentByte += 1;
                if (stackitemsize.totalBytes > 0) {
                    @memcpy(buffer[currentByte .. currentByte + stackitemsize.totalBytes], std.mem.asBytes(&stackitemsize.n));
                    currentByte += stackitemsize.totalBytes;
                }
                const stackitembytes = try allocator.alloc(u8, stackitem.item.len / 2);
                defer allocator.free(stackitembytes);
                _ = try std.fmt.hexToBytes(stackitembytes, stackitem.item);
                @memcpy(buffer[currentByte .. currentByte + stackitem.item.len / 2], stackitembytes);
                currentByte += stackitem.item.len / 2;
            }
        }
    }
    @memcpy(buffer[currentByte .. currentByte + 4], std.mem.asBytes(&tx.locktime));
}

pub fn encodeTxCap(tx: Transaction, txid: bool) usize {
    var currentByte: usize = 4; // version
    if (txid == false) {
        currentByte += 2; // marker + flag
    }

    // Encoded compact size input
    const inputsize = utils.encodeCompactSize(tx.inputs.items.len);
    currentByte += 1;
    if (inputsize.totalBytes > 0) {
        currentByte += inputsize.totalBytes;
    }
    for (0..tx.inputs.items.len) |i| {
        const input = tx.inputs.items[i];
        currentByte += 32; // input prevout txid
        currentByte += 4; // input prevout n
        // encoded compact size script
        const scriptsize = utils.encodeCompactSize(input.scriptsig.len);
        currentByte += 1;
        if (scriptsize.totalBytes > 0) {
            currentByte += scriptsize.totalBytes;
        }
        currentByte += input.scriptsig.len;
        currentByte += 4; // sequence
    }

    // encoded compact size output
    const outputsize = utils.encodeCompactSize(tx.outputs.items.len);
    currentByte += 1; // outputsize
    if (outputsize.totalBytes > 0) {
        currentByte += outputsize.totalBytes;
    }
    for (0..tx.outputs.items.len) |i| {
        const output = tx.outputs.items[i];
        currentByte += 8; // output amount
        // encoded compact size script pubkey
        const scriptsizepubkey = utils.encodeCompactSize(output.script_pubkey.len / 2); // script_pubkey is in hex format, /2 for bytes representation
        currentByte += 1;
        if (scriptsizepubkey.totalBytes > 0) {
            currentByte += scriptsizepubkey.totalBytes;
        }
        currentByte += output.script_pubkey.len / 2; // script pubkey
    }

    if (txid == false) {
        // 1 witness for every input
        for (0..tx.inputs.items.len) |i| {
            const witness = tx.witness.items[i];
            // encoded compact size stack
            const witnessstacksize = utils.encodeCompactSize(witness.stackitems.items.len);
            currentByte += 1;
            if (witnessstacksize.totalBytes > 0) {
                currentByte += witnessstacksize.totalBytes;
            }
            for (0..witness.stackitems.items.len) |j| {
                const stackitem = witness.stackitems.items[j];
                const stackitemsize = utils.encodeCompactSize(stackitem.item.len / 2);
                currentByte += 1;
                if (stackitemsize.totalBytes > 0) {
                    currentByte += stackitemsize.totalBytes;
                }
                currentByte += stackitem.item.len / 2; // stackitem
            }
        }
    }
    return currentByte + 4; //locktime
}

test "getOutputValue" {
    const allocator = std.testing.allocator;
    const o = Output{ .txid = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .n = 0, .amount = 0 };
    var r: [64]u8 = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*;
    const public: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var tx = Transaction.init(allocator, 0, 1, 0, 1);
    defer tx.deinit();
    const txin = try TxInput.init(allocator, o, &r, 0);
    try tx.addInput(txin);
    const txout1 = try TxOutput.init(allocator, 130000, &public);
    const txout2 = try TxOutput.init(allocator, 37000, &public);
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
    try std.testing.expectEqual(tx.inputs.items.len, 1);
    try std.testing.expectEqual(tx.inputs.items[0].sequence, 4294967295);
    try std.testing.expectEqual(tx.inputs.items[0].prevout.?.n, 4294967295);
    var expectedPrevoutTxId = "0000000000000000000000000000000000000000000000000000000000000000".*;
    try std.testing.expectEqualStrings(&expectedPrevoutTxId, &tx.inputs.items[0].prevout.?.txid);
    var expectedScriptSig = "5100".*;
    try std.testing.expectEqualStrings(&expectedScriptSig, tx.inputs.items[0].scriptsig);
    try std.testing.expectEqual(tx.outputs.items.len, 2);
    try std.testing.expectEqual(tx.outputs.items[0].amount, 5000000000);
    var expectedPubKeyScript1 = "0014dd3d4b7d821d44331e31a818d15f583302e8e1c0".*;
    try std.testing.expectEqualStrings(&expectedPubKeyScript1, tx.outputs.items[0].script_pubkey);
    try std.testing.expectEqual(tx.outputs.items[1].amount, 0);
    var expectedPubKeyScript2 = "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9".*;
    try std.testing.expectEqualStrings(&expectedPubKeyScript2, tx.outputs.items[1].script_pubkey);
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
    try std.testing.expectEqual(tx.inputs.items.len, 3);
    try std.testing.expectEqual(tx.outputs.items.len, 2);
    try std.testing.expectEqual(tx.witness.items.len, 3);

    const expectedTxIn1 = "c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec32748673".*;
    try std.testing.expectEqualStrings(&expectedTxIn1, &tx.inputs.items[0].prevout.?.txid);

    const expectedTxIn2 = "daf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef33".*;
    try std.testing.expectEqualStrings(&expectedTxIn2, &tx.inputs.items[1].prevout.?.txid);

    const expectedTxIn3 = "01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b0".*;
    try std.testing.expectEqualStrings(&expectedTxIn3, &tx.inputs.items[2].prevout.?.txid);

    try std.testing.expectEqual(tx.outputs.items[0].amount, 10000000000);
    const expectedPubkey1 = "00147218978afd7fd9270bae7595399b6bc1986e7a4e".*;
    try std.testing.expectEqualStrings(&expectedPubkey1, tx.outputs.items[0].script_pubkey);

    try std.testing.expectEqual(tx.outputs.items[1].amount, 4999999724);
    const expectedPubkey2 = "0014009724e4053330c337bb803eca10071462821246".*;
    try std.testing.expectEqualStrings(&expectedPubkey2, tx.outputs.items[1].script_pubkey);

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

test "encodeTx" {
    const allocator = std.testing.allocator;
    var raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    var buffer: [518]u8 = undefined;
    try encodeTx(allocator, &buffer, tx, false);
    var encodedhex: [1036]u8 = undefined;
    _ = try std.fmt.bufPrint(&encodedhex, "{x}", .{std.fmt.fmtSliceHexLower(&buffer)});

    try std.testing.expectEqualStrings(&raw, &encodedhex);
}

test "txid" {
    const expectedtxid = "f455759f8e184926b7b6a2af4f33fb026da94920a850b3091e1654b9236d33e8".*;
    const allocator = std.testing.allocator;
    var raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    const txid = try tx.getTXID();
    try std.testing.expectEqualStrings(&expectedtxid, &txid);
}

test "wtxid" {
    const expectedtxid = "4d95fff811ffdaefcf9add9217d76f123cdc227581fed44de7c43d75a2aa6ac0".*;
    const expectedwtxid = "ff63ed0cc02c85a7aef6510625b6897abe1b969293f5db2991804e23f2562df1".*;
    const allocator = std.testing.allocator;
    var raw: [450]u8 = "01000000000101438afdb24e414d54cc4a17a95f3d40be90d23dfeeb07a48e9e782178efddd8890100000000fdffffff020db9a60000000000160014b549d227c9edd758288112fe3573c1f85240166880a81201000000001976a914ae28f233464e6da03c052155119a413d13f3380188ac024730440220200254b765f25126334b8de16ee4badf57315c047243942340c16cffd9b11196022074a9476633f093f229456ad904a9d97e26c271fc4f01d0501dec008e4aae71c2012102c37a3c5b21a5991d3d7b1e203be195be07104a1a19e5c2ed82329a56b431213000000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    const txid = try tx.getTXID();
    const wtxid = try tx.getWTXID();
    try std.testing.expectEqualStrings(&expectedtxid, &txid);
    try std.testing.expectEqualStrings(&expectedwtxid, &wtxid);
}

test "encodeTxCap" {
    const allocator = std.testing.allocator;
    var raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    try std.testing.expectEqual(encodeTxCap(tx, false), 518);
}

test "encodeTxCapTxID" {
    const allocator = std.testing.allocator;
    var raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    try std.testing.expectEqual(encodeTxCap(tx, true), 195);
}
