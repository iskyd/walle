const std = @import("std");
const script = @import("script.zig");
const utils = @import("utils.zig");
const KeyPath = @import("bip44.zig").KeyPath;

const COINBASE_TX_ID: [64]u8 = "0000000000000000000000000000000000000000000000000000000000000000".*;

const TxError = error{
    AmountTooLowError,
};

pub const Input = struct {
    txid: [64]u8,
    outputtxid: [64]u8,
    outputn: u32,
};

// Output represented by transaction hash and index n to its outputs
pub const Output = struct {
    txid: [64]u8,
    n: u32,
    amount: u64,
    unspent: ?bool = null,
    keypath: ?KeyPath = null,
};

// Input of a transaction
pub const TxInput = struct {
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
pub const TxOutput = struct {
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
    marker: ?u8,
    flag: ?u8,

    pub fn init(allocator: std.mem.Allocator, version: u32, locktime: u32, marker: ?u8, flag: ?u8) Transaction {
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
        if (self.inputs.items.len == 1 and (self.inputs.items[0].prevout == null or (std.mem.eql(u8, &self.inputs.items[0].prevout.?.txid, &COINBASE_TX_ID) and self.inputs.items[0].prevout.?.n == 4294967295))) {
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
    var total: u64 = 0;
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
    std.debug.assert(version == 1 or version == 2);
    var currentByte: u64 = 4;
    // Marker and flag are used to indicate segwit tx. Can be null for version 1 tx
    // https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
    var marker: ?u8 = null;
    var flag: ?u8 = null;
    if (bytes[4] == 0 and bytes[5] == 1) { // match the pattern
        marker = bytes[4]; // used to indicate segwit tx. Must be 00
        flag = bytes[5]; // used to indicate segwit tx. Must be gte 01
        currentByte += 2;
    }

    const l = bytes[bytes.len - 4 ..][0..4].*;
    const locktime = std.mem.readInt(u32, &l, .little);

    var transaction = Transaction.init(allocator, version, locktime, marker, flag);

    // Compact Size
    // This byte indicates which bytes encode the integer representing the numbers of inputs.
    // <= FC then this byte, FD then the next two bytes, FE the next four bytes, FF the next eight bytes.
    // Compact Size Input
    const inputsize = utils.decodeCompactSize(bytes[currentByte .. currentByte + 9]);
    currentByte += inputsize.totalBytes;
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

    if (marker != null and marker.? == 0 and flag != null and flag != 0) { // it's segwit
        // 1 witness for every input
        for (0..inputsize.n) |_| {
            // Compat size, same as ic and oc
            var witness = TxWitness.init(allocator);
            // compact size stack items
            const stackitemssize = utils.decodeCompactSize(bytes[currentByte .. currentByte + 9]);
            currentByte += stackitemssize.totalBytes;
            for (0..stackitemssize.n) |_| {
                // compact size item
                const s = utils.decodeCompactSize(bytes[currentByte .. currentByte + 9]);
                currentByte += s.totalBytes;
                const item = bytes[currentByte .. currentByte + s.n];
                currentByte += s.n;
                try witness.addItem(item);
            }
            try transaction.addWitness(witness);
        }
    }

    return transaction;
}

pub fn encodeTx(allocator: std.mem.Allocator, buffer: []u8, tx: Transaction, txid: bool) !void {
    @memcpy(buffer[0..4], std.mem.asBytes(&tx.version));
    var currentByte: u64 = 4;
    if (txid == false and tx.marker != null and tx.flag != null) {
        std.debug.assert(tx.marker != null and tx.flag != null); // Marker and flag are required for tx version 2 as describe in bip144
        buffer[4] = std.mem.asBytes(&tx.marker.?)[0];
        buffer[5] = std.mem.asBytes(&tx.flag.?)[0];
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
        const scriptsize = utils.encodeCompactSize(input.scriptsig.len / 2);
        buffer[currentByte] = scriptsize.compactSizeByte;
        currentByte += 1;
        if (scriptsize.totalBytes > 0) {
            @memcpy(buffer[currentByte .. currentByte + scriptsize.totalBytes], std.mem.asBytes(&scriptsize.n));
            currentByte += scriptsize.totalBytes;
        }
        const scriptsigbytes = try allocator.alloc(u8, input.scriptsig.len / 2);
        defer allocator.free(scriptsigbytes);
        _ = try std.fmt.hexToBytes(scriptsigbytes, input.scriptsig);
        @memcpy(buffer[currentByte .. currentByte + input.scriptsig.len / 2], scriptsigbytes);
        currentByte += input.scriptsig.len / 2;
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
        const scriptsize = utils.encodeCompactSize(input.scriptsig.len / 2);
        currentByte += 1;
        if (scriptsize.totalBytes > 0) {
            currentByte += input.scriptsig.len / 2;
        }
        currentByte += input.scriptsig.len / 2;
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

test "txversion2coinbase" {
    const expectedtxid = "5afb3d180b56a65f3ac5c29633e941007a8ad4cc19164eafd626457f2174c46e".*;
    const allocator = std.testing.allocator;
    const raw = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600141065b3dd70fa8d3f9a16a070e7d68d8ea39beb880000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000".*;
    const tx = try decodeRawTx(allocator, @constCast(&raw));
    defer tx.deinit();
    const txid = try tx.getTXID();
    try std.testing.expectEqualStrings(&expectedtxid, &txid);
}

test "txversion1genesis" {
    const allocator = std.testing.allocator;
    const expectedtxid = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a".*;
    const raw = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000".*;
    const tx = try decodeRawTx(allocator, @constCast(&raw));
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

test "decodeandtxidbigtx" {
    const allocator = std.testing.allocator;
    var raw = "0100000000010163c7d4d11b8d0f4d639c6e793e3c6df17e41266e7978fbfa8ff86a98525ace3305000000171600141a32847a8e47455eb34810198296f5ba55ef5533ffffffff2db0ad010000000000160014fe732e1609ace3514a4e1f86d0bcdbdeee20917fd84703000000000017a91485626661dea21c9b7bfe3dfd337e2b8215d9adaa87099a0400000000001976a914d0f5a749de85ffe93c7907a2cc51c4db2d447bb988ac00e204000000000017a914bbb24bbbb2a3244b6ab09e37133bfd7ffe43a5e387149606000000000017a9142f9935540a7dbf1e5c2b0360d99270ef827215998763be09000000000017a9141b15aa3d213fecaec014d6145f5343706537dfe487af020a000000000017a914474022a3202350d7a125da27781d99cb2a6912268720120a000000000017a9144a5de6c16c548528f19f0e5af1b3c1cfd6182f0c8714670a0000000000160014ed494d1107e2a938830744b507009ca9afae1ba440420f000000000017a914de89cfc0c58c3f2dfe19089bc215a55e7f42816187f6801000000000001976a9149ca0596591575e7918bafd81969208b88892e17188ac4ed410000000000017a914458e449732ed4971ce3acb9fb98eac43fc3cdc34872c5d11000000000017a9148ee52c5201edad4d2d2b86f66169fbb1c055f56187136b11000000000017a91419b03c51c341c4da61adec035e932647e8292f1c87804f12000000000017a9149a9a3edefae37a1a17a6ad106fe412b514429ab0871c7514000000000017a91445ea1981c4758c5fb1935a56fca95556219723648704d614000000000017a914fb961c729b4cac147ae792db291e85084807a59187a4591500000000001600143f8c416199a2454ccf23d8717ab10313f731ac9ed1ad150000000000160014a2771b8dc3fe6dbdf7ca821763360940e13de0053db016000000000017a914ea1865640094cc2cbdab1c592cd9d4773d55601387b0a617000000000017a914492f96724df3a85a9f3893017d09a3bffbb030a887e09818000000000017a91453bc1af769d2356d4ff8ba103ba83008f93380528707431d00000000001976a9149500bc0c16e3a6cbc0438af90e94b83364f6bffd88ac9ca41e00000000001976a914e27b5a80d961e0ee4144edc562e5848678f9cce288ac7a272300000000001976a9148584fe6d3b8a41ecd1840919ab98ecd9f16894a988ac80ee36000000000017a91426cc326ae6f496e421889c57494c98646108f5b18785733c000000000016001473a01568596519d3bc924756f647316ff7778a55dc253d000000000017a9142d079eed3636149a758b1acd5757910823a01d958720c155000000000017a9142c1ad0af56f340a9983d9080ec9f3480a05fd6db87ca495a00000000001600147039a4640d98d3dfbf65a8d81af3f9797ba59ca1e24a5a000000000016001422b426058b798231b98c0a172eea254ffa78fb7b9f225b000000000017a91492762e9dd8c6f3be6f8b3eae784f4ee7141b4a7587c09a5e000000000017a914291309107afddd6222eea5df261cdf7429d3fccb875ac45e0000000000160014c806df6b7cabf01fe787d38bbfc04978af3894cc20d960000000000016001417a33fe4469adeabbe117d412d27c1d948615e25af5167000000000017a914e334ea4816db2986069fc572d00ceb86780ebdcd875433690000000000160014bc19ad30eb139573e72daecbdfb5a43c299d8494cde977000000000017a914edf5455d5dfa60335a020e30390049a78049c07e87e0a57e000000000017a914efaffad14e8b8dc872b7a551deca4d394794414587c0e1e4000000000017a9146ae3f0b1e58d6cd3239d4a792d26e561d8e2c3e78780a812010000000017a914ee0fc83c7aaf46de3f3d04121165d3385adad3cf87c0ea21010000000017a914ce5698a58de1d3da19b6b279bb5db1ababe426fa8740d958010000000017a914268803d8241a0c8b76e7a69c500ad854176f176d87438a42020000000017a914b15c19c86d2b8d25042dbfa9c3415bda14ebfada874d0b74500000000017a914903b8360fdecd474f4625be5cfbc73d2ae2769aa8702473044022018ca4dc96716a910b54d4a78cff0c5a9c3aefe40c3a047128f1e045f163589af022004dfc91298efd47a9cfe5c33f81aba52d1604d0e7234a3f4e9c2baf48c5a8fde012103504252e45cc192c46f30776080f36f8e960d7683b5f43f0f68a0efeb10cda11700000000".*;
    const tx = try decodeRawTx(allocator, &raw);
    defer tx.deinit();
    const txid = try tx.getTXID();
    const expected = "6eb6f3b6cd6ea982d647b2b685f4c809e2f761a8309e4c14b601abab87820e6e".*;
    try std.testing.expectEqualStrings(&expected, &txid);
}

test "isCoinbase" {
    const allocator = std.testing.allocator;
    const raw = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600141065b3dd70fa8d3f9a16a070e7d68d8ea39beb880000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000".*;
    const tx = try decodeRawTx(allocator, @constCast(&raw));
    defer tx.deinit();
    try std.testing.expectEqual(true, tx.isCoinbase());

    var raw2 = "0100000000010163c7d4d11b8d0f4d639c6e793e3c6df17e41266e7978fbfa8ff86a98525ace3305000000171600141a32847a8e47455eb34810198296f5ba55ef5533ffffffff2db0ad010000000000160014fe732e1609ace3514a4e1f86d0bcdbdeee20917fd84703000000000017a91485626661dea21c9b7bfe3dfd337e2b8215d9adaa87099a0400000000001976a914d0f5a749de85ffe93c7907a2cc51c4db2d447bb988ac00e204000000000017a914bbb24bbbb2a3244b6ab09e37133bfd7ffe43a5e387149606000000000017a9142f9935540a7dbf1e5c2b0360d99270ef827215998763be09000000000017a9141b15aa3d213fecaec014d6145f5343706537dfe487af020a000000000017a914474022a3202350d7a125da27781d99cb2a6912268720120a000000000017a9144a5de6c16c548528f19f0e5af1b3c1cfd6182f0c8714670a0000000000160014ed494d1107e2a938830744b507009ca9afae1ba440420f000000000017a914de89cfc0c58c3f2dfe19089bc215a55e7f42816187f6801000000000001976a9149ca0596591575e7918bafd81969208b88892e17188ac4ed410000000000017a914458e449732ed4971ce3acb9fb98eac43fc3cdc34872c5d11000000000017a9148ee52c5201edad4d2d2b86f66169fbb1c055f56187136b11000000000017a91419b03c51c341c4da61adec035e932647e8292f1c87804f12000000000017a9149a9a3edefae37a1a17a6ad106fe412b514429ab0871c7514000000000017a91445ea1981c4758c5fb1935a56fca95556219723648704d614000000000017a914fb961c729b4cac147ae792db291e85084807a59187a4591500000000001600143f8c416199a2454ccf23d8717ab10313f731ac9ed1ad150000000000160014a2771b8dc3fe6dbdf7ca821763360940e13de0053db016000000000017a914ea1865640094cc2cbdab1c592cd9d4773d55601387b0a617000000000017a914492f96724df3a85a9f3893017d09a3bffbb030a887e09818000000000017a91453bc1af769d2356d4ff8ba103ba83008f93380528707431d00000000001976a9149500bc0c16e3a6cbc0438af90e94b83364f6bffd88ac9ca41e00000000001976a914e27b5a80d961e0ee4144edc562e5848678f9cce288ac7a272300000000001976a9148584fe6d3b8a41ecd1840919ab98ecd9f16894a988ac80ee36000000000017a91426cc326ae6f496e421889c57494c98646108f5b18785733c000000000016001473a01568596519d3bc924756f647316ff7778a55dc253d000000000017a9142d079eed3636149a758b1acd5757910823a01d958720c155000000000017a9142c1ad0af56f340a9983d9080ec9f3480a05fd6db87ca495a00000000001600147039a4640d98d3dfbf65a8d81af3f9797ba59ca1e24a5a000000000016001422b426058b798231b98c0a172eea254ffa78fb7b9f225b000000000017a91492762e9dd8c6f3be6f8b3eae784f4ee7141b4a7587c09a5e000000000017a914291309107afddd6222eea5df261cdf7429d3fccb875ac45e0000000000160014c806df6b7cabf01fe787d38bbfc04978af3894cc20d960000000000016001417a33fe4469adeabbe117d412d27c1d948615e25af5167000000000017a914e334ea4816db2986069fc572d00ceb86780ebdcd875433690000000000160014bc19ad30eb139573e72daecbdfb5a43c299d8494cde977000000000017a914edf5455d5dfa60335a020e30390049a78049c07e87e0a57e000000000017a914efaffad14e8b8dc872b7a551deca4d394794414587c0e1e4000000000017a9146ae3f0b1e58d6cd3239d4a792d26e561d8e2c3e78780a812010000000017a914ee0fc83c7aaf46de3f3d04121165d3385adad3cf87c0ea21010000000017a914ce5698a58de1d3da19b6b279bb5db1ababe426fa8740d958010000000017a914268803d8241a0c8b76e7a69c500ad854176f176d87438a42020000000017a914b15c19c86d2b8d25042dbfa9c3415bda14ebfada874d0b74500000000017a914903b8360fdecd474f4625be5cfbc73d2ae2769aa8702473044022018ca4dc96716a910b54d4a78cff0c5a9c3aefe40c3a047128f1e045f163589af022004dfc91298efd47a9cfe5c33f81aba52d1604d0e7234a3f4e9c2baf48c5a8fde012103504252e45cc192c46f30776080f36f8e960d7683b5f43f0f68a0efeb10cda11700000000".*;
    const tx2 = try decodeRawTx(allocator, &raw2);
    defer tx2.deinit();
    try std.testing.expectEqual(false, tx2.isCoinbase());
}
