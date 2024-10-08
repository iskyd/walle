const std = @import("std");
const script = @import("script.zig");
const utils = @import("utils.zig");
const KeyPath = @import("bip44.zig").KeyPath;
const assert = @import("std").debug.assert;
const signEcdsa = @import("crypto").signEcdsa;
const db = @import("db/db.zig");
const sqlite = @import("sqlite");
const bip32 = @import("bip32.zig");
const SighashType = @import("const.zig").SighashType;

const coinbase_tx_id: [64]u8 = "0000000000000000000000000000000000000000000000000000000000000000".*;

const TxError = error{
    AmountTooLowError,
};

pub const Input = struct {
    txid: [64]u8,
    output_txid: [64]u8,
    output_vout: u32,
};

// Output represented by transaction hash and index n to its outputs
pub const Output = struct {
    txid: [64]u8,
    vout: u32,
    amount: u64,
    unspent: ?bool = null,
    keypath: ?KeyPath(5) = null,
};

// Input of a transaction
pub const TxInput = struct {
    allocator: std.mem.Allocator,
    prevout: ?Output, // nullable due to coinbase transaction
    scriptsig: []u8, // hex
    sequence: u32,

    // scriptsig in bytes
    pub fn init(allocator: std.mem.Allocator, prevout: ?Output, scriptsig: []u8, sequence: u32) !TxInput {
        const scriptsig_hex = try allocator.alloc(u8, scriptsig.len * 2);
        _ = try std.fmt.bufPrint(scriptsig_hex, "{x}", .{std.fmt.fmtSliceHexLower(scriptsig)});
        return TxInput{ .allocator = allocator, .prevout = prevout, .scriptsig = scriptsig_hex, .sequence = sequence };
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
        const script_pubkey_hex = try allocator.alloc(u8, script_pubkey.len * 2);
        _ = try std.fmt.bufPrint(script_pubkey_hex, "{x}", .{std.fmt.fmtSliceHexLower(script_pubkey)});
        return TxOutput{ .allocator = allocator, .amount = amount, .script_pubkey = script_pubkey_hex };
    }

    pub fn deinit(self: TxOutput) void {
        self.allocator.free(self.script_pubkey);
    }
};

pub const WitnessItem = struct {
    allocator: std.mem.Allocator,
    item: []const u8, // hex

    // item in bytes
    pub fn init(allocator: std.mem.Allocator, item: []const u8) !WitnessItem {
        const item_hex = try allocator.alloc(u8, item.len * 2);
        _ = try std.fmt.bufPrint(item_hex, "{x}", .{std.fmt.fmtSliceHexLower(item)});
        return WitnessItem{ .allocator = allocator, .item = item_hex };
    }

    pub fn deinit(self: WitnessItem) void {
        self.allocator.free(self.item);
    }
};

pub const TxWitness = struct {
    allocator: std.mem.Allocator,
    stack_items: std.ArrayList(WitnessItem),

    pub fn init(allocator: std.mem.Allocator) TxWitness {
        return TxWitness{ .allocator = allocator, .stack_items = std.ArrayList(WitnessItem).init(allocator) };
    }

    pub fn deinit(self: TxWitness) void {
        for (self.stack_items.items) |i| {
            i.deinit();
        }
        self.stack_items.deinit();
    }

    // Item in byte
    pub fn addItem(self: *TxWitness, item: []const u8) !void {
        const witness_item = try WitnessItem.init(self.allocator, item);
        try self.stack_items.append(witness_item);
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
        if (self.inputs.items.len == 1 and (self.inputs.items[0].prevout == null or (std.mem.eql(u8, &self.inputs.items[0].prevout.?.txid, &coinbase_tx_id) and self.inputs.items[0].prevout.?.vout == 4294967295))) {
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
        const total_bytes: usize = encodeTxCap(self, false);
        const encoded = try self.allocator.alloc(u8, total_bytes);
        defer self.allocator.free(encoded);
        try encodeTx(self.allocator, encoded, self, false);
        const txid = utils.doubleSha256(encoded);
        var txid_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txid_hex, "{x}", .{std.fmt.fmtSliceHexLower(&txid)});
        return txid_hex;
    }

    pub fn getWTXID(self: Transaction) ![64]u8 {
        const total_bytes: usize = encodeTxCap(self, true);
        const encoded = try self.allocator.alloc(u8, total_bytes);
        defer self.allocator.free(encoded);
        try encodeTx(self.allocator, encoded, self, true);
        const wtxid = utils.doubleSha256(encoded);
        var wtxid_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&wtxid_hex, "{x}", .{std.fmt.fmtSliceHexLower(&wtxid)});
        return wtxid_hex;
    }

    pub fn format(self: Transaction, actual_fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = actual_fmt;
        _ = options;

        try writer.print("version: {d}\n", .{self.version});
        try writer.print("marker: {?d}\n", .{self.marker});
        try writer.print("flag: {?d}\n", .{self.flag});
        try writer.print("locktime: {?d}\n", .{self.locktime});
        try writer.print("Inputs: \n", .{});
        for (0..self.inputs.items.len) |i| {
            const input = self.inputs.items[i];
            try writer.print("    txid: {s}\n", .{input.prevout.?.txid});
            try writer.print("    reverse txid: {s}\n", .{try utils.reverseByteOrderFromHex(64, input.prevout.?.txid)});
            try writer.print("    n: {d}\n", .{input.prevout.?.vout});
            try writer.print("    sequence: {d}\n\n", .{input.sequence});
        }
        try writer.print("Outputs: \n", .{});
        for (0..self.outputs.items.len) |i| {
            const output = self.outputs.items[i];
            try writer.print("    script pubkey: {s}\n", .{output.script_pubkey});
            try writer.print("    amount: {d}\n\n", .{output.amount});
        }

        if (self.witness.items.len > 0) {
            try writer.print("Witness: \n", .{});
            for (0..self.witness.items.len) |i| {
                const witness = self.witness.items[i];
                for (0..witness.stack_items.items.len) |j| {
                    const stack_item = witness.stack_items.items[j];
                    try writer.print("    item: {s}\n", .{stack_item.item});
                }
            }
        }
    }
};

fn getPrivateKeyForOutput(allocator: std.mem.Allocator, conn: *sqlite.Db, output: Output) ![32]u8 {
    assert(output.keypath != null);
    const keypath = try db.getOutputDescriptorPath(allocator, conn, output.txid, output.vout);
    const strkeypath = try keypath.toStr(allocator, 3);
    defer allocator.free(strkeypath);
    const descriptor = try db.getDescriptor(allocator, conn, strkeypath, true);
    if (descriptor == null) {
        return error.DescriptorNotFound;
    }
    const private = try bip32.ExtendedPrivateKey.fromAddress(descriptor.?.extended_key);
    const p2 = try bip32.deriveChildFromExtendedPrivateKey(private, keypath.path[3]);
    const p3 = try bip32.deriveChildFromExtendedPrivateKey(p2, keypath.path[4]);

    return p3.privatekey;
}

fn getPublicKeyForOutput(allocator: std.mem.Allocator, conn: *sqlite.Db, output: Output) !bip32.PublicKey {
    const keypath = try db.getOutputDescriptorPath(allocator, conn, output.txid, output.vout);
    const strkeypath = try keypath.toStr(allocator, 3);
    defer allocator.free(strkeypath);
    const descriptor = try db.getDescriptor(allocator, conn, strkeypath, false);
    if (descriptor == null) {
        return error.DescriptorNotFound;
    }
    const public = try bip32.ExtendedPublicKey.fromAddress(descriptor.?.extended_key);
    const p2 = try bip32.deriveChildFromExtendedPublicKey(public, keypath.path[3]);
    const p3 = try bip32.deriveChildFromExtendedPublicKey(p2, keypath.path[4]);

    return p3.key;
}

// Memory ownership to the caller
pub fn createTx(allocator: std.mem.Allocator, inputs: []TxInput, outputs: []TxOutput) !Transaction {
    for (inputs) |input| {
        assert(input.prevout != null);
    }

    var totalAmountInputs: u64 = 0;
    for (inputs) |input| {
        totalAmountInputs += input.prevout.?.amount;
    }

    var totalAmountOutputs: u64 = 0;
    for (outputs) |output| {
        totalAmountOutputs += output.amount;
    }

    if (totalAmountInputs < totalAmountOutputs) {
        return TxError.AmountTooLowError;
    }

    const locktime = 0;
    const marker = 0;
    const flag = 1;
    const version = 2;

    var tx = Transaction.init(allocator, version, locktime, marker, flag);
    for (inputs) |input| {
        // We do not sign this input because we're going to use segwit
        try tx.addInput(input);
    }
    for (outputs) |output| {
        try tx.addOutput(output);
    }

    return tx;
}

test "createTx" {
    const allocator = std.testing.allocator;
    const prevout = Output{ .txid = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a".*, .vout = 1, .amount = 30000 };
    const input = try TxInput.init(allocator, prevout, "", 4294967295);
    var inputs = [1]TxInput{input};
    const script_pubkey_hex = "76a914ce72abfd0e6d9354a660c18f2825eb392f060fdc88ac";

    var script_bytes: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&script_bytes, script_pubkey_hex);
    const output = try TxOutput.init(allocator, 20000, &script_bytes);
    var outputs = [1]TxOutput{output};

    const privkey_hex: [64]u8 = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f".*;
    var privkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&privkey, &privkey_hex);
    const pubkey = bip32.generatePublicKey(privkey);
    var pubkeys = std.AutoHashMap([72]u8, bip32.PublicKey).init(allocator);
    const key: [72]u8 = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a01000000".*;
    try pubkeys.put(key, pubkey);
    defer pubkeys.deinit();

    var tx = try createTx(allocator, &inputs, &outputs);
    defer tx.deinit();

    const expected_txid = "4ed74b96ff867d0469b3e56e64a2c2ccf0a95f4428e662977970fe9602bcf704";
    const txid = try tx.getTXID();
    try std.testing.expectEqualStrings(expected_txid, &txid);
}

// [72]u8 = 64 txid + 8 vout
pub fn signTx(allocator: std.mem.Allocator, tx: *Transaction, privkeys: std.AutoHashMap([72]u8, [32]u8), pubkeys: std.AutoHashMap([72]u8, bip32.PublicKey), comptime nonce: ?u256) !void {
    const inputs_preimage_hash = try getTxInputsPreImageHash(allocator, tx.inputs.items);
    const inputs_sequences_preimage_hash = try getTxInputsSequencesPreImageHash(allocator, tx.inputs.items);
    const outputs_preimage_hash = try getTxOutputsPreImageHash(allocator, tx.outputs.items);
    const sighash_type = SighashType.sighash_all;

    // Add witness, support only p2wpkh atm
    for (0..tx.inputs.items.len) |i| {
        const input = tx.inputs.items[i];
        var key: [72]u8 = undefined;
        var vout_hex: [8]u8 = undefined;
        try utils.intToHexStr(u32, @byteSwap(input.prevout.?.vout), &vout_hex);
        _ = try std.fmt.bufPrint(&key, "{s}{s}", .{ input.prevout.?.txid, vout_hex });
        const pubkey = pubkeys.get(key).?;
        const privkey = privkeys.get(key).?;
        const preimage_hash = try getPreImageHash(tx.version, inputs_preimage_hash, inputs_sequences_preimage_hash, outputs_preimage_hash, tx.locktime, input, pubkey, sighash_type);
        const witness = try createWitness(allocator, preimage_hash, privkey, pubkey, sighash_type, nonce);
        try tx.addWitness(witness);
    }
}

test "signTx" {
    const allocator = std.testing.allocator;
    const prevout = Output{ .txid = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a".*, .vout = 1, .amount = 30000 };
    const input = try TxInput.init(allocator, prevout, "", 4294967295);
    var inputs = [1]TxInput{input};
    const script_pubkey_hex = "76a914ce72abfd0e6d9354a660c18f2825eb392f060fdc88ac";

    var script_bytes: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&script_bytes, script_pubkey_hex);
    const output = try TxOutput.init(allocator, 20000, &script_bytes);
    var outputs = [1]TxOutput{output};

    const privkey_hex: [64]u8 = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f".*;
    var privkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&privkey, &privkey_hex);
    const pubkey = bip32.generatePublicKey(privkey);
    var pubkeys = std.AutoHashMap([72]u8, bip32.PublicKey).init(allocator);
    const map_key: [72]u8 = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a01000000".*;
    try pubkeys.put(map_key, pubkey);
    defer pubkeys.deinit();

    var tx = try createTx(allocator, &inputs, &outputs);
    defer tx.deinit();

    try signTx(allocator, &tx, privkey, pubkeys, 123456789);
    var tx_raw: [194]u8 = undefined;
    try encodeTx(allocator, &tx_raw, tx, true);
    const expected_tx_raw_hex = "02000000000101ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a0100000000ffffffff01204e0000000000001976a914ce72abfd0e6d9354a660c18f2825eb392f060fdc88ac02473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb022032b1374d1a0f125eae4f69d1bc0b7f896c964cfdba329f38a952426cf427484c012103eed0d937090cae6ffde917de8a80dc6156e30b13edd5e51e2e50d52428da1c8700000000";
    var expected_tx_raw: [194]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_tx_raw, expected_tx_raw_hex);
    const expected_item1 = "3044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb022032b1374d1a0f125eae4f69d1bc0b7f896c964cfdba329f38a952426cf427484c01";
    const expected_item2 = "03eed0d937090cae6ffde917de8a80dc6156e30b13edd5e51e2e50d52428da1c87";
    try std.testing.expectEqualStrings(expected_item1, tx.witness.items[0].stack_items.items[0].item);
    try std.testing.expectEqualStrings(expected_item2, tx.witness.items[0].stack_items.items[1].item);
    try std.testing.expectEqualSlices(u8, &expected_tx_raw, &tx_raw);
}

pub fn decodeRawTx(allocator: std.mem.Allocator, tx_raw: []const u8) !Transaction {
    var bytes: []u8 = try allocator.alloc(u8, tx_raw.len / 2);
    _ = try std.fmt.hexToBytes(bytes, tx_raw);
    defer allocator.free(bytes);
    const v = bytes[0..4]; // Little Endian
    const version = std.mem.readInt(u32, v, .little);
    std.debug.assert(version == 1 or version == 2);
    var current_byte: u64 = 4;
    // Marker and flag are used to indicate segwit tx. Can be null for version 1 tx
    // https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
    var marker: ?u8 = null;
    var flag: ?u8 = null;
    if (bytes[4] == 0 and bytes[5] == 1) { // match the pattern
        marker = bytes[4]; // used to indicate segwit tx. Must be 00
        flag = bytes[5]; // used to indicate segwit tx. Must be gte 01
        current_byte += 2;
    }

    const l = bytes[bytes.len - 4 ..][0..4].*;
    const locktime = std.mem.readInt(u32, &l, .little);

    var transaction = Transaction.init(allocator, version, locktime, marker, flag);

    // Compact Size
    // This byte indicates which bytes encode the integer representing the numbers of inputs.
    // <= FC then this byte, FD then the next two bytes, FE the next four bytes, FF the next eight bytes.
    // Compact Size Input
    const input_size = utils.decodeCompactSize(bytes[current_byte .. current_byte + 9]);
    current_byte += input_size.total_bytes;
    for (0..input_size.n) |_| {
        const txid = bytes[current_byte .. current_byte + 32];
        var txid_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txid_hex, "{x}", .{std.fmt.fmtSliceHexLower(txid)});
        current_byte += 32;
        const vout_bytes: [4]u8 = bytes[current_byte .. current_byte + 4][0..4].*;
        const vout = std.mem.readInt(u32, &vout_bytes, .little);
        const prevout = Output{ .txid = txid_hex, .vout = vout, .amount = 0 };
        current_byte += 4;
        const scriptsig_size = bytes[current_byte];
        current_byte += 1;
        const scriptsig = bytes[current_byte .. current_byte + scriptsig_size];
        current_byte += scriptsig_size;
        const s = bytes[current_byte .. current_byte + 4][0..4].*;
        const sequence = std.mem.readInt(u32, &s, .little);
        current_byte += 4;

        const input = try TxInput.init(allocator, prevout, scriptsig, sequence);
        try transaction.addInput(input);
    }

    // Compat size output
    const output_size_end = if (current_byte + 9 >= bytes.len) bytes.len - 1 else current_byte + 9;
    const output_size = utils.decodeCompactSize(bytes[current_byte..output_size_end]);
    current_byte += output_size.total_bytes;
    for (0..output_size.n) |_| {
        const a = bytes[current_byte .. current_byte + 8][0..8].*;
        current_byte += 8;
        const amount = std.mem.readInt(u64, &a, .little);
        const script_pubkey_size = bytes[current_byte];
        current_byte += 1;
        const script_pubkey = bytes[current_byte .. current_byte + script_pubkey_size];
        current_byte += script_pubkey_size;
        const output = try TxOutput.init(allocator, amount, script_pubkey);
        try transaction.addOutput(output);
    }

    if (marker != null and marker.? == 0 and flag != null and flag != 0) { // it's segwit
        // 1 witness for every input
        for (0..input_size.n) |_| {
            // Compat size, same as ic and oc
            var witness = TxWitness.init(allocator);
            // compact size stack items
            const stack_items_size_end = if (current_byte + 9 >= bytes.len) bytes.len - 1 else current_byte + 9;
            const stack_items_size = utils.decodeCompactSize(bytes[current_byte..stack_items_size_end]);
            current_byte += stack_items_size.total_bytes;
            for (0..stack_items_size.n) |_| {
                // compact size item
                const item_size_end = if (current_byte + 9 >= bytes.len) bytes.len - 1 else current_byte + 9;
                const item_size = utils.decodeCompactSize(bytes[current_byte..item_size_end]);
                current_byte += item_size.total_bytes;
                if (item_size.n == 0) {
                    try witness.addItem("");
                } else {
                    const item = bytes[current_byte .. current_byte + item_size.n];
                    current_byte += item_size.n;
                    try witness.addItem(item);
                }
            }
            try transaction.addWitness(witness);
        }
    }

    return transaction;
}

pub fn encodeTx(allocator: std.mem.Allocator, buffer: []u8, tx: Transaction, include_witness: bool) !void {
    @memcpy(buffer[0..4], std.mem.asBytes(&tx.version));
    var current_byte: u64 = 4;
    if (include_witness == true and tx.marker != null and tx.flag != null) {
        std.debug.assert(tx.marker != null and tx.flag != null); // Marker and flag are required for tx version 2 as describe in bip144
        buffer[4] = std.mem.asBytes(&tx.marker.?)[0];
        buffer[5] = std.mem.asBytes(&tx.flag.?)[0];
        current_byte += 2;
    }

    // Encoded compact size input
    const input_size = utils.encodeCompactSize(tx.inputs.items.len);
    buffer[current_byte] = input_size.compact_size_byte;
    current_byte += 1;
    if (input_size.total_bytes > 0) {
        @memcpy(buffer[current_byte .. current_byte + input_size.total_bytes], std.mem.asBytes(&input_size.n));
        current_byte += input_size.total_bytes;
    }
    for (0..tx.inputs.items.len) |i| {
        const input = tx.inputs.items[i];
        var input_prevout_txid_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&input_prevout_txid_bytes, &input.prevout.?.txid);
        @memcpy(buffer[current_byte .. current_byte + 32], &input_prevout_txid_bytes);
        current_byte += 32;
        @memcpy(buffer[current_byte .. current_byte + 4], std.mem.asBytes(&input.prevout.?.vout));
        current_byte += 4;
        // encoded compact size script
        const script_size = utils.encodeCompactSize(input.scriptsig.len / 2);
        buffer[current_byte] = script_size.compact_size_byte;
        current_byte += 1;
        if (script_size.total_bytes > 0) {
            @memcpy(buffer[current_byte .. current_byte + script_size.total_bytes], std.mem.asBytes(&script_size.n));
            current_byte += script_size.total_bytes;
        }
        const scriptsig_bytes = try allocator.alloc(u8, input.scriptsig.len / 2);
        defer allocator.free(scriptsig_bytes);
        _ = try std.fmt.hexToBytes(scriptsig_bytes, input.scriptsig);
        @memcpy(buffer[current_byte .. current_byte + input.scriptsig.len / 2], scriptsig_bytes);
        current_byte += input.scriptsig.len / 2;
        @memcpy(buffer[current_byte .. current_byte + 4], std.mem.asBytes(&input.sequence));
        current_byte += 4;
    }

    // encoded compact size output
    const output_size = utils.encodeCompactSize(tx.outputs.items.len);
    buffer[current_byte] = output_size.compact_size_byte;
    current_byte += 1;
    if (output_size.total_bytes > 0) {
        @memcpy(buffer[current_byte .. current_byte + output_size.total_bytes], std.mem.asBytes(&output_size.n));
        current_byte += output_size.total_bytes;
    }
    for (0..tx.outputs.items.len) |i| {
        const output = tx.outputs.items[i];
        @memcpy(buffer[current_byte .. current_byte + 8], std.mem.asBytes(&output.amount));
        current_byte += 8;
        // encoded compact size script pubkey
        const script_pubkey_size = utils.encodeCompactSize(output.script_pubkey.len / 2); // script_pubkey is in hex format, /2 for bytes representation
        buffer[current_byte] = script_pubkey_size.compact_size_byte;
        current_byte += 1;
        if (script_pubkey_size.total_bytes > 0) {
            @memcpy(buffer[current_byte .. current_byte + script_pubkey_size.total_bytes], std.mem.asBytes(&script_pubkey_size.n));
            current_byte += script_pubkey_size.total_bytes;
        }
        const bytes: []u8 = try allocator.alloc(u8, output.script_pubkey.len / 2);
        defer allocator.free(bytes);
        _ = try std.fmt.hexToBytes(bytes, output.script_pubkey);
        @memcpy(buffer[current_byte .. current_byte + output.script_pubkey.len / 2], bytes);
        current_byte += output.script_pubkey.len / 2;
    }

    if (include_witness == true) {
        // 1 witness for every input
        for (0..tx.inputs.items.len) |i| {
            const witness = tx.witness.items[i];
            // encoded compact size stack
            const witness_stack_size = utils.encodeCompactSize(witness.stack_items.items.len);
            buffer[current_byte] = witness_stack_size.compact_size_byte;
            current_byte += 1;
            if (witness_stack_size.total_bytes > 0) {
                @memcpy(buffer[current_byte .. current_byte + witness_stack_size.total_bytes], std.mem.asBytes(&witness_stack_size.n));
                current_byte += witness_stack_size.total_bytes;
            }
            for (0..witness.stack_items.items.len) |j| {
                const stack_item = witness.stack_items.items[j];
                const stack_item_size = utils.encodeCompactSize(stack_item.item.len / 2);
                buffer[current_byte] = stack_item_size.compact_size_byte;
                current_byte += 1;
                if (stack_item_size.total_bytes > 0) {
                    @memcpy(buffer[current_byte .. current_byte + stack_item_size.total_bytes], std.mem.asBytes(&stack_item_size.n));
                    current_byte += stack_item_size.total_bytes;
                }
                const stack_item_bytes = try allocator.alloc(u8, stack_item.item.len / 2);
                defer allocator.free(stack_item_bytes);
                _ = try std.fmt.hexToBytes(stack_item_bytes, stack_item.item);
                @memcpy(buffer[current_byte .. current_byte + stack_item.item.len / 2], stack_item_bytes);
                current_byte += stack_item.item.len / 2;
            }
        }
    }
    @memcpy(buffer[current_byte .. current_byte + 4], std.mem.asBytes(&tx.locktime));
}

pub fn encodeTxCap(tx: Transaction, include_witness: bool) usize {
    var current_byte: usize = 4; // version
    if (include_witness == true) {
        current_byte += 2; // marker + flag
    }

    // Encoded compact size input
    const input_size = utils.encodeCompactSize(tx.inputs.items.len);
    current_byte += 1;
    if (input_size.total_bytes > 0) {
        current_byte += input_size.total_bytes;
    }
    for (0..tx.inputs.items.len) |i| {
        const input = tx.inputs.items[i];
        current_byte += 32; // input prevout txid
        current_byte += 4; // input prevout n
        // encoded compact size script
        const script_size = utils.encodeCompactSize(input.scriptsig.len / 2);
        current_byte += 1;
        if (script_size.total_bytes > 0) {
            current_byte += input.scriptsig.len / 2;
        }
        current_byte += input.scriptsig.len / 2;
        current_byte += 4; // sequence
    }

    // encoded compact size output
    const output_size = utils.encodeCompactSize(tx.outputs.items.len);
    current_byte += 1; // outputsize
    if (output_size.total_bytes > 0) {
        current_byte += output_size.total_bytes;
    }
    for (0..tx.outputs.items.len) |i| {
        const output = tx.outputs.items[i];
        current_byte += 8; // output amount
        // encoded compact size script pubkey
        const script_pubkey_size = utils.encodeCompactSize(output.script_pubkey.len / 2); // script_pubkey is in hex format, /2 for bytes representation
        current_byte += 1;
        if (script_pubkey_size.total_bytes > 0) {
            current_byte += script_pubkey_size.total_bytes;
        }
        current_byte += output.script_pubkey.len / 2; // script pubkey
    }

    if (include_witness == true) {
        // 1 witness for every input
        for (0..tx.inputs.items.len) |i| {
            const witness = tx.witness.items[i];
            // encoded compact size stack
            const witness_stack_size = utils.encodeCompactSize(witness.stack_items.items.len);
            current_byte += 1;
            if (witness_stack_size.total_bytes > 0) {
                current_byte += witness_stack_size.total_bytes;
            }
            for (0..witness.stack_items.items.len) |j| {
                const stack_item = witness.stack_items.items[j];
                const stack_item_size = utils.encodeCompactSize(stack_item.item.len / 2);
                current_byte += 1;
                if (stack_item_size.total_bytes > 0) {
                    current_byte += stack_item_size.total_bytes;
                }
                current_byte += stack_item.item.len / 2; // stackitem
            }
        }
    }
    return current_byte + 4; //locktime
}

fn getTxInputsPreImageHash(allocator: std.mem.Allocator, inputs: []TxInput) ![32]u8 {
    const inputs_concat = try allocator.alloc(u8, inputs.len * 72); // 72 = 64 (tx id) + 8 (vout)
    defer allocator.free(inputs_concat);
    for (inputs, 0..) |input, i| {
        var vout_hex: [8]u8 = undefined;
        try utils.intToHexStr(u32, @byteSwap(input.prevout.?.vout), &vout_hex);
        @memcpy(inputs_concat[i * 72 .. i * 72 + 64], &input.prevout.?.txid);
        @memcpy(inputs_concat[i * 72 + 64 .. i * 72 + 72], &vout_hex);
    }
    const bytes: []u8 = try allocator.alloc(u8, inputs_concat.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, inputs_concat);
    return utils.doubleSha256(bytes);
}

test "getTxInputPreImageHash" {
    const allocator = std.testing.allocator;
    const prevout = Output{ .txid = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a".*, .vout = 1, .amount = 100 };
    const input = try TxInput.init(allocator, prevout, "", 4294967295);
    defer input.deinit();
    var inputs = [1]TxInput{input};
    const hash = try getTxInputsPreImageHash(allocator, &inputs);
    const expected = "cbfaca386d65ea7043aaac40302325d0dc7391a73b585571e28d3287d6b16203".*;
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, &expected);
    try std.testing.expectEqualStrings(&expected_bytes, &hash);
}

fn getTxInputsSequencesPreImageHash(allocator: std.mem.Allocator, inputs: []TxInput) ![32]u8 {
    const sequences_concat = try allocator.alloc(u8, inputs.len * 8); // 8 = characters to represent u32 in hex
    defer allocator.free(sequences_concat);
    for (inputs, 0..) |input, i| {
        var sequence_hex: [8]u8 = undefined;
        try utils.intToHexStr(u32, input.sequence, &sequence_hex);
        @memcpy(sequences_concat[i * 8 .. i * 8 + 8], &sequence_hex);
    }
    const bytes: []u8 = try allocator.alloc(u8, sequences_concat.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, sequences_concat);
    return utils.doubleSha256(bytes);
}

test "getTxInputSequencesPreImageHash" {
    const allocator = std.testing.allocator;
    const prevout = Output{ .txid = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a".*, .vout = 1, .amount = 20000 };
    const input = try TxInput.init(allocator, prevout, "", 4294967295);
    defer input.deinit();
    var inputs = [1]TxInput{input};
    const hash = try getTxInputsSequencesPreImageHash(allocator, &inputs);
    const expected = "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044".*;
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, &expected);
    try std.testing.expectEqualStrings(&expected_bytes, &hash);

    const input2 = try TxInput.init(allocator, prevout, "", 4294967295);
    defer input2.deinit();
    var inputs2 = [2]TxInput{ input, input2 };
    const hash2 = try getTxInputsSequencesPreImageHash(allocator, &inputs2);
    const expected2 = "752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad".*;
    var expected_bytes2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes2, &expected2);
    try std.testing.expectEqualStrings(&expected_bytes2, &hash2);
}

fn getTxOutputsPreImageHash(allocator: std.mem.Allocator, outputs: []TxOutput) ![32]u8 {
    var cap: usize = 0;
    for (outputs) |output| {
        cap += 16; // amount
        cap += 2; // scriptpubkeysize
        cap += output.script_pubkey.len;
    }
    const outputconcat = try allocator.alloc(u8, cap);
    defer allocator.free(outputconcat);
    var current: usize = 0;
    for (outputs) |output| {
        var amounthex: [16]u8 = undefined;
        try utils.intToHexStr(u64, @byteSwap(output.amount), &amounthex);
        @memcpy(outputconcat[current .. current + 16], &amounthex);
        current += 16;
        const script_size: u8 = @intCast(output.script_pubkey.len / 2);
        var script_size_hex: [2]u8 = undefined;
        try utils.intToHexStr(u8, script_size, &script_size_hex);
        @memcpy(outputconcat[current .. current + 2], &script_size_hex);
        current += 2;
        @memcpy(outputconcat[current .. current + output.script_pubkey.len], output.script_pubkey);
        current += output.script_pubkey.len;
    }
    const bytes: []u8 = try allocator.alloc(u8, outputconcat.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, outputconcat);
    return utils.doubleSha256(bytes);
}

test "getTxOutputsPreImageHash" {
    const allocator = std.testing.allocator;
    const scriptubkeyhex = "76a914ce72abfd0e6d9354a660c18f2825eb392f060fdc88ac";
    var scriptBytes: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scriptBytes, scriptubkeyhex);
    const output = try TxOutput.init(allocator, 20000, &scriptBytes);
    defer output.deinit();
    var outputs = [1]TxOutput{output};
    const hash = try getTxOutputsPreImageHash(allocator, &outputs);
    const expected = "900a6c6ff6cd938bf863e50613a4ed5fb1661b78649fe354116edaf5d4abb952".*;
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, &expected);
    try std.testing.expectEqualStrings(&expected_bytes, &hash);
}

// get the pre image for the current input
pub fn getPreImageHash(version: u32, inputs_preimage_hash: [32]u8, inputs_sequences_preimage_hash: [32]u8, outputs_preimage_hash: [32]u8, locktime: u32, input: TxInput, pubkey: bip32.PublicKey, sighash_type: SighashType) ![32]u8 {
    assert(input.prevout != null);
    var vout_hex: [8]u8 = undefined;
    try utils.intToHexStr(u32, @byteSwap(input.prevout.?.vout), &vout_hex);
    var input_serialization: [72]u8 = undefined;
    @memcpy(input_serialization[0..64], &input.prevout.?.txid);
    @memcpy(input_serialization[64..72], &vout_hex);

    var script_code_hex: [52]u8 = undefined; // scriptcode is 1976a914{publickeyhash}88ac
    const pubkey_hash = try pubkey.toHashHex();
    _ = try std.fmt.bufPrint(&script_code_hex, "1976a914{s}88ac", .{pubkey_hash});

    var amount_hex: [16]u8 = undefined;
    try utils.intToHexStr(u64, @byteSwap(input.prevout.?.amount), &amount_hex);

    var version_hex: [8]u8 = undefined;
    try utils.intToHexStr(u32, @byteSwap(version), &version_hex);

    var sequence_hex: [8]u8 = undefined;
    try utils.intToHexStr(u32, @byteSwap(input.sequence), &sequence_hex);

    var locktime_hex: [8]u8 = undefined;
    try utils.intToHexStr(u32, @byteSwap(locktime), &locktime_hex);

    var sighash_type_hex: [8]u8 = undefined;
    try utils.intToHexStr(u32, @byteSwap(@as(u32, @intFromEnum(sighash_type))), &sighash_type_hex);

    var preimage: [364]u8 = undefined;
    _ = try std.fmt.bufPrint(&preimage, "{s}{x}{x}{s}{s}{s}{s}{x}{s}{s}", .{ version_hex, std.fmt.fmtSliceHexLower(&inputs_preimage_hash), std.fmt.fmtSliceHexLower(&inputs_sequences_preimage_hash), input_serialization, script_code_hex, amount_hex, sequence_hex, std.fmt.fmtSliceHexLower(&outputs_preimage_hash), locktime_hex, sighash_type_hex });

    var bytes: [182]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &preimage);

    return utils.doubleSha256(&bytes);
}

test "getPreImageHash" {
    const allocator = std.testing.allocator;
    const version: u32 = 2;
    const locktime: u32 = 0;
    const sighash_type = SighashType.sighash_all;
    const inputs_preimage_hash_hex = "cbfaca386d65ea7043aaac40302325d0dc7391a73b585571e28d3287d6b16203";
    var inputs_preimage_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&inputs_preimage_hash, inputs_preimage_hash_hex);
    const inputs_sequences_preimage_hash_hex = "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044";
    var inputs_sequences_preimage_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&inputs_sequences_preimage_hash, inputs_sequences_preimage_hash_hex);
    const outputs_preimage_hash_hex = "900a6c6ff6cd938bf863e50613a4ed5fb1661b78649fe354116edaf5d4abb952";
    var outputs_preimage_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&outputs_preimage_hash, outputs_preimage_hash_hex);

    const prevout = Output{ .txid = "ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a".*, .vout = 1, .amount = 30000 };
    const input = try TxInput.init(allocator, prevout, "", 4294967295);
    const privkey_hex: [64]u8 = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f".*;
    var privkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&privkey, &privkey_hex);
    const pubkey = bip32.generatePublicKey(privkey);
    const expected = "d7b60220e1b9b2c1ab40845118baf515203f7b6f0ad83cbb68d3c89b5b3098a6";
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, expected);
    const hash = try getPreImageHash(version, inputs_preimage_hash, inputs_sequences_preimage_hash, outputs_preimage_hash, locktime, input, pubkey, sighash_type);
    try std.testing.expectEqualSlices(u8, &expected_bytes, &hash);
}

pub fn createWitness(allocator: std.mem.Allocator, preimage_hash: [32]u8, privkey: [32]u8, pubkey: bip32.PublicKey, sighash_type: SighashType, comptime nonce: ?u256) !TxWitness {
    const signature = signEcdsa(privkey, preimage_hash, nonce);
    const partial_serialized = try signature.derEncode(allocator);
    defer allocator.free(partial_serialized);
    var sighash_type_hex: [2]u8 = undefined;
    try utils.intToHexStr(u8, @byteSwap(@as(u8, @intFromEnum(sighash_type))), &sighash_type_hex);
    const serialized = try allocator.alloc(u8, partial_serialized.len + 2);
    defer allocator.free(serialized);
    _ = try std.fmt.bufPrint(serialized, "{s}{s}", .{ partial_serialized, sighash_type_hex });
    const bytes = try allocator.alloc(u8, serialized.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, serialized);
    const pubkey_compressed = try pubkey.compress();
    var witness = TxWitness.init(allocator);
    try witness.addItem(bytes);
    try witness.addItem(&pubkey_compressed);

    return witness;
}

test "createWitness" {
    const allocator = std.testing.allocator;
    const preimage_hash_hex = "d7b60220e1b9b2c1ab40845118baf515203f7b6f0ad83cbb68d3c89b5b3098a6";
    var preimage_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&preimage_hash, preimage_hash_hex);
    const privkey_hex: [64]u8 = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f".*;
    var privkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&privkey, &privkey_hex);
    const pubkey = bip32.generatePublicKey(privkey);

    const witness = try createWitness(allocator, preimage_hash, privkey, pubkey, SighashType.sighash_all, 123456789);
    defer witness.deinit();

    const expected_signature_hex = "3044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb022032b1374d1a0f125eae4f69d1bc0b7f896c964cfdba329f38a952426cf427484c01";
    const expected_pubkey = "03eed0d937090cae6ffde917de8a80dc6156e30b13edd5e51e2e50d52428da1c87";

    try std.testing.expectEqual(witness.stack_items.items.len, 2);
    try std.testing.expectEqualStrings(expected_signature_hex, witness.stack_items.items[0].item);
    try std.testing.expectEqualStrings(expected_pubkey, witness.stack_items.items[1].item);
}

test "getOutputValue" {
    const allocator = std.testing.allocator;
    const o = Output{ .txid = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .vout = 0, .amount = 0 };
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
    try std.testing.expectEqual(tx.inputs.items[0].prevout.?.vout, 4294967295);
    var expected_prevout_txid = "0000000000000000000000000000000000000000000000000000000000000000".*;
    try std.testing.expectEqualStrings(&expected_prevout_txid, &tx.inputs.items[0].prevout.?.txid);
    var expected_scriptsig = "5100".*;
    try std.testing.expectEqualStrings(&expected_scriptsig, tx.inputs.items[0].scriptsig);
    try std.testing.expectEqual(tx.outputs.items.len, 2);
    try std.testing.expectEqual(tx.outputs.items[0].amount, 5000000000);
    var expected_pubkey_script1 = "0014dd3d4b7d821d44331e31a818d15f583302e8e1c0".*;
    try std.testing.expectEqualStrings(&expected_pubkey_script1, tx.outputs.items[0].script_pubkey);
    try std.testing.expectEqual(tx.outputs.items[1].amount, 0);
    var expected_pubkey_script2 = "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9".*;
    try std.testing.expectEqualStrings(&expected_pubkey_script2, tx.outputs.items[1].script_pubkey);
    try std.testing.expectEqual(tx.witness.items.len, 1);
    var expected_witness = "0000000000000000000000000000000000000000000000000000000000000000".*;
    try std.testing.expectEqualStrings(&expected_witness, tx.witness.items[0].stack_items.items[0].item);
}

test "decodeRawTxSimple" {
    const allocator = std.testing.allocator;
    var tx_raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    try std.testing.expectEqual(tx.version, 2);
    try std.testing.expectEqual(tx.marker, 0);
    try std.testing.expectEqual(tx.flag, 1);
    try std.testing.expectEqual(tx.locktime, 200);
    try std.testing.expectEqual(tx.inputs.items.len, 3);
    try std.testing.expectEqual(tx.outputs.items.len, 2);
    try std.testing.expectEqual(tx.witness.items.len, 3);

    const expected_tx_input1 = "c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec32748673".*;
    try std.testing.expectEqualStrings(&expected_tx_input1, &tx.inputs.items[0].prevout.?.txid);

    const expected_tx_input2 = "daf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef33".*;
    try std.testing.expectEqualStrings(&expected_tx_input2, &tx.inputs.items[1].prevout.?.txid);

    const expected_tx_input3 = "01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b0".*;
    try std.testing.expectEqualStrings(&expected_tx_input3, &tx.inputs.items[2].prevout.?.txid);

    try std.testing.expectEqual(tx.outputs.items[0].amount, 10000000000);
    const expected_pubkey1 = "00147218978afd7fd9270bae7595399b6bc1986e7a4e".*;
    try std.testing.expectEqualStrings(&expected_pubkey1, tx.outputs.items[0].script_pubkey);

    try std.testing.expectEqual(tx.outputs.items[1].amount, 4999999724);
    const expected_pubkey2 = "0014009724e4053330c337bb803eca10071462821246".*;
    try std.testing.expectEqualStrings(&expected_pubkey2, tx.outputs.items[1].script_pubkey);

    const expected_witness1_item1 = "3044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e288701".*;
    const expected_witness1_item2 = "029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4".*;
    try std.testing.expectEqualStrings(&expected_witness1_item1, tx.witness.items[0].stack_items.items[0].item);
    try std.testing.expectEqualStrings(&expected_witness1_item2, tx.witness.items[0].stack_items.items[1].item);

    const expected_witness2_item1 = "30440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b01".*;
    const expected_witness2_item2 = "029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4".*;
    try std.testing.expectEqualStrings(&expected_witness2_item1, tx.witness.items[1].stack_items.items[0].item);
    try std.testing.expectEqualStrings(&expected_witness2_item2, tx.witness.items[1].stack_items.items[1].item);

    const expected_witness3_item1 = "304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a861101".*;
    const expected_witness3_item2 = "029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4".*;
    try std.testing.expectEqualStrings(&expected_witness3_item1, tx.witness.items[2].stack_items.items[0].item);
    try std.testing.expectEqualStrings(&expected_witness3_item2, tx.witness.items[2].stack_items.items[1].item);
}

test "decodeRawTxEmptyWitnessItem" {
    const allocator = std.testing.allocator;
    const tx_raw = "010000000001037790b18693b2c4b6344577dc8d973e51388670a2b60ef1156b69f141f66b837e0400000000fdffffff4429cda513e5258a16f5be9fe6bf9d8f18aa7d8ca6e5147b10961955db88ac740100000000fdffffff396b7f0fcac84f700b471fc72874f56795433b7cb7657fe3ff9e9d0e573960a70100000000fdffffff0206a50a00000000001976a9149e6b8bfbbf4cc975fdcbfddbd06c70925d4c8f9f88ac4bfc02000000000017a91485ec27a75202121fe50d284a1798d66b097e033d8702000002000002000000000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();

    try std.testing.expectEqual(tx.version, 1);
    try std.testing.expectEqual(tx.marker, 0);
    try std.testing.expectEqual(tx.flag, 1);
    try std.testing.expectEqual(tx.locktime, 0);
    try std.testing.expectEqual(tx.inputs.items.len, 3);
    try std.testing.expectEqual(tx.outputs.items.len, 2);
    try std.testing.expectEqual(tx.witness.items.len, 3);

    const expected_tx_input1 = "7790b18693b2c4b6344577dc8d973e51388670a2b60ef1156b69f141f66b837e".*;
    try std.testing.expectEqualStrings(&expected_tx_input1, &tx.inputs.items[0].prevout.?.txid);
    try std.testing.expectEqual(tx.inputs.items[0].prevout.?.vout, 4);

    const expected_tx_input2 = "4429cda513e5258a16f5be9fe6bf9d8f18aa7d8ca6e5147b10961955db88ac74".*;
    try std.testing.expectEqualStrings(&expected_tx_input2, &tx.inputs.items[1].prevout.?.txid);
    try std.testing.expectEqual(tx.inputs.items[1].prevout.?.vout, 1);

    const expected_tx_input3 = "396b7f0fcac84f700b471fc72874f56795433b7cb7657fe3ff9e9d0e573960a7".*;
    try std.testing.expectEqualStrings(&expected_tx_input3, &tx.inputs.items[2].prevout.?.txid);
    try std.testing.expectEqual(tx.inputs.items[2].prevout.?.vout, 1);

    try std.testing.expectEqual(tx.outputs.items[0].amount, 697606);
    const expected_script_pubkey1 = "76a9149e6b8bfbbf4cc975fdcbfddbd06c70925d4c8f9f88ac".*;
    try std.testing.expectEqualStrings(&expected_script_pubkey1, tx.outputs.items[0].script_pubkey);

    try std.testing.expectEqual(tx.outputs.items[1].amount, 195659);
    const expected_script_pubkey2 = "a91485ec27a75202121fe50d284a1798d66b097e033d87".*;
    try std.testing.expectEqualStrings(&expected_script_pubkey2, tx.outputs.items[1].script_pubkey);

    try std.testing.expectEqualStrings("", tx.witness.items[0].stack_items.items[0].item);
    try std.testing.expectEqualStrings("", tx.witness.items[0].stack_items.items[1].item);

    try std.testing.expectEqualStrings("", tx.witness.items[1].stack_items.items[0].item);
    try std.testing.expectEqualStrings("", tx.witness.items[1].stack_items.items[1].item);

    try std.testing.expectEqualStrings("", tx.witness.items[2].stack_items.items[0].item);
    try std.testing.expectEqualStrings("", tx.witness.items[2].stack_items.items[1].item);
}

test "encodeTx" {
    const allocator = std.testing.allocator;
    var tx_raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    var buffer: [518]u8 = undefined;
    try encodeTx(allocator, &buffer, tx, true);
    var encoded_hex: [1036]u8 = undefined;
    _ = try std.fmt.bufPrint(&encoded_hex, "{x}", .{std.fmt.fmtSliceHexLower(&buffer)});
    try std.testing.expectEqualStrings(&tx_raw, &encoded_hex);

    var tx_raw2: [816]u8 = "02000000000101977c82700772e8bf232d744f52f6c408dbdc2b655958641d8b89c1cfe23ee104010000002322002092ca8217ed15abd6f85e3c056f928d0c457ca78d76f32ec2b638b3bd408efdc3ffffffff0248570400000000001976a9141cbb9f8e59b3082d961c5e81f092f52b3dd9c9de88ac300601000000000017a9140ea9c688d853fb95c49bc8bec527fdf0ce28c015870400483045022100a2d70e48f0009802efbb9c49e4fc4dc3111021469141038ee4509d84183d0f0602204d2066912ea4f0abba6abf554344987dcdc21f37ff68e04a9196540a69a85aba01483045022100eeda4a1e0dc0ff6a1a5bfa3e4ebb51a9fd97e0f306e94b6a742a0cdee080c0f10220309ac61cc79db7f5611157a7c2f005cc2645602324172b05a43af7e87848bbd10169522102f1367627a1d391db3561cd0092e799f101b408179b1751f946c51cce7c3cea55210249b1137d2a8584717acdf591c03eb2a39557d45ce6757481c37c7358b05c8dba21037cd0ba9adc6c3019f886d26f3d73cdcfc5cf7b3c35fc6ae8b2bebcc6ec7542b653ae00000000".*;

    const tx2 = try decodeRawTx(allocator, &tx_raw2);
    defer tx2.deinit();
    var buffer2: [408]u8 = undefined;
    try encodeTx(allocator, &buffer2, tx2, true);
    var encoded_hex2: [816]u8 = undefined;
    _ = try std.fmt.bufPrint(&encoded_hex2, "{x}", .{std.fmt.fmtSliceHexLower(&buffer2)});
    try std.testing.expectEqualStrings(&tx_raw2, &encoded_hex2);
}

test "txid" {
    const expected_txid = "f455759f8e184926b7b6a2af4f33fb026da94920a850b3091e1654b9236d33e8".*;
    const allocator = std.testing.allocator;
    var tx_raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    const txid = try tx.getTXID();
    try std.testing.expectEqualStrings(&expected_txid, &txid);
}

test "decodeTxCoinbase" {
    const expected_txid = "5afb3d180b56a65f3ac5c29633e941007a8ad4cc19164eafd626457f2174c46e".*;
    const allocator = std.testing.allocator;
    const tx_raw = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600141065b3dd70fa8d3f9a16a070e7d68d8ea39beb880000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000".*;
    const tx = try decodeRawTx(allocator, @constCast(&tx_raw));
    defer tx.deinit();
    const txid = try tx.getTXID();
    try std.testing.expectEqualStrings(&expected_txid, &txid);
}

test "decodeTxVersion1Genesis" {
    const allocator = std.testing.allocator;
    const expected_txid = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a".*;
    const tx_raw = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000".*;
    const tx = try decodeRawTx(allocator, @constCast(&tx_raw));
    defer tx.deinit();
    const txid = try tx.getTXID();
    try std.testing.expectEqualStrings(&expected_txid, &txid);
}

test "wtxid" {
    const expected_txid = "4d95fff811ffdaefcf9add9217d76f123cdc227581fed44de7c43d75a2aa6ac0".*;
    const expected_wtxid = "ff63ed0cc02c85a7aef6510625b6897abe1b969293f5db2991804e23f2562df1".*;
    const allocator = std.testing.allocator;
    var tx_raw: [450]u8 = "01000000000101438afdb24e414d54cc4a17a95f3d40be90d23dfeeb07a48e9e782178efddd8890100000000fdffffff020db9a60000000000160014b549d227c9edd758288112fe3573c1f85240166880a81201000000001976a914ae28f233464e6da03c052155119a413d13f3380188ac024730440220200254b765f25126334b8de16ee4badf57315c047243942340c16cffd9b11196022074a9476633f093f229456ad904a9d97e26c271fc4f01d0501dec008e4aae71c2012102c37a3c5b21a5991d3d7b1e203be195be07104a1a19e5c2ed82329a56b431213000000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    const txid = try tx.getTXID();
    const wtxid = try tx.getWTXID();
    try std.testing.expectEqualStrings(&expected_txid, &txid);
    try std.testing.expectEqualStrings(&expected_wtxid, &wtxid);
}

test "encodeTxCap" {
    const allocator = std.testing.allocator;
    var tx_raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    try std.testing.expectEqual(encodeTxCap(tx, true), 518);
}

test "encodeTxCapTxID" {
    const allocator = std.testing.allocator;
    var tx_raw: [1036]u8 = "02000000000103c0483c7c93aaefd5ee008cbec6f114d45d7502ffd8c427e9aac13eec327486730000000000fdffffffdaf971319fa0477b53ea4890c647c755c9a0021265f9fc3661ef0c4b7db6ef330000000000fdffffff01bb0ca2b5819c7b6a173cd36b8807d0809cc8bd3f9d5189a354e51b9f9337b00000000000fdffffff0200e40b54020000001600147218978afd7fd9270bae7595399b6bc1986e7a4eecf0052a01000000160014009724e4053330c337bb803eca1007146282124602473044022034141a0bc3da3adfa9162a8ab8f64eed52c94e7cdbc1aa49b0c1bf699c807b2c022015ff3eed0047ab1a202edd89d49cc9a144abeb20a89ff594b7fc50ca723e28870121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4024730440220571285fdbac00b8828883744503ae30bf846fdab3fa197f843f74ec8b6c8627602206a9aa3a646f5a67f62c04f8a181a63f5d4db37ae4e69af5e7f6912b60170bd9b0121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a40247304402206d542feca659eed9a470867e1d820b372f434d2a72688143fe68c4c66671a5e50220782b0bd5884d220a537bf86b438cd40eee0a58d08151eb1757e33286658a86110121029e9c928d39269fb6adf718c34e1754983a4d939ea7012f8fbbe51c6711a4a0a4c8000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    try std.testing.expectEqual(encodeTxCap(tx, false), 195);
}

test "decodeBigTxAndTXID" {
    const allocator = std.testing.allocator;
    var tx_raw = "0100000000010163c7d4d11b8d0f4d639c6e793e3c6df17e41266e7978fbfa8ff86a98525ace3305000000171600141a32847a8e47455eb34810198296f5ba55ef5533ffffffff2db0ad010000000000160014fe732e1609ace3514a4e1f86d0bcdbdeee20917fd84703000000000017a91485626661dea21c9b7bfe3dfd337e2b8215d9adaa87099a0400000000001976a914d0f5a749de85ffe93c7907a2cc51c4db2d447bb988ac00e204000000000017a914bbb24bbbb2a3244b6ab09e37133bfd7ffe43a5e387149606000000000017a9142f9935540a7dbf1e5c2b0360d99270ef827215998763be09000000000017a9141b15aa3d213fecaec014d6145f5343706537dfe487af020a000000000017a914474022a3202350d7a125da27781d99cb2a6912268720120a000000000017a9144a5de6c16c548528f19f0e5af1b3c1cfd6182f0c8714670a0000000000160014ed494d1107e2a938830744b507009ca9afae1ba440420f000000000017a914de89cfc0c58c3f2dfe19089bc215a55e7f42816187f6801000000000001976a9149ca0596591575e7918bafd81969208b88892e17188ac4ed410000000000017a914458e449732ed4971ce3acb9fb98eac43fc3cdc34872c5d11000000000017a9148ee52c5201edad4d2d2b86f66169fbb1c055f56187136b11000000000017a91419b03c51c341c4da61adec035e932647e8292f1c87804f12000000000017a9149a9a3edefae37a1a17a6ad106fe412b514429ab0871c7514000000000017a91445ea1981c4758c5fb1935a56fca95556219723648704d614000000000017a914fb961c729b4cac147ae792db291e85084807a59187a4591500000000001600143f8c416199a2454ccf23d8717ab10313f731ac9ed1ad150000000000160014a2771b8dc3fe6dbdf7ca821763360940e13de0053db016000000000017a914ea1865640094cc2cbdab1c592cd9d4773d55601387b0a617000000000017a914492f96724df3a85a9f3893017d09a3bffbb030a887e09818000000000017a91453bc1af769d2356d4ff8ba103ba83008f93380528707431d00000000001976a9149500bc0c16e3a6cbc0438af90e94b83364f6bffd88ac9ca41e00000000001976a914e27b5a80d961e0ee4144edc562e5848678f9cce288ac7a272300000000001976a9148584fe6d3b8a41ecd1840919ab98ecd9f16894a988ac80ee36000000000017a91426cc326ae6f496e421889c57494c98646108f5b18785733c000000000016001473a01568596519d3bc924756f647316ff7778a55dc253d000000000017a9142d079eed3636149a758b1acd5757910823a01d958720c155000000000017a9142c1ad0af56f340a9983d9080ec9f3480a05fd6db87ca495a00000000001600147039a4640d98d3dfbf65a8d81af3f9797ba59ca1e24a5a000000000016001422b426058b798231b98c0a172eea254ffa78fb7b9f225b000000000017a91492762e9dd8c6f3be6f8b3eae784f4ee7141b4a7587c09a5e000000000017a914291309107afddd6222eea5df261cdf7429d3fccb875ac45e0000000000160014c806df6b7cabf01fe787d38bbfc04978af3894cc20d960000000000016001417a33fe4469adeabbe117d412d27c1d948615e25af5167000000000017a914e334ea4816db2986069fc572d00ceb86780ebdcd875433690000000000160014bc19ad30eb139573e72daecbdfb5a43c299d8494cde977000000000017a914edf5455d5dfa60335a020e30390049a78049c07e87e0a57e000000000017a914efaffad14e8b8dc872b7a551deca4d394794414587c0e1e4000000000017a9146ae3f0b1e58d6cd3239d4a792d26e561d8e2c3e78780a812010000000017a914ee0fc83c7aaf46de3f3d04121165d3385adad3cf87c0ea21010000000017a914ce5698a58de1d3da19b6b279bb5db1ababe426fa8740d958010000000017a914268803d8241a0c8b76e7a69c500ad854176f176d87438a42020000000017a914b15c19c86d2b8d25042dbfa9c3415bda14ebfada874d0b74500000000017a914903b8360fdecd474f4625be5cfbc73d2ae2769aa8702473044022018ca4dc96716a910b54d4a78cff0c5a9c3aefe40c3a047128f1e045f163589af022004dfc91298efd47a9cfe5c33f81aba52d1604d0e7234a3f4e9c2baf48c5a8fde012103504252e45cc192c46f30776080f36f8e960d7683b5f43f0f68a0efeb10cda11700000000".*;
    const tx = try decodeRawTx(allocator, &tx_raw);
    defer tx.deinit();
    const txid = try tx.getTXID();
    const expected = "6eb6f3b6cd6ea982d647b2b685f4c809e2f761a8309e4c14b601abab87820e6e".*;
    try std.testing.expectEqualStrings(&expected, &txid);
}

test "isCoinbase" {
    const allocator = std.testing.allocator;
    const tx_raw = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600141065b3dd70fa8d3f9a16a070e7d68d8ea39beb880000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000".*;
    const tx = try decodeRawTx(allocator, @constCast(&tx_raw));
    defer tx.deinit();
    try std.testing.expectEqual(true, tx.isCoinbase());

    var tx_raw2 = "0100000000010163c7d4d11b8d0f4d639c6e793e3c6df17e41266e7978fbfa8ff86a98525ace3305000000171600141a32847a8e47455eb34810198296f5ba55ef5533ffffffff2db0ad010000000000160014fe732e1609ace3514a4e1f86d0bcdbdeee20917fd84703000000000017a91485626661dea21c9b7bfe3dfd337e2b8215d9adaa87099a0400000000001976a914d0f5a749de85ffe93c7907a2cc51c4db2d447bb988ac00e204000000000017a914bbb24bbbb2a3244b6ab09e37133bfd7ffe43a5e387149606000000000017a9142f9935540a7dbf1e5c2b0360d99270ef827215998763be09000000000017a9141b15aa3d213fecaec014d6145f5343706537dfe487af020a000000000017a914474022a3202350d7a125da27781d99cb2a6912268720120a000000000017a9144a5de6c16c548528f19f0e5af1b3c1cfd6182f0c8714670a0000000000160014ed494d1107e2a938830744b507009ca9afae1ba440420f000000000017a914de89cfc0c58c3f2dfe19089bc215a55e7f42816187f6801000000000001976a9149ca0596591575e7918bafd81969208b88892e17188ac4ed410000000000017a914458e449732ed4971ce3acb9fb98eac43fc3cdc34872c5d11000000000017a9148ee52c5201edad4d2d2b86f66169fbb1c055f56187136b11000000000017a91419b03c51c341c4da61adec035e932647e8292f1c87804f12000000000017a9149a9a3edefae37a1a17a6ad106fe412b514429ab0871c7514000000000017a91445ea1981c4758c5fb1935a56fca95556219723648704d614000000000017a914fb961c729b4cac147ae792db291e85084807a59187a4591500000000001600143f8c416199a2454ccf23d8717ab10313f731ac9ed1ad150000000000160014a2771b8dc3fe6dbdf7ca821763360940e13de0053db016000000000017a914ea1865640094cc2cbdab1c592cd9d4773d55601387b0a617000000000017a914492f96724df3a85a9f3893017d09a3bffbb030a887e09818000000000017a91453bc1af769d2356d4ff8ba103ba83008f93380528707431d00000000001976a9149500bc0c16e3a6cbc0438af90e94b83364f6bffd88ac9ca41e00000000001976a914e27b5a80d961e0ee4144edc562e5848678f9cce288ac7a272300000000001976a9148584fe6d3b8a41ecd1840919ab98ecd9f16894a988ac80ee36000000000017a91426cc326ae6f496e421889c57494c98646108f5b18785733c000000000016001473a01568596519d3bc924756f647316ff7778a55dc253d000000000017a9142d079eed3636149a758b1acd5757910823a01d958720c155000000000017a9142c1ad0af56f340a9983d9080ec9f3480a05fd6db87ca495a00000000001600147039a4640d98d3dfbf65a8d81af3f9797ba59ca1e24a5a000000000016001422b426058b798231b98c0a172eea254ffa78fb7b9f225b000000000017a91492762e9dd8c6f3be6f8b3eae784f4ee7141b4a7587c09a5e000000000017a914291309107afddd6222eea5df261cdf7429d3fccb875ac45e0000000000160014c806df6b7cabf01fe787d38bbfc04978af3894cc20d960000000000016001417a33fe4469adeabbe117d412d27c1d948615e25af5167000000000017a914e334ea4816db2986069fc572d00ceb86780ebdcd875433690000000000160014bc19ad30eb139573e72daecbdfb5a43c299d8494cde977000000000017a914edf5455d5dfa60335a020e30390049a78049c07e87e0a57e000000000017a914efaffad14e8b8dc872b7a551deca4d394794414587c0e1e4000000000017a9146ae3f0b1e58d6cd3239d4a792d26e561d8e2c3e78780a812010000000017a914ee0fc83c7aaf46de3f3d04121165d3385adad3cf87c0ea21010000000017a914ce5698a58de1d3da19b6b279bb5db1ababe426fa8740d958010000000017a914268803d8241a0c8b76e7a69c500ad854176f176d87438a42020000000017a914b15c19c86d2b8d25042dbfa9c3415bda14ebfada874d0b74500000000017a914903b8360fdecd474f4625be5cfbc73d2ae2769aa8702473044022018ca4dc96716a910b54d4a78cff0c5a9c3aefe40c3a047128f1e045f163589af022004dfc91298efd47a9cfe5c33f81aba52d1604d0e7234a3f4e9c2baf48c5a8fde012103504252e45cc192c46f30776080f36f8e960d7683b5f43f0f68a0efeb10cda11700000000".*;
    const tx2 = try decodeRawTx(allocator, &tx_raw2);
    defer tx2.deinit();
    try std.testing.expectEqual(false, tx2.isCoinbase());
}
