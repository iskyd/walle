const std = @import("std");
const script = @import("../script/script.zig");

const TxError = error{
    AmountTooLowError,
};

// Output represented by transaction hash and index n to its vout
const Output = struct {
    txhash: [64]u8,
    n: u32,
    amount: u32,
};

// Input of a transaction
const TxInput = struct {
    prevout: ?Output, // nullable due to coinbase transaction
    scriptsig: []u8,
};

// Output of a transaction
const TxOutput = struct {
    amount: u32,
    pubkey_script: script.Script,
};

// Transaction
pub const Transaction = struct {
    vin: std.ArrayList(TxInput),
    vout: std.ArrayList(TxOutput),
    version: i32,
    locktime: u32,

    pub fn isCoinbase(self: Transaction) bool {
        if (self.vin.items.len == 1 and self.vin.items[0].prevout == null) {
            return true;
        }
        return false;
    }

    pub fn getOutputValue(self: Transaction) u32 {
        var v: u32 = 0;
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

pub fn decodeRawTx(allocator: std.mem.Allocator, raw: []u8) !void {
    var bytes: []u8 = try allocator.alloc(u8, raw.len / 2);
    _ = try std.fmt.hexToBytes(bytes, raw);
    defer allocator.free(bytes);
    const version = bytes[0..4]; // Little Endian
    const v = std.mem.readIntLittle(u32, version);
    std.debug.print("version {d}\n", .{v});
    const marker = bytes[4]; // used to indicate segwit tx. Must be 00
    const flag = bytes[5]; // used to indicate segwit tx. Must be gte 01
    std.debug.print("marker {d}\n", .{marker});
    std.debug.print("flag {d}\n", .{flag});

    // Compat Size
    // This byte indicates which bytes encode the integer representing the numbers of inputs.
    // <= FC then this byte, FD then the next two bytes, FE the next four bytes, FF the next eight bytes.
    // ATM just using this bytes as byte count
    // TODO: add the other scenario
    const ci = bytes[6];
    std.debug.print("c input {d}\n", .{ci});
    var currentByte: u32 = 7;
    for (0..ci) |i| {
        const txid = bytes[currentByte .. currentByte + 32];
        var txidhex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&txidhex, "{x}", .{std.fmt.fmtSliceHexLower(txid)});
        _ = i;
        std.debug.print("txidhex {s}\n", .{txidhex});
        currentByte += 32;
        const vo: [4]u8 = bytes[currentByte .. currentByte + 4][0..4].*;
        const vout = std.mem.readIntLittle(u32, &vo);
        std.debug.print("vout {d}\n", .{vout});
        currentByte += 4;
        const scriptsigsize = bytes[currentByte];
        currentByte += 1;
        std.debug.print("Script sig size {d}\n", .{scriptsigsize});
        const scriptsig = bytes[currentByte .. currentByte + scriptsigsize];
        var scriptsighex = try allocator.alloc(u8, scriptsigsize * 2);
        defer allocator.free(scriptsighex);
        _ = try std.fmt.bufPrint(scriptsighex, "{x}", .{std.fmt.fmtSliceHexLower(scriptsig)});
        std.debug.print("Script sig {s}\n", .{scriptsighex});
        currentByte += scriptsigsize;
        const s = bytes[currentByte .. currentByte + 4][0..4].*;
        const sequence = std.mem.readIntLittle(u32, &s);
        std.debug.print("Sequence {d}\n", .{sequence});
        currentByte += 4;
    }

    // Compat size, same as ic
    const oc = bytes[currentByte];
    std.debug.print("\n\n", .{});
    std.debug.print("c output {d}\n", .{oc});
    currentByte += 1;
    for (0..oc) |i| {
        _ = i;
        const a = bytes[currentByte .. currentByte + 8][0..8].*;
        currentByte += 8;
        const amount = std.mem.readIntLittle(u64, &a);
        std.debug.print("amount {d}\n", .{amount});
        const scriptpubkeysize = bytes[currentByte];
        std.debug.print("script pub key size {d}\n", .{scriptpubkeysize});
        currentByte += 1;
        const scriptpubkey = bytes[currentByte .. currentByte + scriptpubkeysize];
        currentByte += scriptpubkeysize;
        var scriptpubkeyhex = try allocator.alloc(u8, scriptpubkeysize * 2);
        defer allocator.free(scriptpubkeyhex);
        _ = try std.fmt.bufPrint(scriptpubkeyhex, "{x}", .{std.fmt.fmtSliceHexLower(scriptpubkey)});
        std.debug.print("scriptpubkey {s}\n", .{scriptpubkeyhex});
    }

    // Compat size, same as ic and oc
    const stackitems = bytes[currentByte];
    std.debug.print("Stack items {d}\n", .{stackitems});
    currentByte += 1;
    for (0..stackitems) |i| {
        _ = i;
        const size = bytes[currentByte];
        currentByte += 1;
        std.debug.print("stack item size {d}\n", .{size});
        const item = bytes[currentByte .. currentByte + size];
        var itemhex = try allocator.alloc(u8, size * 2);
        defer allocator.free(itemhex);
        _ = try std.fmt.bufPrint(itemhex, "{x}", .{std.fmt.fmtSliceHexLower(item)});
        currentByte += size;
        std.debug.print("item hex {s}\n", .{itemhex});
    }

    const l = bytes[currentByte .. currentByte + 4][0..4].*;
    const locktime = std.mem.readIntLittle(u32, &l);
    std.debug.print("locktime {d}\n", .{locktime});
}

test "getOutputValue" {
    const allocator = std.testing.allocator;
    const o = Output{ .txhash = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .n = 0, .amount = 0 };
    var vin = std.ArrayList(TxInput).init(allocator);
    defer vin.deinit();
    var r: [6]u8 = "random".*;
    const txin = TxInput{ .prevout = o, .scriptsig = &r };
    try vin.append(txin);
    var vout = std.ArrayList(TxOutput).init(allocator);
    defer vout.deinit();
    const public: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var pubkey_script = try script.p2pk(allocator, &public);
    defer pubkey_script.deinit();
    try vout.append(TxOutput{ .amount = 130000, .pubkey_script = pubkey_script });
    try vout.append(TxOutput{ .amount = 37000, .pubkey_script = pubkey_script });
    const tx = Transaction{ .vin = vin, .vout = vout, .version = 1, .locktime = 0 };
    const outputv = tx.getOutputValue();
    try std.testing.expectEqual(outputv, 167000);
}

test "createTx" {
    const o1 = Output{ .txhash = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .n = 0, .amount = 10000 };
    const o2 = Output{ .txhash = "cabfe93aaa1d0ddb1c9faf1da80d902a693a9c84b9673f5524abf1fa3ce46349".*, .n = 1, .amount = 20000 };

    var outputs: [2]Output = [2]Output{ o1, o2 };
    try std.testing.expectError(TxError.AmountTooLowError, createTx(&outputs, 31000));
}

test "decodeRawTx" {
    const allocator = std.testing.allocator;
    var raw: [334]u8 = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a01000000160014dd3d4b7d821d44331e31a818d15f583302e8e1c00000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000".*;
    try decodeRawTx(allocator, &raw);
}
