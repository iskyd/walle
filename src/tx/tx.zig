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
