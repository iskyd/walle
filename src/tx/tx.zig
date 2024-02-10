const std = @import("std");
const script = @import("../script/script.zig");

// Output represented by transaction hash and index n to its vout
const Output = struct {
    txhash: [64]u8,
    n: u32,
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
const Transaction = struct {
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

test "getOutputValue" {
    const allocator = std.testing.allocator;
    const o = Output{ .txhash = "95cff5f34612b16e73ee2db28ddb08884136d005fb5d8ba8405bec30368f49e2".*, .n = 0 };
    var vin = std.ArrayList(TxInput).init(allocator);
    defer vin.deinit();
    var r: [6]u8 = "random".*;
    const txin = TxInput{ .prevout = o, .scriptsig = &r };
    try vin.append(txin);
    var vout = std.ArrayList(TxOutput).init(allocator);
    defer vout.deinit();
    try vout.append(TxOutput{ .amount = 130000, .pubkey_script = &r });
    try vout.append(TxOutput{ .amount = 37000, .pubkey_script = &r });
    const tx = Transaction{ .vin = vin, .vout = vout, .version = 1, .locktime = 0 };
    const outputv = tx.getOutputValue();
    try std.testing.expectEqual(outputv, 167000);
}
