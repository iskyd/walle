const std = @import("std");

pub fn generateMasterPrivateKey(seed: [64]u8) void {
    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &seed, "Bitcoin seed");

    const masterSecretKey = I[0..32];
    const masterChainCode = I[32..64];

    const mi = std.mem.readIntBig(u256, masterSecretKey);
    std.debug.print("Master secret {x}\n", .{mi});
    const mc = std.mem.readIntBig(u256, masterChainCode);
    std.debug.print("Master chain {x}\n", .{mc});
}
