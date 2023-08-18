const std = @import("std");

pub fn generateMasterPrivateKey(seed: [64]u8) void {
    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &seed, "Bitcoin seed");
    std.debug.print("{d}\n", .{I});

    const masterSecretKey = I[0..32];
    const masterChainCode = I[32..64];

    std.debug.print("Master secret key {d}\n", .{masterSecretKey.*});
    std.debug.print("Master chain code {d}\n", .{masterChainCode.*});
}
