const std = @import("std");
const bip32 = @import("../bip32/bip32.zig");
const scrypt = std.crypto.pwhash.scrypt;

pub fn encrypt(allocator: std.mem.Allocator, wpk: bip32.WifPrivateKey, passphrase: []const u8) !void {
    const public_key = bip32.generatePublicKey(wpk.key);
    const address = try bip32.deriveAddress(public_key);
    var addresshash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&address, &addresshash, .{});
    std.crypto.hash.sha2.Sha256.hash(&addresshash, &addresshash, .{});
    var derived: [64]u8 = undefined;
    // ln is log2(N) where N=16384 as specified here https://en.bitcoin.it/wiki/BIP_0038
    const params = scrypt.Params{ .ln = 14, .r = 8, .p = 8 };
    try scrypt.kdf(allocator, &derived, passphrase, &addresshash, params);
    const derivedhalf1 = derived[0..32];
    _ = derivedhalf1;
    const derivedhalf2 = derived[32..64];
    _ = derivedhalf2;
    std.debug.print("ADDRESS HASHED\n", .{});
}
