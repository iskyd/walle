const std = @import("std");
const bip32 = @import("../bip32/bip32.zig");
const scrypt = std.crypto.pwhash.scrypt;
const aes = std.crypto.core.aes;
const utils = @import("../utils.zig");

const EC_MULTIPLY_FLAG_NO_PREFIX = [2]u8{ 0b00000001, 0b01000010 };
const FLAG_BYTE = [1]u8{0b11000000};

pub fn encrypt(allocator: std.mem.Allocator, wpk: bip32.WifPrivateKey, passphrase: []const u8) ![58]u8 {
    const public_key = bip32.generatePublicKey(wpk.key);
    const address = try bip32.deriveAddress(public_key);
    var addresshash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&address, &addresshash, .{});
    std.crypto.hash.sha2.Sha256.hash(&addresshash, &addresshash, .{});
    const salt = addresshash[0..4];
    var derived: [64]u8 = undefined;
    // ln is log2(N) where N=16384 as specified here https://en.bitcoin.it/wiki/BIP_0038
    const params = scrypt.Params{ .ln = 14, .r = 8, .p = 8 };
    try scrypt.kdf(allocator, &derived, passphrase, salt, params);
    const derivedhalf1 = derived[0..32];
    const derivedhalf2 = derived[32..64];
    std.debug.print("ADDRESS HASHED\n", .{});

    var hexstrkey1: [32]u8 = undefined;
    var hexstrkey2: [32]u8 = undefined;
    var hexdh1: [32]u8 = undefined;
    var hexdh2: [32]u8 = undefined;
    _ = try std.fmt.bufPrint(&hexstrkey1, "{x}", .{std.fmt.fmtSliceHexLower(wpk.key[0..16])});
    _ = try std.fmt.bufPrint(&hexstrkey2, "{x}", .{std.fmt.fmtSliceHexLower(wpk.key[16..32])});
    _ = try std.fmt.bufPrint(&hexdh1, "{x}", .{std.fmt.fmtSliceHexLower(derivedhalf1[0..16])});
    _ = try std.fmt.bufPrint(&hexdh2, "{x}", .{std.fmt.fmtSliceHexLower(derivedhalf1[16..32])});

    std.debug.print("Wpk key : {s}\n", .{hexstrkey1});
    std.debug.print("Wpk key : {s}\n", .{hexstrkey2});
    std.debug.print("Derived half 1 : {s}\n", .{hexdh1});
    std.debug.print("Derived half 2 : {s}\n", .{hexdh2});

    const ukey1: u128 = try std.fmt.parseInt(u128, &hexstrkey1, 16);
    const ukey2: u128 = try std.fmt.parseInt(u128, &hexstrkey2, 16);
    const udh1: u128 = try std.fmt.parseInt(u128, &hexdh1, 16);
    const udh2: u128 = try std.fmt.parseInt(u128, &hexdh2, 16);

    std.debug.print("Key int {d}\n", .{ukey1});
    std.debug.print("Key2 int {d}\n", .{ukey2});
    std.debug.print("Udh1 int {d}\n", .{udh1});
    std.debug.print("Udh2 int {d}\n", .{udh2});

    var ctx = aes.Aes256.initEnc(derivedhalf2.*);

    const ub1 = ukey1 ^ udh1;
    const ub2 = ukey2 ^ udh2;

    var strblock1: [32]u8 = undefined;
    var strblock2: [32]u8 = undefined;
    _ = try std.fmt.bufPrint(&strblock1, "{x}", .{ub1});
    _ = try std.fmt.bufPrint(&strblock2, "{x}", .{ub2});

    std.debug.print("Block 1 {s}\n", .{strblock1});
    std.debug.print("Block 2 {s}\n", .{strblock2});

    var block1: [16]u8 = undefined;
    var block2: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&block1, &strblock1);
    _ = try std.fmt.hexToBytes(&block2, &strblock2);
    var encryptedhalf1: [16]u8 = undefined;
    var encryptedhalf2: [16]u8 = undefined;

    ctx.encrypt(&encryptedhalf1, &block1);
    ctx.encrypt(&encryptedhalf2, &block2);

    var encryptedpk: [43]u8 = undefined;
    std.mem.copy(u8, encryptedpk[0..2], EC_MULTIPLY_FLAG_NO_PREFIX[0..2]);
    std.mem.copy(u8, encryptedpk[2..3], FLAG_BYTE[0..]);
    std.mem.copy(u8, encryptedpk[3..7], salt);
    std.mem.copy(u8, encryptedpk[7..23], encryptedhalf1[0..16]);
    std.mem.copy(u8, encryptedpk[23..39], encryptedhalf2[0..16]);

    const checksum = utils.calculateChecksum(encryptedpk[0..39]);
    std.mem.copy(u8, encryptedpk[39..43], checksum[0..4]);

    var encoded: [58]u8 = undefined;
    _ = try utils.toBase58(&encoded, &encryptedpk);

    std.debug.print("Base58 res {s}\n", .{encoded});
    return encoded;
}

test "base58" {
    try std.testing.expectEqual(3, 3);
}
