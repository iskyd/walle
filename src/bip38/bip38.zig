const std = @import("std");
const bip32 = @import("../bip32/bip32.zig");
const scrypt = std.crypto.pwhash.scrypt;
const aes = std.crypto.core.aes;
const utils = @import("../utils.zig");

const Network = @import("../const.zig").Network;
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

    var hexstrkey1: [32]u8 = undefined;
    var hexstrkey2: [32]u8 = undefined;
    var hexdh1: [32]u8 = undefined;
    var hexdh2: [32]u8 = undefined;
    _ = try std.fmt.bufPrint(&hexstrkey1, "{x}", .{std.fmt.fmtSliceHexLower(wpk.key[0..16])});
    _ = try std.fmt.bufPrint(&hexstrkey2, "{x}", .{std.fmt.fmtSliceHexLower(wpk.key[16..32])});
    _ = try std.fmt.bufPrint(&hexdh1, "{x}", .{std.fmt.fmtSliceHexLower(derivedhalf1[0..16])});
    _ = try std.fmt.bufPrint(&hexdh2, "{x}", .{std.fmt.fmtSliceHexLower(derivedhalf1[16..32])});

    const ukey1: u128 = try std.fmt.parseInt(u128, &hexstrkey1, 16);
    const ukey2: u128 = try std.fmt.parseInt(u128, &hexstrkey2, 16);
    const udh1: u128 = try std.fmt.parseInt(u128, &hexdh1, 16);
    const udh2: u128 = try std.fmt.parseInt(u128, &hexdh2, 16);

    var ctx = aes.Aes256.initEnc(derivedhalf2.*);

    const ub1 = ukey1 ^ udh1;
    const ub2 = ukey2 ^ udh2;

    var strblock1: [32]u8 = undefined;
    var strblock2: [32]u8 = undefined;
    try utils.intToHexStr(u128, ub1, &strblock1);
    try utils.intToHexStr(u128, ub2, &strblock2);

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

    return encoded;
}

test "base58_encrypt" {
    const allocator = std.testing.allocator;
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };

    const epk = bip32.generateExtendedMasterPrivateKey(seed);
    const wpk = bip32.WifPrivateKey.fromPrivateKey(epk.privatekey, Network.MAINNET, true);

    const encrypted = try encrypt(allocator, wpk, "password");

    try std.testing.expectEqualStrings(&encrypted, "6PRPV4a5qWAiCxmxFDZQ1bmMwMzUrT7tfkNm9eZsszoj7VWkHu5aQE3jgA");
}
