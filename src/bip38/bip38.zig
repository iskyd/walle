const std = @import("std");
const bip32 = @import("../bip32/bip32.zig");
const scrypt = std.crypto.pwhash.scrypt;
const aes = std.crypto.core.aes;
const utils = @import("../utils.zig");
const addrlib = @import("../address/address.zig");

const Network = @import("../const.zig").Network;
const EC_NO_MULTIPLY_FLAG = [2]u8{ 0b00000001, 0b01000010 };
const FLAG_BYTE = [1]u8{0b11100000};

pub const DecryptError = error{
    InvalidChecksumError,
    InvalidPassphraseError,
};

pub fn encrypt(allocator: std.mem.Allocator, privatekey: [32]u8, passphrase: []const u8, network: Network) ![58]u8 {
    const publickey = bip32.generatePublicKey(privatekey);
    const addr = try addrlib.deriveP2PKHAddress(allocator, publickey, network);
    defer addr.deinit();
    const salt = utils.calculateChecksum(addr.val);
    var derived: [64]u8 = undefined;
    // ln is log2(N) where N=16384 as specified here https://en.bitcoin.it/wiki/BIP_0038
    const params = scrypt.Params{ .ln = 14, .r = 8, .p = 8 };
    var passbytes: [128]u8 = undefined;
    const pbl = try utils.encodeutf8(passphrase, &passbytes);
    try scrypt.kdf(allocator, &derived, passbytes[0..pbl], &salt, params);

    const derivedhalf1 = derived[0..32];
    const derivedhalf2 = derived[32..64];

    var hexstrkey1: [32]u8 = undefined;
    var hexstrkey2: [32]u8 = undefined;
    var hexdh1: [32]u8 = undefined;
    var hexdh2: [32]u8 = undefined;
    _ = try std.fmt.bufPrint(&hexstrkey1, "{x}", .{std.fmt.fmtSliceHexLower(privatekey[0..16])});
    _ = try std.fmt.bufPrint(&hexstrkey2, "{x}", .{std.fmt.fmtSliceHexLower(privatekey[16..32])});
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
    @memcpy(encryptedpk[0..2], EC_NO_MULTIPLY_FLAG[0..2]);
    @memcpy(encryptedpk[2..3], FLAG_BYTE[0..]);
    @memcpy(encryptedpk[3..7], &salt);
    @memcpy(encryptedpk[7..23], &encryptedhalf1);
    @memcpy(encryptedpk[23..39], &encryptedhalf2);

    const checksum = utils.calculateChecksum(encryptedpk[0..39]);
    @memcpy(encryptedpk[39..43], checksum[0..4]);

    var encoded: [58]u8 = undefined;
    _ = try utils.toBase58(&encoded, &encryptedpk);

    return encoded;
}

pub fn decrypt(allocator: std.mem.Allocator, encoded: [58]u8, passphrase: []const u8, network: Network) ![32]u8 {
    var encrypted: [43]u8 = undefined;
    try utils.fromBase58(&encoded, &encrypted);
    const checksum = encrypted[39..43];
    const isvalid = utils.verifyChecksum(encrypted[0..39], checksum[0..4].*);
    if (isvalid == false) {
        return DecryptError.InvalidChecksumError;
    }

    const prefix = encrypted[0..2];
    _ = prefix;
    const flag = encrypted[2..3];
    _ = flag;
    const addresshash = encrypted[3..7];

    var derived: [64]u8 = undefined;
    // const passbytes = std.mem.asBytes(&passphrase);
    // ln is log2(N) where N=16384 as specified here https://en.bitcoin.it/wiki/BIP_0038
    const params = scrypt.Params{ .ln = 14, .r = 8, .p = 8 };
    var passbytes: [128]u8 = undefined;
    const pbl = try utils.encodeutf8(passphrase, &passbytes);
    _ = try scrypt.kdf(allocator, &derived, passbytes[0..pbl], addresshash, params);
    const derivedhalf1 = derived[0..32];
    const derivedhalf2 = derived[32..64];
    const encryptedhalf1 = encrypted[7..23];
    const encryptedhalf2 = encrypted[23..39];
    var ctx = aes.Aes256.initDec(derivedhalf2.*);
    var block1: [16]u8 = undefined;
    var block2: [16]u8 = undefined;
    ctx.decrypt(&block1, encryptedhalf1);
    ctx.decrypt(&block2, encryptedhalf2);

    var strblock1: [32]u8 = undefined;
    var strblock2: [32]u8 = undefined;
    var strderivedhalf1: [32]u8 = undefined;
    var strderivedhalf2: [32]u8 = undefined;
    _ = try std.fmt.bufPrint(&strblock1, "{x}", .{std.fmt.fmtSliceHexLower(&block1)});
    _ = try std.fmt.bufPrint(&strblock2, "{x}", .{std.fmt.fmtSliceHexLower(&block2)});
    _ = try std.fmt.bufPrint(&strderivedhalf1, "{x}", .{std.fmt.fmtSliceHexLower(derivedhalf1[0..16])});
    _ = try std.fmt.bufPrint(&strderivedhalf2, "{x}", .{std.fmt.fmtSliceHexLower(derivedhalf1[16..32])});

    const ub1: u128 = try std.fmt.parseInt(u128, &strblock1, 16);
    const ub2: u128 = try std.fmt.parseInt(u128, &strblock2, 16);
    const udh1: u128 = try std.fmt.parseInt(u128, &strderivedhalf1, 16);
    const udh2: u128 = try std.fmt.parseInt(u128, &strderivedhalf2, 16);
    const ukey1 = ub1 ^ udh1;
    const ukey2 = ub2 ^ udh2;

    var hexstrkey1: [32]u8 = undefined;
    var hexstrkey2: [32]u8 = undefined;
    try utils.intToHexStr(u128, ukey1, &hexstrkey1);
    try utils.intToHexStr(u128, ukey2, &hexstrkey2);

    var pkstr: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&pkstr, "{s}{s}", .{ hexstrkey1, hexstrkey2 });
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, &pkstr);
    const publickey = bip32.generatePublicKey(pk);
    const addr = try addrlib.deriveP2PKHAddress(allocator, publickey, network);
    defer addr.deinit();
    const salt = utils.calculateChecksum(addr.val);
    if (std.mem.eql(u8, addresshash, &salt) == false) {
        return error.InvalidPassphraseError;
    }
    return pk;
}

test "base58_encrypt" {
    var hexpk: [64]u8 = "b39586851d52222a098455b1283de23b3b984da16a492d96a4f62189677b8495".*;
    var hexchaincode: [64]u8 = "18ee0c9e49d8382e9f9b14633503c583145bc9499db55dcff153904f6f6c4116".*;
    var pvk: [32]u8 = undefined;
    var chaincode: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pvk, &hexpk);
    _ = try std.fmt.hexToBytes(&chaincode, &hexchaincode);
    const epk = bip32.ExtendedPrivateKey{ .privatekey = pvk, .chaincode = chaincode };
    const allocator = std.testing.allocator;
    const encrypted = try encrypt(allocator, epk.privatekey, "password", Network.MAINNET);
    try std.testing.expectEqualStrings("6PYNENTKYFjz3QpEufgZjX9XozWPy5bqvvwpG9xdPUM8pr16ziKxyJktDD", &encrypted);
}

test "decrypt" {
    const allocator = std.testing.allocator;
    const encrypted = "6PYNENTKYFjz3QpEufgZjX9XozWPy5bqvvwpG9xdPUM8pr16ziKxyJktDD".*;
    const decryptedpk = try decrypt(allocator, encrypted, "password", Network.MAINNET);
    var decryptedhexpk: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&decryptedhexpk, "{x}", .{std.fmt.fmtSliceHexLower(&decryptedpk)});

    try std.testing.expectEqualStrings("b39586851d52222a098455b1283de23b3b984da16a492d96a4f62189677b8495", &decryptedhexpk);
}
