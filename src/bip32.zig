const std = @import("std");
const math = std.math;
const assert = std.debug.assert;
const utils = @import("utils.zig");
const Network = @import("const.zig").Network;
const script = @import("script.zig");
const KeyPath = @import("keypath.zig").KeyPath;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ripemd160 = @import("crypto").Ripemd160;

pub const SerializedPrivateKeyVersion = enum(u32) {
    mainnet = 0x0488aDe4,
    testnet = 0x04358394,
    segwit_mainnet = 0x04b2430c,
    segwit_testnet = 0x045f18bc,
};

pub const SerializedPublicKeyVersion = enum(u32) {
    mainnet = 0x0488b21e,
    testnet = 0x043587cf,
    segwit_mainnet = 0x04b24746,
    segwit_testnet = 0x045f1cf6,
};

pub const ExtendedPrivateKey = struct {
    privatekey: [32]u8, // Private Key
    chaincode: [32]u8, // Chain Code

    pub fn fromSeed(seed: []const u8) ExtendedPrivateKey {
        var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], seed, "Bitcoin seed");

        return ExtendedPrivateKey{
            .privatekey = I[0..32].*,
            .chaincode = I[32..].*,
        };
    }

    pub fn toStrPrivate(self: ExtendedPrivateKey) ![64]u8 {
        var str: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&self.privatekey)});
        return str;
    }

    pub fn toStrChainCode(self: ExtendedPrivateKey) ![64]u8 {
        var str: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&self.chaincode)});
        return str;
    }

    // Fingerprint bytes
    pub fn serialize(self: ExtendedPrivateKey, version: SerializedPrivateKeyVersion, depth: u8, fingerprint: [4]u8, index: u32) [82]u8 {
        var index_bytes: [4]u8 = @bitCast(@byteSwap(index));
        var res: [82]u8 = undefined;
        var version_bytes: [4]u8 = @bitCast(@byteSwap(@intFromEnum(version)));
        @memcpy(res[0..4], &version_bytes);
        res[4] = depth;
        @memcpy(res[5..9], &fingerprint);
        @memcpy(res[9..13], &index_bytes);
        @memcpy(res[13..45], &self.chaincode);
        res[45] = 0;
        @memcpy(res[46..78], &self.privatekey);
        const checksum = utils.calculateChecksum(res[0..78]);
        @memcpy(res[78..82], &checksum);

        return res;
    }

    pub fn address(self: ExtendedPrivateKey, version: SerializedPrivateKeyVersion, depth: u8, fingerprint: [4]u8, index: u32) ![111]u8 {
        const serialized = self.serialize(version, depth, fingerprint, index);
        var buffer: [111]u8 = undefined;
        try utils.toBase58(&buffer, &serialized);
        return buffer;
    }

    pub fn fromAddress(addr: [111]u8) !ExtendedPrivateKey {
        var bytes: [82]u8 = undefined;
        try utils.fromBase58(&addr, &bytes);
        const chaincode: [32]u8 = bytes[13..45].*;
        const pk: [32]u8 = bytes[46..78].*;
        const checksum = utils.calculateChecksum(bytes[0..78]);
        if (std.mem.eql(u8, &checksum, bytes[78..]) != true) {
            return error.InvalidChecksum;
        }
        return ExtendedPrivateKey{ .privatekey = pk, .chaincode = chaincode };
    }

    pub fn format(self: ExtendedPrivateKey, actual_fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = actual_fmt;
        _ = options;

        const private = try self.toStrPrivate();
        const chaincode = try self.toStrChainCode();
        try writer.print("Private key: {s}\nChain Code: {s}\n", .{ private, chaincode });
    }
};

pub const PublicKey = struct {
    point: Secp256k1, // Public Key

    pub fn fromPrivateKey(privkey: [32]u8) !PublicKey {
        const public = try Secp256k1.basePoint.mul(privkey, .big);
        return PublicKey{ .point = public };
    }

    pub fn toCompressed(self: PublicKey) [33]u8 {
        return self.point.toCompressedSec1();
    }

    pub fn toUncompressed(self: PublicKey) [65]u8 {
        return self.point.toUncompressedSec1();
    }

    pub fn toStrCompressed(self: PublicKey) ![66]u8 {
        const compressed = self.toCompressed();
        return try utils.bytesToHex(66, &compressed);
    }

    pub fn toStrUncompressed(self: PublicKey) ![130]u8 {
        const uncompressed = self.toUncompressed();
        return try utils.bytesToHex(130, &uncompressed);
    }

    // return bytes
    pub fn toHash(self: PublicKey) ![20]u8 {
        // We use the compressed public key because P2WPKH only works with compressed public keys
        const compressed = self.point.toCompressedSec1();

        var hashed: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&compressed, &hashed, .{});

        const r = Ripemd160.hash(&hashed);
        var rstr: [40]u8 = undefined;
        _ = try std.fmt.bufPrint(&rstr, "{x}", .{std.fmt.fmtSliceHexLower(r.bytes[0..])});
        var bytes: [20]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, &rstr);

        var address: [20]u8 = undefined;
        @memcpy(address[0..20], bytes[0..20]);

        return address;
    }

    // return hex string of hash
    pub fn toHashHex(self: PublicKey) ![40]u8 {
        const hash = try self.toHash();
        var hashhex: [40]u8 = undefined;
        _ = try std.fmt.bufPrint(&hashhex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
        return hashhex;
    }

    // return bytes.
    // It also adds prefix and checksum
    pub fn toCompleteHash(self: PublicKey, n: Network) ![25]u8 {
        const pubkey_hash = try self.toHash();
        var pubkey_withprefix: [42]u8 = undefined;
        _ = switch (n) {
            Network.mainnet => try std.fmt.bufPrint(&pubkey_withprefix, "00{x}", .{std.fmt.fmtSliceHexLower(&pubkey_hash)}),
            else => _ = try std.fmt.bufPrint(&pubkey_withprefix, "6f{x}", .{std.fmt.fmtSliceHexLower(&pubkey_hash)}),
        };
        var bytes: [21]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, &pubkey_withprefix);

        const checksum = utils.calculateChecksum(&bytes);
        var addr: [25]u8 = undefined;
        @memcpy(addr[0..21], bytes[0..]);
        @memcpy(addr[21..25], checksum[0..4]);
        return addr;
    }

    pub fn fromCompressed(compressed: [33]u8) !PublicKey {
        const p = try Secp256k1.fromSec1(&compressed);
        return PublicKey{ .point = p };
    }

    pub fn fromStrCompressed(compressed: [66]u8) !PublicKey {
        // TODO: str to bytes without passing from an u264
        const v = try std.fmt.parseInt(u264, &compressed, 16);
        const c: [33]u8 = @bitCast(@byteSwap(v));
        const p = try Secp256k1.fromSec1(&c);
        return PublicKey{ .point = p };
    }

    pub fn format(self: PublicKey, actual_fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = actual_fmt;
        _ = options;

        const public_uncompressed = try self.toStrUncompressed();
        try writer.print("Public uncompressed key: {s}\n\n", .{public_uncompressed});
    }
};

pub const ExtendedPublicKey = struct {
    key: PublicKey,
    chaincode: [32]u8,

    pub fn serialize(self: ExtendedPublicKey, version: SerializedPublicKeyVersion, depth: u8, fingerprint: [4]u8, index: u32) ![82]u8 {
        var index_bytes: [4]u8 = @bitCast(@byteSwap(index));
        var res: [82]u8 = undefined;
        var version_bytes: [4]u8 = @bitCast(@byteSwap(@intFromEnum(version)));
        @memcpy(res[0..4], &version_bytes);
        res[4] = depth;
        @memcpy(res[5..9], &fingerprint);
        @memcpy(res[9..13], &index_bytes);
        @memcpy(res[13..45], &self.chaincode);
        const compressed = self.key.toCompressed();
        @memcpy(res[45..78], &compressed);
        const checksum = utils.calculateChecksum(res[0..78]);
        @memcpy(res[78..82], &checksum);

        return res;
    }

    pub fn address(self: ExtendedPublicKey, version: SerializedPublicKeyVersion, depth: u8, fingerprint: [4]u8, index: u32) ![111]u8 {
        const serialized = try self.serialize(version, depth, fingerprint, index);
        var buffer: [111]u8 = undefined;
        try utils.toBase58(&buffer, &serialized);
        return buffer;
    }

    pub fn fromAddress(addr: [111]u8) !ExtendedPublicKey {
        var bytes: [82]u8 = undefined;
        try utils.fromBase58(&addr, &bytes);
        const chaincode: [32]u8 = bytes[13..45].*;
        const compressed: [33]u8 = bytes[45..78].*;
        const checksum = utils.calculateChecksum(bytes[0..78]);
        if (std.mem.eql(u8, &checksum, bytes[78..]) != true) {
            return error.InvalidChecksum;
        }
        var compressed_str: [66]u8 = undefined;
        _ = try std.fmt.bufPrint(&compressed_str, "{x}", .{std.fmt.fmtSliceHexLower(compressed[0..])});
        const pubkey = try PublicKey.fromStrCompressed(compressed_str);
        return ExtendedPublicKey{ .key = pubkey, .chaincode = chaincode };
    }
};

pub fn deriveChildFromExtendedPrivateKey(extended_privkey: ExtendedPrivateKey, index: u32) !ExtendedPrivateKey {
    assert(index >= 0);
    assert(index <= 2147483647);
    const index_bytes: [4]u8 = @bitCast(@byteSwap(index));
    const public = try PublicKey.fromPrivateKey(extended_privkey.privatekey);
    const compressed = public.toCompressed();
    const data: [37]u8 = compressed ++ index_bytes;

    // 74 = 37 * 2 (2 hex characters per byte)
    var buffer: [74]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer, "{x}", .{std.fmt.fmtSliceHexLower(&data)});
    var chaincode_buffer: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&chaincode_buffer, "{x}", .{std.fmt.fmtSliceHexLower(&extended_privkey.chaincode)});

    var bytes: [37]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &buffer);
    var chaincode_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&chaincode_bytes, &chaincode_buffer);

    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &bytes, &chaincode_bytes);

    const private: u256 = std.mem.readInt(u256, &extended_privkey.privatekey, .big);
    const random: u256 = std.mem.readInt(u256, I[0..32], .big);
    const k: u256 = @intCast(@mod(@as(u512, private) + random, Secp256k1.scalar.field_order));

    return ExtendedPrivateKey{
        .privatekey = @bitCast(@byteSwap(k)),
        .chaincode = I[32..].*,
    };
}

pub fn deriveChildFromExtendedPublicKey(extended_pubkey: ExtendedPublicKey, index: u32) !ExtendedPublicKey {
    assert(index >= 0);
    assert(index <= 2147483647);
    const index_bytes: [4]u8 = @bitCast(@byteSwap(index));
    const compressed: [33]u8 = extended_pubkey.key.toCompressed();
    const data: [37]u8 = compressed ++ index_bytes;

    var buffer: [74]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer, "{x}", .{std.fmt.fmtSliceHexLower(&data)});
    var chaincode_buffer: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&chaincode_buffer, "{x}", .{std.fmt.fmtSliceHexLower(&extended_pubkey.chaincode)});

    var bytes: [37]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &buffer);
    var chaincode_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&chaincode_bytes, &chaincode_buffer);

    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &bytes, &chaincode_bytes);

    var base_point = Secp256k1.basePoint;
    const new_point = extended_pubkey.key.point.add(try base_point.mul(I[0..32].*, .big));

    return ExtendedPublicKey{ .key = PublicKey{ .point = new_point }, .chaincode = I[32..].* };
}

pub fn deriveHardenedChild(extended_privkey: ExtendedPrivateKey, index: u32) !ExtendedPrivateKey {
    assert(index >= 2147483648);
    assert(index <= 4294967295);
    const prefix: [1]u8 = [1]u8{0b00000000};
    const index_bytes: [4]u8 = @bitCast(@byteSwap(index));
    const data: [37]u8 = prefix ++ extended_privkey.privatekey ++ index_bytes;

    var buffer: [74]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer, "{x}", .{std.fmt.fmtSliceHexLower(&data)});
    var chaincode_buffer: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&chaincode_buffer, "{x}", .{std.fmt.fmtSliceHexLower(&extended_privkey.chaincode)});

    var bytes: [37]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &buffer);
    var chaincode_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&chaincode_bytes, &chaincode_buffer);

    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &bytes, &chaincode_bytes);

    const private: u256 = std.mem.readInt(u256, &extended_privkey.privatekey, .big);
    const random: u256 = std.mem.readInt(u256, I[0..32], .big);
    const k: u256 = @intCast(@mod(@as(u512, private) + random, Secp256k1.scalar.field_order));

    return ExtendedPrivateKey{
        .privatekey = @bitCast(@byteSwap(k)),
        .chaincode = I[32..].*,
    };
}

pub fn deriveChildFromKeyPath(comptime T: type, extended_key: T, comptime keypath_depth: u8, keypath: KeyPath(keypath_depth)) !T {
    return switch (T) {
        ExtendedPrivateKey => {
            var r = ExtendedPrivateKey{ .privatekey = extended_key.privatekey, .chaincode = extended_key.chaincode };
            for (keypath.path) |p| {
                if (p.is_hardened == true) {
                    r = try deriveHardenedChild(r, p.value + 2147483648);
                } else {
                    r = try deriveChildFromExtendedPrivateKey(r, p.value);
                }
            }

            return r;
        },
        ExtendedPublicKey => {
            var r = ExtendedPublicKey{ .key = extended_key.key, .chaincode = extended_key.chaincode };
            for (keypath.path) |p| {
                assert(p.is_hardened == false);
                r = try deriveChildFromExtendedPublicKey(r, p.value);
            }

            return r;
        },
        else => @compileError("Expected type ExtendedPrivateKey or ExtendedPublicKey"),
    };
}

test "extendedMasterPrivateKeyFromSeed" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };

    const epk: ExtendedPrivateKey = ExtendedPrivateKey.fromSeed(&seed);
    const str: [64]u8 = try epk.toStrPrivate();
    const str2: [64]u8 = try epk.toStrChainCode();

    try std.testing.expectEqualSlices(u8, "b21fcb414b4414e9bcf7ae647a79a4d29280f6b71cba204cb4dd3d6c6568d0fc", &str);
    try std.testing.expectEqualSlices(u8, "bbb5f26acee2e3713d43cf4e702f2b1ff8672afa9e0d5ac846196689e1d893d2", &str2);
}

test "publicKeyFromPrivateKey" {
    const private = try utils.hexToBytes(32, "6794b846e8930a00bb341d0c412f67bd7521d840afae30378647b6a0b2ed2905");
    const public = try PublicKey.fromPrivateKey(private);

    try std.testing.expectEqualStrings(&try public.toStrCompressed(), "039c24336ceb871255aaf6d7c6afb295f4493ac6d3245fdcbbcc75a72e237ab020");
}

test "deriveChildFromExtendedPrivateKey" {
    const seedhex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = ExtendedPrivateKey.fromSeed(&seed);
    const child = try deriveChildFromExtendedPrivateKey(epk, 0);

    const expectedprivatekeyaddr = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt".*;
    const expectedprivate = try ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);
    try std.testing.expectEqualSlices(u8, &expectedprivate.privatekey, &child.privatekey);
}

test "deriveChildFromExtendedPrivateKeyIndex1" {
    const seedhex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = ExtendedPrivateKey.fromSeed(&seed);
    const child = try deriveChildFromExtendedPrivateKey(epk, 1);
    var privatekey: [64]u8 = undefined;
    var chaincode: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&privatekey, "{x}", .{std.fmt.fmtSliceHexLower(&child.privatekey)});
    _ = try std.fmt.bufPrint(&chaincode, "{x}", .{std.fmt.fmtSliceHexLower(&child.chaincode)});
    const expectedpk = "63bbae9fe4abd1ff6ac75ab7306ea1d91a743246be33b2c6eb6fef812180924d".*;
    const expectedchaincode = "009e0528bc0cd2b12baf964a6de3ee6f4c05513fe990b0077ddeb726c017c0f5".*;
    try std.testing.expectEqualStrings(&expectedpk, &privatekey);
    try std.testing.expectEqualStrings(&expectedchaincode, &chaincode);
}

test "deriveChildFromExtendedPublicKey" {
    const seedhex = "81a79e3c7df2fc3376b087b5d5db952eb3c29eaf958b73aaad4ebc9eedb29e55abd8880457171d73ee4adeeaa3950812e6d1d935202f4ecc4aa62d8974665bcf".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = ExtendedPrivateKey.fromSeed(&seed);
    const public = try PublicKey.fromPrivateKey(epk.privatekey);
    const extendedpublic = ExtendedPublicKey{ .key = public, .chaincode = epk.chaincode };
    const extendedchild = try deriveChildFromExtendedPublicKey(extendedpublic, 0);
    const expectedPublicAddr = "xpub6812wt8cXaNNpj6dn1q7cYvhyyyYHAECx3Dx1vZYtJS9Ts5gz2BsmgBVxnbwg3g6vrZJSWJuBSmVSyyMwMKYRohB6WxCCnACY97JAF7AshB".*;
    const expectedpublic = try ExtendedPublicKey.fromAddress(expectedPublicAddr);

    try std.testing.expect(extendedchild.key.point.equivalent(expectedpublic.key.point));
    try std.testing.expectEqualStrings(&extendedchild.chaincode, &expectedpublic.chaincode);
}

test "deriveChildFromExtendedPublicKeyIndex1" {
    // testing only with index = 0 is not enough since byte order matters and 0 is the same in both directions
    const addr = "tpubDCqjeTSmMEVcovTXiEJ8xNCZXobYFckihB9M6LsRMF9XNPX87ndZkLvGmY2z6PguGJDyUdzpF7tc1EtmqK1zJmPuJkfvutYGTz15JE7QW2Y".*;
    const epk = try ExtendedPublicKey.fromAddress(addr);
    const derived = try deriveChildFromExtendedPublicKey(epk, 1);
    const expectedpublic = "020387ef75af3aafba234f679ba4104b270eb8372bc7e727d13cfe4eec8122ac43".*;
    const expectedchaincode = "b88386ce58d712d33afe158f0322655c58cfab158cb7ec25b5fb6f880e1f6716".*;
    var chaincodehex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&chaincodehex, "{x}", .{std.fmt.fmtSliceHexLower(&derived.chaincode)});
    const publiccompressed = try derived.key.toStrCompressed();
    try std.testing.expectEqualStrings(&expectedpublic, &publiccompressed);
    try std.testing.expectEqualStrings(&expectedchaincode, &chaincodehex);
}

test "deriveHardenedChild" {
    const seedhex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = ExtendedPrivateKey.fromSeed(&seed);
    const child = try deriveHardenedChild(epk, 2147483648); // 0'
    const expectedprivatekeyaddr = "xprv9vHkqa6NpjQMiZJLz4sFbVqYk7EXEUrWBd8drQZCp4furXS13egriq1pr2ncv2UBok3GifpitiQfp9kxNitz2RXbwtAo8hiv4CieaLTHyRL".*;
    const expectedprivate = try ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);

    try std.testing.expectEqualStrings(&try utils.bytesToHex(66, &expectedprivate.privatekey), &try utils.bytesToHex(66, &child.privatekey));
}

test "pubKeyCompress" {
    const p = Secp256k1.basePoint;
    const pk = PublicKey{ .point = p };
    const compressed = pk.toCompressed();
    try std.testing.expectEqualStrings(&try utils.bytesToHex(66, &compressed), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
}

test "toStrCompressed" {
    const p = Secp256k1.basePoint;
    const pk = PublicKey{ .point = p };
    const str = try pk.toStrCompressed();
    try std.testing.expectEqualSlices(u8, &str, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
}

test "toStrUncompressed" {
    const p = Secp256k1.basePoint;
    const pk = PublicKey{ .point = p };
    const str = try pk.toStrUncompressed();
    try std.testing.expectEqualStrings(&str, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
}

test "toHash" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = ExtendedPrivateKey.fromSeed(&seed);
    const pk = try PublicKey.fromPrivateKey(epk.privatekey);
    const address: [20]u8 = try pk.toHash();
    var str: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&address)});
    try std.testing.expectEqualSlices(u8, "f57f296d748bb310dc0512b28231e8ebd6245455", &str);

    const pubkeystr = "02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277".*;
    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    const c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try Secp256k1.fromSec1(&c);
    const pk1 = PublicKey{ .point = p };
    const addr = try pk1.toHash();
    var s: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&s, "{x}", .{std.fmt.fmtSliceHexLower(&addr)});
    try std.testing.expectEqualSlices(u8, "1e51fcdc14be9a148bb0aaec9197eb47c83776fb", s[0..]);

    const pubkeystr2 = "03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31".*;
    const v2 = try std.fmt.parseInt(u264, &pubkeystr2, 16);
    const c2: [33]u8 = @bitCast(@byteSwap(v2));
    const p2 = try Secp256k1.fromSec1(&c2);
    const pk2 = PublicKey{ .point = p2 };
    const addr2 = try pk2.toHash();
    var s2: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&s2, "{x}", .{std.fmt.fmtSliceHexLower(&addr2)});
    try std.testing.expectEqualSlices(u8, "55ae51684c43435da751ac8d2173b2652eb64105", s2[0..]);
}

test "serializePrivateKey" {
    var pkstr = "1205ace2508d2b0376a6826c6b2a0f4573fb926a432d4ae3f9e6976fc566afd5".*;
    var ccstr = "7d44cde0cdd0423cfa61fc4ac0e371fa6eba38e6fe5081eca5fcf4ae934a26d3".*;
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, &pkstr);
    var cc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cc, &ccstr);

    const epk = ExtendedPrivateKey{ .privatekey = pk, .chaincode = cc };
    var fingerprintstr = "59b172d8".*;
    var fingerprint: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fingerprint, &fingerprintstr);
    const serialized = epk.serialize(.mainnet, 5, fingerprint, 14);
    const serialized_testnet = epk.serialize(.testnet, 5, fingerprint, 14);
    var str: [164]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&serialized)});
    var str_testnet: [164]u8 = undefined;
    _ = try std.fmt.bufPrint(&str_testnet, "{x}", .{std.fmt.fmtSliceHexLower(&serialized_testnet)});

    const expected = "0488ade40559b172d80000000e7d44cde0cdd0423cfa61fc4ac0e371fa6eba38e6fe5081eca5fcf4ae934a26d3001205ace2508d2b0376a6826c6b2a0f4573fb926a432d4ae3f9e6976fc566afd53ed3f8fe";
    const expected_testnet = "043583940559b172d80000000e7d44cde0cdd0423cfa61fc4ac0e371fa6eba38e6fe5081eca5fcf4ae934a26d3001205ace2508d2b0376a6826c6b2a0f4573fb926a432d4ae3f9e6976fc566afd5550312a1";
    try std.testing.expectEqualStrings(expected, &str);
    try std.testing.expectEqualStrings(expected_testnet, &str_testnet);
}

test "privateKeyAddress" {
    var pkstr = "1205ace2508d2b0376a6826c6b2a0f4573fb926a432d4ae3f9e6976fc566afd5".*;
    var ccstr = "7d44cde0cdd0423cfa61fc4ac0e371fa6eba38e6fe5081eca5fcf4ae934a26d3".*;
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, &pkstr);
    var cc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cc, &ccstr);

    const epk = ExtendedPrivateKey{ .privatekey = pk, .chaincode = cc };
    var fingerprintstr = "59b172d8".*;
    var fingerprint: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fingerprint, &fingerprintstr);
    const base58 = try epk.address(.mainnet, 5, fingerprint, 14);
    const base58_bip84 = try epk.address(.segwit_mainnet, 5, fingerprint, 14);

    const expected = "xprvA35vcVznDBo4f5dPwVtqdFoqxXrADVyad5xb6Hk37pcExHa8z8xK9761jiWDkyAudCPVCbdqko4k2EUjSVcVz1xxkggfkULjGzWdnzG7zKf";
    const expected_bip84 = "zprvAgkTDqLcWYt2Mg1dcDU63RzrJU946jxaTK12f5XosqN14VCbVTHSPEQHn8RPknUkSUd6hYpxg7mqnohrstSXaVLAVN5WvHyhpSdvaAWpc3c";

    try std.testing.expectEqualStrings(expected, &base58);
    try std.testing.expectEqualStrings(expected_bip84, &base58_bip84);
}

test "extendedPrivateKeyFromAddress" {
    const addr = "xprvA35vcVznDBo4f5dPwVtqdFoqxXrADVyad5xb6Hk37pcExHa8z8xK9761jiWDkyAudCPVCbdqko4k2EUjSVcVz1xxkggfkULjGzWdnzG7zKf".*;
    const expected = "1205ace2508d2b0376a6826c6b2a0f4573fb926a432d4ae3f9e6976fc566afd5".*;
    const expectedchaincode = "7d44cde0cdd0423cfa61fc4ac0e371fa6eba38e6fe5081eca5fcf4ae934a26d3".*;
    const epk = try ExtendedPrivateKey.fromAddress(addr);
    var strprivatekey: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&strprivatekey, "{x}", .{std.fmt.fmtSliceHexLower(&epk.privatekey)});
    var strchaincode: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&strchaincode, "{x}", .{std.fmt.fmtSliceHexLower(&epk.chaincode)});

    try std.testing.expectEqualStrings(&expected, &strprivatekey);
    try std.testing.expectEqualStrings(&expectedchaincode, &strchaincode);

    const epk2 = try ExtendedPrivateKey.fromAddress("tprv8ZgxMBicQKsPfCxvMSGLjZegGFnZn9VZfVdsnEbuzTGdS9aZjvaYpyh7NsxsrAc8LsRQZ2EYaCfkvwNpas8cKUBbptDzadY7c3hUi8i33XJ".*);
    try std.testing.expectEqualStrings("3cce48c84f22343cbdac8e7f252ed8ca11fce329deae7ed635b73822dfed9c77", &try utils.bytesToHex(64, &epk2.privatekey));
    try std.testing.expectEqualStrings("ea6f63babb3dc5c58ea4cd11cb3fc9d7baa51c0e14be8230ffb8b1696796a63f", &try utils.bytesToHex(64, &epk2.chaincode));
}

test "serializePublicKey" {
    var pubkeystr = "0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302".*;
    var ccstr = "d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf".*;
    var cc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cc, &ccstr);

    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    const c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try Secp256k1.fromSec1(&c);
    const pk = PublicKey{ .point = p };

    const epk = ExtendedPublicKey{ .key = pk, .chaincode = cc };
    var fingerprintstr = "024bd5de".*;
    var fingerprint: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fingerprint, &fingerprintstr);
    const serialized = try epk.serialize(.mainnet, 3, fingerprint, 18);
    var str: [164]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&serialized)});

    const serialized_testnet = try epk.serialize(.testnet, 3, fingerprint, 18);
    var str_testnet: [164]u8 = undefined;
    _ = try std.fmt.bufPrint(&str_testnet, "{x}", .{std.fmt.fmtSliceHexLower(&serialized_testnet)});

    const expected = "0488b21e03024bd5de00000012d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302c431f6fc";
    const expected_testnet = "043587cf03024bd5de00000012d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced330227f05bf3";

    try std.testing.expectEqualStrings(expected, &str);
    try std.testing.expectEqualStrings(expected_testnet, &str_testnet);
}

test "extendedPublicKeyAddress" {
    var pubkeystr = "0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302".*;
    var ccstr = "d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf".*;
    var cc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cc, &ccstr);

    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    const c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try Secp256k1.fromSec1(&c);
    const pk = PublicKey{ .point = p };

    const epk = ExtendedPublicKey{ .key = pk, .chaincode = cc };
    var fingerprintstr = "024bd5de".*;
    var fingerprint: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fingerprint, &fingerprintstr);
    const base58 = try epk.address(.mainnet, 3, fingerprint, 18);
    const base58_bip84 = try epk.address(.segwit_mainnet, 3, fingerprint, 18);

    const expected = "xpub6BfkKmAArYaLxNUQE8d87QuhPwipqTykFJLMND7NgihE9GSo317PjazsLo2Ex2JmDmwXGyiB5K5nyx6n3rpW5oJc8TXXvEex6ipo9rrCUWw";
    const expected_testnet = "zpub6qLGw6W19ufJexrdtrCNXb6hjt1iihxk5XNnvzu9SjSzFU5FYKSWyiK9PCwQwqcc34B8mvuHzdntkXKuVFeXgGfos8vP64HveAx5w2KMgRn";
    try std.testing.expectEqualStrings(expected, &base58);
    try std.testing.expectEqualStrings(expected_testnet, &base58_bip84);
}

test "extendedPublicKeyFromAddress" {
    const addr = "xpub6BfkKmAArYaLxNUQE8d87QuhPwipqTykFJLMND7NgihE9GSo317PjazsLo2Ex2JmDmwXGyiB5K5nyx6n3rpW5oJc8TXXvEex6ipo9rrCUWw".*;
    const expected = "0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302".*;
    const epk = try ExtendedPublicKey.fromAddress(addr);
    const strcompressed = try epk.key.toStrCompressed();
    try std.testing.expectEqualStrings(&expected, &strcompressed);
}

test "bip44Derivation" {
    const seedhex = "81a79e3c7df2fc3376b087b5d5db952eb3c29eaf958b73aaad4ebc9eedb29e55abd8880457171d73ee4adeeaa3950812e6d1d935202f4ecc4aa62d8974665bcf".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = ExtendedPrivateKey.fromSeed(&seed);
    const child = try deriveHardenedChild(epk, 2147483648 + 44); // 44'
    try std.testing.expectEqualStrings(&try utils.bytesToHex(64, &child.privatekey), "e790ffc898a4246bb39c7fbb5c0a4ccd1ea42dfb697851fdade7397b914cea39");

    const child2 = try deriveHardenedChild(child, 2147483648);
    try std.testing.expectEqualStrings(&try utils.bytesToHex(64, &child2.privatekey), "3ce0b150c6523994bd8c4371dcf4f2faf7f187d364a7041402e360554c1fdcee");

    const child3 = try deriveHardenedChild(child2, 2147483648);
    const expectedprivatekeyaddr = "xprv9xibuu9WWWf3fYnGiKY6sqk8rvNHCZMjbLLDcF2Qj8N3WcNzw2AknNGapkd79mUuU2BwC5kvqcFuC5VAujGHBuT2gujogoMq1A4qDasdxVM".*;
    const expectedpublicaddr = "xpub6G3vxdEYuhYffVX9HjJrdDaQdeyG2bm2LCCM8FP7QcH5xtXkND1FPzEHYmWL9STdzZodqxyWBBXWV3BNRbJkhwMZBjZYmfwm1D5tVYwWfZ8".*;
    const expectedprivate = try ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);
    const expectedpublic = try ExtendedPublicKey.fromAddress(expectedpublicaddr);

    const public = try PublicKey.fromPrivateKey(child3.privatekey);
    const extendedpublic = ExtendedPublicKey{ .key = public, .chaincode = child3.chaincode };
    const child4 = try deriveChildFromExtendedPublicKey(extendedpublic, 0);
    const child5 = try deriveChildFromExtendedPublicKey(child4, 0);

    try std.testing.expectEqualStrings(&try utils.bytesToHex(66, &expectedprivate.privatekey), &try utils.bytesToHex(66, &child3.privatekey));
    try std.testing.expect(child5.key.point.equivalent(expectedpublic.key.point));
}

test "toStrCompressedLessHexChars" {
    const expected = "0203888acbf80676b8118d2ea5e1f821723aa1257ed5da18402025a17b09b2d4bc".*;
    const pk = try PublicKey.fromStrCompressed(expected);
    const compressed = try pk.toStrCompressed();
    try std.testing.expectEqualStrings(&expected, &compressed);
}

test "extendedPrivateKeyAddress" {
    const seed = "54f2ee3035cc4310d5ef260e821fb608a2c753369282a6932a13e583291a1662".*;
    var bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &seed);
    const epk = ExtendedPrivateKey.fromSeed(&bytes);
    const expected = "xprv9s21ZrQH143K3HShLjMf6GB3sQPW6rxZ3sS8tkgsvE38tViJ1rC53ESrkPM5mZYoJxjsz9nnkrAJSLenjCW2QKBPccQ3mpukTDmxQ5d1Ahx".*;
    const addr = try epk.address(.mainnet, 0, [4]u8{ 0, 0, 0, 0 }, 0);
    try std.testing.expectEqualStrings(&expected, &addr);
}

test "deriveChildFromKeyPathExtendedPrivate" {
    const epk = try ExtendedPrivateKey.fromAddress("tprv8ZgxMBicQKsPfCxvMSGLjZegGFnZn9VZfVdsnEbuzTGdS9aZjvaYpyh7NsxsrAc8LsRQZ2EYaCfkvwNpas8cKUBbptDzadY7c3hUi8i33XJ".*);

    const keypath_partial = try KeyPath(3).fromStr("84'/1'/0'");
    const epk_partial = try deriveChildFromKeyPath(ExtendedPrivateKey, epk, 3, keypath_partial);

    const keypath = try KeyPath(4).fromStr("84'/1'/0'/0");
    const r = try deriveChildFromKeyPath(ExtendedPrivateKey, epk, 4, keypath);

    try std.testing.expectEqualStrings("ef3b8a82492a138ca4e39f6d508ec858e60dbfac64a143b021687aa42897682c", &try utils.bytesToHex(64, &r.privatekey));
    try std.testing.expectEqualStrings("da50dba459aa9adcb6410bba999e5a6827d583d100efea52ede417a767729c70", &try utils.bytesToHex(64, &r.chaincode));

    // 84'/1'/0'/0/1
    const n = try deriveChildFromExtendedPrivateKey(r, 1);

    const keypath_public = try KeyPath(2).fromStr("0/1");
    const extended_public = ExtendedPublicKey{ .key = try PublicKey.fromPrivateKey(epk_partial.privatekey), .chaincode = epk_partial.chaincode };

    const r2 = try deriveChildFromKeyPath(ExtendedPublicKey, extended_public, 2, keypath_public);
    const expected_public = try PublicKey.fromPrivateKey(n.privatekey);

    try std.testing.expect(expected_public.point.equivalent(r2.key.point));
    try std.testing.expectEqualSlices(u8, &n.chaincode, &r2.chaincode);
}

test "deriveChildFromKeyPathExtendedPublic" {
    const epk = try ExtendedPrivateKey.fromAddress("tprv8ZgxMBicQKsPfCxvMSGLjZegGFnZn9VZfVdsnEbuzTGdS9aZjvaYpyh7NsxsrAc8LsRQZ2EYaCfkvwNpas8cKUBbptDzadY7c3hUi8i33XJ".*);

    const keypath = try KeyPath(4).fromStr("84'/1'/0'/0");
    const r = try deriveChildFromKeyPath(ExtendedPrivateKey, epk, 4, keypath);

    try std.testing.expectEqualStrings("ef3b8a82492a138ca4e39f6d508ec858e60dbfac64a143b021687aa42897682c", &try utils.bytesToHex(64, &r.privatekey));
    try std.testing.expectEqualStrings("da50dba459aa9adcb6410bba999e5a6827d583d100efea52ede417a767729c70", &try utils.bytesToHex(64, &r.chaincode));
}
