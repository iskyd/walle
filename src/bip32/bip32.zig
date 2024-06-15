const std = @import("std");
const secp256k1 = @import("../secp256k1/secp256k1.zig");
const utils = @import("../utils.zig");
const math = std.math;
const ripemd = @import("../ripemd160/ripemd160.zig");
const assert = std.debug.assert;
const Network = @import("../const.zig").Network;
const script = @import("../script/script.zig");

const PRIVATE_KEY_ADDRESS_VERSION = [4]u8{ 0b00000100, 0b10001000, 0b10101101, 0b11100100 };
const PUBLIC_KEY_ADDRESS_VERSION = [4]u8{ 0b00000100, 0b10001000, 0b10110010, 0b00011110 };

pub const ExtendedPrivateKey = struct {
    privatekey: [32]u8, // Private Key
    chaincode: [32]u8, // Chain Code

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
    pub fn serialize(self: ExtendedPrivateKey, depth: u8, fingerprint: [4]u8, index: u32) [82]u8 {
        var indexBytes: [4]u8 = @bitCast(@byteSwap(index));
        var res: [82]u8 = undefined;
        @memcpy(res[0..4], &PRIVATE_KEY_ADDRESS_VERSION);
        res[4] = depth;
        @memcpy(res[5..9], &fingerprint);
        @memcpy(res[9..13], &indexBytes);
        @memcpy(res[13..45], &self.chaincode);
        res[45] = 0;
        @memcpy(res[46..78], &self.privatekey);
        const checksum = utils.calculateChecksum(res[0..78]);
        @memcpy(res[78..82], &checksum);

        return res;
    }

    pub fn address(self: ExtendedPrivateKey, depth: u8, fingerprint: [4]u8, index: u32) ![111]u8 {
        const serialized = self.serialize(depth, fingerprint, index);
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
    point: secp256k1.Point, // Public Key

    pub fn compress(self: PublicKey) ![33]u8 {
        var buffer: [66]u8 = undefined;
        if (@mod(self.point.y, 2) == 0) {
            _ = try std.fmt.bufPrint(&buffer, "02{x}", .{self.point.x});
        } else {
            _ = try std.fmt.bufPrint(&buffer, "03{x}", .{self.point.x});
        }
        const v: u264 = try std.fmt.parseInt(u264, &buffer, 16);
        const compressed: [33]u8 = @bitCast(@byteSwap(v));
        return compressed;
    }

    pub fn toStrCompressed(self: PublicKey) ![66]u8 {
        const compressed: [33]u8 = try self.compress();
        var str: [66]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&compressed)});
        return str;
    }

    pub fn toStrUncompressed(self: PublicKey) ![130]u8 {
        var str: [130]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "04{x}{x}", .{ self.point.x, self.point.y });
        return str;
    }

    // return bytes
    pub fn toHash(self: PublicKey) ![20]u8 {
        // We use the compressed public key because P2WPKH only works with compressed public keys
        const str: [66]u8 = try self.toStrCompressed();
        var bytes: [33]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, &str);

        var hashed: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&bytes, &hashed, .{});

        const r = ripemd.Ripemd160.hash(&hashed);
        var rstr: [40]u8 = undefined;
        _ = try std.fmt.bufPrint(&rstr, "{x}", .{std.fmt.fmtSliceHexLower(r.bytes[0..])});
        var bytes_hashed: [20]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes_hashed, &rstr);

        var address: [20]u8 = undefined;
        @memcpy(address[0..20], bytes_hashed[0..20]);

        return address;
    }

    // return bytes.
    // It also adds prefix and checksum
    pub fn toCompleteHash(self: PublicKey, n: Network) ![25]u8 {
        const pkh = try self.toHash();
        var pkwithprefix: [42]u8 = undefined;
        _ = switch (n) {
            Network.MAINNET => try std.fmt.bufPrint(&pkwithprefix, "00{x}", .{std.fmt.fmtSliceHexLower(&pkh)}),
            else => _ = try std.fmt.bufPrint(&pkwithprefix, "6f{x}", .{std.fmt.fmtSliceHexLower(&pkh)}),
        };
        var b: [21]u8 = undefined;
        _ = try std.fmt.hexToBytes(&b, &pkwithprefix);

        const checksum = utils.calculateChecksum(&b);
        var addr: [25]u8 = undefined;
        @memcpy(addr[0..21], b[0..]);
        @memcpy(addr[21..25], checksum[0..4]);
        return addr;
    }

    pub fn fromStrCompressed(compressed: [66]u8) !PublicKey {
        const v = try std.fmt.parseInt(u264, &compressed, 16);
        const c: [33]u8 = @bitCast(@byteSwap(v));
        const p = try secp256k1.uncompress(c);
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

    pub fn serialize(self: ExtendedPublicKey, depth: u8, fingerprint: [4]u8, index: u32) ![82]u8 {
        var indexBytes: [4]u8 = @bitCast(@byteSwap(index));
        var res: [82]u8 = undefined;
        @memcpy(res[0..4], &PUBLIC_KEY_ADDRESS_VERSION);
        res[4] = depth;
        @memcpy(res[5..9], &fingerprint);
        @memcpy(res[9..13], &indexBytes);
        @memcpy(res[13..45], &self.chaincode);
        const compressed = try self.key.compress();
        @memcpy(res[45..78], &compressed);
        const checksum = utils.calculateChecksum(res[0..78]);
        @memcpy(res[78..82], &checksum);

        return res;
    }

    pub fn address(self: ExtendedPublicKey, depth: u8, fingerprint: [4]u8, index: u32) ![111]u8 {
        const serialized = try self.serialize(depth, fingerprint, index);
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
        var strcompressed: [66]u8 = undefined;
        _ = try std.fmt.bufPrint(&strcompressed, "{x}", .{std.fmt.fmtSliceHexLower(compressed[0..])});
        const pk = try PublicKey.fromStrCompressed(strcompressed);
        return ExtendedPublicKey{ .key = pk, .chaincode = chaincode };
    }
};

pub const WifPrivateKey = struct {
    key: [32]u8,
    net: [1]u8,
    suffix: [1]u8,

    pub fn fromPrivateKey(key: [32]u8, net: Network, compressed: bool) WifPrivateKey {
        const netslice: [1]u8 = switch (net) {
            Network.MAINNET => [1]u8{0b10000000},
            Network.TESTNET => [1]u8{0b11101111},
            else => unreachable,
        };

        const suffix = switch (compressed) {
            true => [1]u8{0b00000001},
            false => [1]u8{0b00000000},
        };

        return WifPrivateKey{
            .key = key,
            .net = netslice,
            .suffix = suffix,
        };
    }
};

pub fn generateExtendedMasterPrivateKey(seed: [64]u8) ExtendedPrivateKey {
    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &seed, "Bitcoin seed");

    return ExtendedPrivateKey{
        .privatekey = I[0..32].*,
        .chaincode = I[32..].*,
    };
}

pub fn generatePublicKey(pk: [32]u8) PublicKey {
    const k = std.mem.readInt(u256, &pk, .big);
    var public = secp256k1.Point{ .x = secp256k1.BASE_POINT.x, .y = secp256k1.BASE_POINT.y };
    public.multiply(k);

    return PublicKey{ .point = public };
}

pub fn deriveChildFromExtendedPrivateKey(epk: ExtendedPrivateKey, index: u32) !ExtendedPrivateKey {
    assert(index >= 0);
    assert(index <= 2147483647);
    const index_bytes: [4]u8 = @bitCast(index);
    const public = generatePublicKey(epk.privatekey);
    const compressed = try public.compress();
    const data: [37]u8 = compressed ++ index_bytes;

    // 74 = 37 * 2 (2 hex characters per byte)
    var buffer: [74]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer, "{x}", .{std.fmt.fmtSliceHexLower(&data)});
    var buffer_chaincode: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer_chaincode, "{x}", .{std.fmt.fmtSliceHexLower(&epk.chaincode)});

    var bytes: [37]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &buffer);
    var bytes_chaincode: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_chaincode, &buffer_chaincode);

    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &bytes, &bytes_chaincode);

    const private: u256 = std.mem.readInt(u256, &epk.privatekey, .big);
    const random: u256 = std.mem.readInt(u256, I[0..32], .big);
    const k: u256 = @intCast(@mod(@as(u512, private) + random, secp256k1.NUMBER_OF_POINTS));

    return ExtendedPrivateKey{
        .privatekey = @bitCast(@byteSwap(k)),
        .chaincode = I[32..].*,
    };
}

pub fn deriveChildFromExtendedPublicKey(pk: ExtendedPublicKey, index: u32) !ExtendedPublicKey {
    assert(index >= 0);
    assert(index <= 2147483647);
    const index_bytes: [4]u8 = @bitCast(index);
    const compressed: [33]u8 = try pk.key.compress();
    const data: [37]u8 = compressed ++ index_bytes;

    var buffer: [74]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer, "{x}", .{std.fmt.fmtSliceHexLower(&data)});
    var buffer_chaincode: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer_chaincode, "{x}", .{std.fmt.fmtSliceHexLower(&pk.chaincode)});

    var bytes: [37]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &buffer);
    var bytes_chaincode: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_chaincode, &buffer_chaincode);

    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &bytes, &bytes_chaincode);

    const random: u256 = std.mem.readInt(u256, I[0..32], .big);
    var point_hmac: secp256k1.Point = secp256k1.Point{ .x = secp256k1.BASE_POINT.x, .y = secp256k1.BASE_POINT.y };
    point_hmac.multiply(random);
    var public: secp256k1.Point = secp256k1.Point{ .x = pk.key.point.x, .y = pk.key.point.y };
    public.add(point_hmac);

    return ExtendedPublicKey{ .key = PublicKey{ .point = public }, .chaincode = I[32..].* };
}

pub fn deriveHardenedChild(epk: ExtendedPrivateKey, index: u32) !ExtendedPrivateKey {
    assert(index >= 2147483648);
    assert(index <= 4294967295);
    const prefix: [1]u8 = [1]u8{0b00000000};
    const index_bytes: [4]u8 = @bitCast(@byteSwap(index));
    const data: [37]u8 = prefix ++ epk.privatekey ++ index_bytes;

    var buffer: [74]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer, "{x}", .{std.fmt.fmtSliceHexLower(&data)});
    var buffer_chaincode: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&buffer_chaincode, "{x}", .{std.fmt.fmtSliceHexLower(&epk.chaincode)});

    var bytes: [37]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &buffer);
    var bytes_chaincode: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_chaincode, &buffer_chaincode);

    var I: [std.crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(I[0..], &bytes, &bytes_chaincode);

    const private: u256 = std.mem.readInt(u256, &epk.privatekey, .big);
    const random: u256 = std.mem.readInt(u256, I[0..32], .big);
    const k: u256 = @intCast(@mod(@as(u512, private) + random, secp256k1.NUMBER_OF_POINTS));

    return ExtendedPrivateKey{
        .privatekey = @bitCast(@byteSwap(k)),
        .chaincode = I[32..].*,
    };
}

pub fn toWif(wpk: WifPrivateKey) ![52]u8 {
    var extended: [34]u8 = undefined;
    @memcpy(extended[0..1], wpk.net[0..1]);
    @memcpy(extended[1..33], wpk.key[0..]);
    @memcpy(extended[33..], wpk.suffix[0..]);

    var str: [68]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&extended)});

    var bytes: [34]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &str);

    var checksum: [32]u8 = utils.doubleSha256(&bytes);

    var wif: [38]u8 = undefined;
    @memcpy(wif[0..34], bytes[0..]);
    @memcpy(wif[34..], checksum[0..4]);

    var wif_base58: [52]u8 = undefined;
    try utils.toBase58(&wif_base58, &wif);

    return wif_base58;
}

pub fn fromWif(wif: [52]u8) !WifPrivateKey {
    var decoded: [38]u8 = undefined;
    try utils.fromBase58(&wif, &decoded);

    const net: [1]u8 = [1]u8{decoded[0]};
    const key: [32]u8 = decoded[1..33].*;
    const suffix: [1]u8 = [1]u8{decoded[33]};
    const checksum: [4]u8 = decoded[34..38].*;

    var str: [68]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}{x}{x}", .{ std.fmt.fmtSliceHexLower(&net), std.fmt.fmtSliceHexLower(&key), std.fmt.fmtSliceHexLower(&suffix) });

    var bytes: [34]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &str);

    const ok = utils.verifyChecksum(&bytes, checksum);
    if (ok == false) {
        std.debug.print("Error: Invalid checksum\n", .{});
        return error.InvalidChecksum;
    }

    return WifPrivateKey{
        .key = key,
        .net = net,
        .suffix = suffix,
    };
}

test "generateExtendedMasterPrivateKey" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };

    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const str: [64]u8 = try epk.toStrPrivate();
    const str2: [64]u8 = try epk.toStrChainCode();

    try std.testing.expectEqualSlices(u8, "b21fcb414b4414e9bcf7ae647a79a4d29280f6b71cba204cb4dd3d6c6568d0fc", &str);
    try std.testing.expectEqualSlices(u8, "bbb5f26acee2e3713d43cf4e702f2b1ff8672afa9e0d5ac846196689e1d893d2", &str2);
}
//
test "generatePublicKey" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const pk = generatePublicKey(epk.privatekey);

    try std.testing.expectEqual(pk.point.x, 79027560793086286861659885563794118884743103107570705965389288630856279203871);
    try std.testing.expectEqual(pk.point.y, 70098904748994065624629803197701842741428754294763691930704573059552158053128);
}

test "deriveChildFromExtendedPrivateKey" {
    const seedhex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = generateExtendedMasterPrivateKey(seed);
    const child = try deriveChildFromExtendedPrivateKey(epk, 0);

    const expectedprivatekeyaddr = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt".*;
    const expectedprivate = try ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);
    try std.testing.expectEqualSlices(u8, &expectedprivate.privatekey, &child.privatekey);
}

test "deriveChildFromExtendedPublicKey" {
    const seedhex = "81a79e3c7df2fc3376b087b5d5db952eb3c29eaf958b73aaad4ebc9eedb29e55abd8880457171d73ee4adeeaa3950812e6d1d935202f4ecc4aa62d8974665bcf".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = generateExtendedMasterPrivateKey(seed);
    const public = generatePublicKey(epk.privatekey);
    const extendedpublic = ExtendedPublicKey{ .key = public, .chaincode = epk.chaincode };
    const extendedchild = try deriveChildFromExtendedPublicKey(extendedpublic, 0);
    const expectedPublicAddr = "xpub6812wt8cXaNNpj6dn1q7cYvhyyyYHAECx3Dx1vZYtJS9Ts5gz2BsmgBVxnbwg3g6vrZJSWJuBSmVSyyMwMKYRohB6WxCCnACY97JAF7AshB".*;
    const expectedpublic = try ExtendedPublicKey.fromAddress(expectedPublicAddr);

    try std.testing.expectEqual(extendedchild.key.point, expectedpublic.key.point);
    try std.testing.expectEqualSlices(u8, &extendedchild.chaincode, &expectedpublic.chaincode);
}

test "deriveHardenedChild" {
    const seedhex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = generateExtendedMasterPrivateKey(seed);
    const child = try deriveHardenedChild(epk, 2147483648); // 0'
    const expectedprivatekeyaddr = "xprv9vHkqa6NpjQMiZJLz4sFbVqYk7EXEUrWBd8drQZCp4furXS13egriq1pr2ncv2UBok3GifpitiQfp9kxNitz2RXbwtAo8hiv4CieaLTHyRL".*;
    const expectedprivate = try ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);

    try std.testing.expectEqualSlices(u8, &expectedprivate.privatekey, &child.privatekey);
}

test "toWif" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const wpk = WifPrivateKey.fromPrivateKey(epk.privatekey, Network.MAINNET, true);
    const wif = try toWif(wpk);
    try std.testing.expectEqualSlices(u8, "L3BxhCBNNLihRFeZVEa6846is2Qe5YHpvddiLb83aNyUDpGumiiq", &wif);
}

test "fromWif" {
    const str: [52]u8 = "L3BxhCBNNLihRFeZVEa6846is2Qe5YHpvddiLb83aNyUDpGumiiq".*;
    const wif = try fromWif(str);

    try std.testing.expectEqualSlices(u8, &[1]u8{0b10000000}, &wif.net);
    try std.testing.expectEqualSlices(u8, &[1]u8{0b00000001}, &wif.suffix);

    var keystr: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&keystr, "{x}", .{std.fmt.fmtSliceHexLower(&wif.key)});
    try std.testing.expectEqualSlices(u8, "b21fcb414b4414e9bcf7ae647a79a4d29280f6b71cba204cb4dd3d6c6568d0fc", &keystr);
}

test "pubKeyCompress" {
    const x = 79027560793086286861659885563794118884743103107570705965389288630856279203871;
    const y = 70098904748994065624629803197701842741428754294763691930704573059552158053128;
    const p = secp256k1.Point{ .x = x, .y = y };
    const pk = PublicKey{ .point = p };
    const compressed = try pk.compress();
    var compress_hex_str: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&compress_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&compressed)});
    try std.testing.expectEqualSlices(u8, &compress_hex_str, "02aeb803a9ace6dcc5f11d06e8f30e24186c904f463be84f303d15bb7d48d1201f");
}

test "toStrCompressed" {
    const x = 79027560793086286861659885563794118884743103107570705965389288630856279203871;
    const y = 70098904748994065624629803197701842741428754294763691930704573059552158053128;
    const p = secp256k1.Point{ .x = x, .y = y };
    const pk = PublicKey{ .point = p };
    const str = try pk.toStrCompressed();
    try std.testing.expectEqualSlices(u8, &str, "02aeb803a9ace6dcc5f11d06e8f30e24186c904f463be84f303d15bb7d48d1201f");
}

test "toStrUncompressed" {
    const x = 79027560793086286861659885563794118884743103107570705965389288630856279203871;
    const y = 70098904748994065624629803197701842741428754294763691930704573059552158053128;
    const p = secp256k1.Point{ .x = x, .y = y };
    const pk = PublicKey{ .point = p };
    const str = try pk.toStrUncompressed();
    try std.testing.expectEqualSlices(u8, &str, "04aeb803a9ace6dcc5f11d06e8f30e24186c904f463be84f303d15bb7d48d1201f9afa92f683a2ed207bcba8f4c3354190cb5eb416802016c5c432b22a00c67308");
}

test "toHash" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const pk = generatePublicKey(epk.privatekey);
    const address: [20]u8 = try pk.toHash();
    var str: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&address)});
    try std.testing.expectEqualSlices(u8, "f57f296d748bb310dc0512b28231e8ebd6245455", &str);

    const pubkeystr = "02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277".*;
    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    const c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try secp256k1.uncompress(c);
    const pk1 = PublicKey{ .point = p };
    const addr = try pk1.toHash();
    var s: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&s, "{x}", .{std.fmt.fmtSliceHexLower(&addr)});
    try std.testing.expectEqualSlices(u8, "1e51fcdc14be9a148bb0aaec9197eb47c83776fb", s[0..]);

    const pubkeystr2 = "03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31".*;
    const v2 = try std.fmt.parseInt(u264, &pubkeystr2, 16);
    const c2: [33]u8 = @bitCast(@byteSwap(v2));
    const p2 = try secp256k1.uncompress(c2);
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
    const serialized = epk.serialize(5, fingerprint, 14);
    var str: [164]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&serialized)});

    var expected = "0488ade40559b172d80000000e7d44cde0cdd0423cfa61fc4ac0e371fa6eba38e6fe5081eca5fcf4ae934a26d3001205ace2508d2b0376a6826c6b2a0f4573fb926a432d4ae3f9e6976fc566afd53ed3f8fe".*;
    try std.testing.expectEqualStrings(&expected, &str);
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
    const base58 = try epk.address(5, fingerprint, 14);

    var expected = "xprvA35vcVznDBo4f5dPwVtqdFoqxXrADVyad5xb6Hk37pcExHa8z8xK9761jiWDkyAudCPVCbdqko4k2EUjSVcVz1xxkggfkULjGzWdnzG7zKf".*;
    try std.testing.expectEqualStrings(&expected, &base58);
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
}

test "serializePublicKey" {
    var pubkeystr = "0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302".*;
    var ccstr = "d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf".*;
    var cc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cc, &ccstr);

    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    const c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try secp256k1.uncompress(c);
    const pk = PublicKey{ .point = p };

    const epk = ExtendedPublicKey{ .key = pk, .chaincode = cc };
    var fingerprintstr = "024bd5de".*;
    var fingerprint: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fingerprint, &fingerprintstr);
    const serialized = try epk.serialize(3, fingerprint, 18);
    var str: [164]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&serialized)});

    var expected = "0488b21e03024bd5de00000012d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302c431f6fc".*;
    try std.testing.expectEqualStrings(&expected, &str);
}

test "extendedPublicKeyAddress" {
    var pubkeystr = "0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302".*;
    var ccstr = "d1ca94c25198ce7cd330f8b8c2c1cc2a56a042837711a4143bef371934aa3bdf".*;
    var cc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cc, &ccstr);

    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    const c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try secp256k1.uncompress(c);
    const pk = PublicKey{ .point = p };

    const epk = ExtendedPublicKey{ .key = pk, .chaincode = cc };
    var fingerprintstr = "024bd5de".*;
    var fingerprint: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fingerprint, &fingerprintstr);
    const base58 = try epk.address(3, fingerprint, 18);

    const expected = "xpub6BfkKmAArYaLxNUQE8d87QuhPwipqTykFJLMND7NgihE9GSo317PjazsLo2Ex2JmDmwXGyiB5K5nyx6n3rpW5oJc8TXXvEex6ipo9rrCUWw".*;
    try std.testing.expectEqualStrings(&expected, &base58);
}

test "extendedPublicKeyFromAddress" {
    const addr = "xpub6BfkKmAArYaLxNUQE8d87QuhPwipqTykFJLMND7NgihE9GSo317PjazsLo2Ex2JmDmwXGyiB5K5nyx6n3rpW5oJc8TXXvEex6ipo9rrCUWw".*;
    const expected = "0262e67fa65a016bd71defb6a161b3a0068a1e4582948654b30a77e1624ced3302".*;
    const epk = try ExtendedPublicKey.fromAddress(addr);
    const strcompressed = try epk.key.toStrCompressed();
    try std.testing.expectEqualStrings(&expected, &strcompressed);
}

test "bip44Dervivation" {
    const seedhex = "81a79e3c7df2fc3376b087b5d5db952eb3c29eaf958b73aaad4ebc9eedb29e55abd8880457171d73ee4adeeaa3950812e6d1d935202f4ecc4aa62d8974665bcf".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = generateExtendedMasterPrivateKey(seed);
    const child = try deriveHardenedChild(epk, 2147483648 + 44); // 44'
    const child2 = try deriveHardenedChild(child, 2147483648);
    const child3 = try deriveHardenedChild(child2, 2147483648);
    const expectedprivatekeyaddr = "xprv9xibuu9WWWf3fYnGiKY6sqk8rvNHCZMjbLLDcF2Qj8N3WcNzw2AknNGapkd79mUuU2BwC5kvqcFuC5VAujGHBuT2gujogoMq1A4qDasdxVM".*;
    const expectedpublicaddr = "xpub6G3vxdEYuhYffVX9HjJrdDaQdeyG2bm2LCCM8FP7QcH5xtXkND1FPzEHYmWL9STdzZodqxyWBBXWV3BNRbJkhwMZBjZYmfwm1D5tVYwWfZ8".*;
    const expectedprivate = try ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);
    const expectedpublic = try ExtendedPublicKey.fromAddress(expectedpublicaddr);

    const public = generatePublicKey(child3.privatekey);
    const extendedpublic = ExtendedPublicKey{ .key = public, .chaincode = child3.chaincode };
    const child4 = try deriveChildFromExtendedPublicKey(extendedpublic, 0);
    const child5 = try deriveChildFromExtendedPublicKey(child4, 0);

    try std.testing.expectEqualSlices(u8, &expectedprivate.privatekey, &child3.privatekey);
    try std.testing.expectEqual(child5.key.point, expectedpublic.key.point);
}
