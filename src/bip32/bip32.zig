const std = @import("std");
const secp256k1 = @import("../secp256k1/secp256k1.zig");
const utils = @import("../utils.zig");
const math = std.math;
const ripemd = @import("../ripemd160/ripemd160.zig");
const assert = std.debug.assert;
const Network = @import("../const.zig").Network;

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

    pub fn format(self: ExtendedPrivateKey, actual_fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = actual_fmt;
        _ = options;

        const private = try self.toStrPrivate();
        const chaincode = try self.toStrChainCode();
        try writer.print("Private key: {s}\nChain Code: {s}\n", .{ private, chaincode });
    }
};

pub const ExtendedPublicKey = struct {
    publickey: secp256k1.Point, // Public Key
    chaincode: [32]u8, // Chain Code

    pub fn toStrCompressedPublic(self: ExtendedPublicKey) ![66]u8 {
        const str = try self.publickey.toStrCompressed();
        return str;
    }

    pub fn toStrUncompressedPublic(self: ExtendedPublicKey) ![130]u8 {
        const str = self.publickey.toStrUncompressed();
        return str;
    }

    pub fn toStrChainCode(self: ExtendedPublicKey) ![64]u8 {
        var str: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&self.chaincode)});
        return str;
    }

    pub fn format(self: ExtendedPublicKey, actual_fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = actual_fmt;
        _ = options;

        const public_uncompressed = try self.toStrUncompressedPublic();
        const chaincode = try self.toStrChainCode();
        try writer.print("Public uncompressed key: {s}\nChain Code: {s}\n", .{ public_uncompressed, chaincode });
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

pub fn generatePublicKey(pk: [32]u8) secp256k1.Point {
    const k = std.mem.readIntBig(u256, &pk);
    var public = secp256k1.Point{ .x = secp256k1.BASE_POINT.x, .y = secp256k1.BASE_POINT.y };
    public.multiply(k);

    return public;
}

pub fn deriveAddress(public: secp256k1.Point) ![25]u8 {
    const str: [66]u8 = try public.toStrCompressed();
    var bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &str);

    var hashed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &hashed, .{});

    const r = ripemd.Ripemd160.hash(&hashed);
    var rstr: [42]u8 = undefined;
    _ = try std.fmt.bufPrint(&rstr, "00{x}", .{std.fmt.fmtSliceHexLower(r.bytes[0..])});
    var bytes_hashed: [21]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_hashed, &rstr);

    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes_hashed, &checksum, .{});
    std.crypto.hash.sha2.Sha256.hash(&checksum, &checksum, .{});

    var address: [25]u8 = undefined;
    std.mem.copy(u8, address[0..21], bytes_hashed[0..21]);
    std.mem.copy(u8, address[21..], checksum[0..4]);

    return address;
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

    const private: u256 = std.mem.readIntBig(u256, &epk.privatekey);
    const random: u256 = std.mem.readIntBig(u256, I[0..32]);
    const k: u256 = @intCast(@mod(@as(u512, private) + random, secp256k1.NUMBER_OF_POINTS));

    return ExtendedPrivateKey{
        .privatekey = @bitCast(@byteSwap(k)),
        .chaincode = I[32..].*,
    };
}

pub fn deriveChildFromExtendedPublicKey(epk: ExtendedPublicKey, index: u32) !ExtendedPublicKey {
    assert(index >= 0);
    assert(index <= 2147483647);
    const index_bytes: [4]u8 = @bitCast(index);
    const compressed: [33]u8 = try epk.publickey.compress();
    const data: [37]u8 = compressed ++ index_bytes;

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

    const random: u256 = std.mem.readIntBig(u256, I[0..32]);
    var point_hmac: secp256k1.Point = secp256k1.Point{ .x = secp256k1.BASE_POINT.x, .y = secp256k1.BASE_POINT.y };
    point_hmac.multiply(random);
    var public: secp256k1.Point = secp256k1.Point{ .x = epk.publickey.x, .y = epk.publickey.y };
    public.add(point_hmac);

    return ExtendedPublicKey{
        .publickey = public,
        .chaincode = I[32..].*,
    };
}

pub fn deriveHardenedChild(epk: ExtendedPrivateKey, index: u32) !ExtendedPrivateKey {
    assert(index >= 2147483647);
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

    const private: u256 = std.mem.readIntBig(u256, &epk.privatekey);
    const random: u256 = std.mem.readIntBig(u256, I[0..32]);
    const k: u256 = @intCast(@mod(@as(u512, private) + random, secp256k1.NUMBER_OF_POINTS));

    return ExtendedPrivateKey{
        .privatekey = @bitCast(@byteSwap(k)),
        .chaincode = I[32..].*,
    };
}

pub fn toWif(wpk: WifPrivateKey) ![52]u8 {
    var extended: [34]u8 = undefined;
    std.mem.copy(u8, extended[0..], wpk.net[0..]);
    std.mem.copy(u8, extended[1..33], wpk.key[0..]);
    std.mem.copy(u8, extended[33..], wpk.suffix[0..]);

    var str: [68]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&extended)});

    var bytes: [34]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &str);

    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &checksum, .{});
    std.crypto.hash.sha2.Sha256.hash(&checksum, &checksum, .{});

    var wif: [38]u8 = undefined;
    std.mem.copy(u8, wif[0..34], bytes[0..]);
    std.mem.copy(u8, wif[34..], checksum[0..4]);

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

    const ok = utils.verifyChecksum(&bytes, checksum) catch |err| {
        std.debug.print("Error: {}\n", .{err});
        return error.InvalidChecksum;
    };
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

test "generatePublicKey" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const publickey: secp256k1.Point = generatePublicKey(epk.privatekey);

    try std.testing.expectEqual(publickey.x, 79027560793086286861659885563794118884743103107570705965389288630856279203871);
    try std.testing.expectEqual(publickey.y, 70098904748994065624629803197701842741428754294763691930704573059552158053128);
}

test "deriveAddress" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const publickey: secp256k1.Point = generatePublicKey(epk.privatekey);

    const address: [25]u8 = try deriveAddress(publickey);
    var str: [50]u8 = undefined;
    _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&address)});
    try std.testing.expectEqualSlices(u8, "00f57f296d748bb310dc0512b28231e8ebd62454557d5edaef", &str);
}

test "deriveChildFromExtendedPrivateKey" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);

    const child = try deriveChildFromExtendedPrivateKey(epk, 0);
    const str: [64]u8 = try child.toStrPrivate();
    const str2: [64]u8 = try child.toStrChainCode();

    try std.testing.expectEqualSlices(u8, "f13967de2c2ef9341f1336ab3cb6ff43c2b7b9166e23019ad216e0eba47c4d1d", &str);
    try std.testing.expectEqualSlices(u8, "a9a319ef6f8f4b0a04513ee111f7683c2d74be1fab6c01bd6c937b985aa60100", &str2);
}

test "deriveChildFromExtendedPublicKey" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const point: secp256k1.Point = generatePublicKey(epk.privatekey);
    const public: ExtendedPublicKey = ExtendedPublicKey{
        .publickey = point,
        .chaincode = epk.chaincode,
    };

    const child = try deriveChildFromExtendedPublicKey(public, 0);
    const str: [66]u8 = try child.toStrCompressedPublic();
    const str2: [64]u8 = try child.toStrChainCode();

    try std.testing.expectEqualSlices(u8, "03a11a24457b5ca09618ba5bf3c50529afda0d533599eaeff942e17894ffcbb1cf", &str);
    try std.testing.expectEqualSlices(u8, "a9a319ef6f8f4b0a04513ee111f7683c2d74be1fab6c01bd6c937b985aa60100", &str2);
}

test "deriveHardenedChild" {
    const seed = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    const epk: ExtendedPrivateKey = generateExtendedMasterPrivateKey(seed);
    const child = try deriveHardenedChild(epk, 2147483648);

    const str: [64]u8 = try child.toStrPrivate();
    const str2: [64]u8 = try child.toStrChainCode();
    try std.testing.expectEqualSlices(u8, "7f03ba6e108da0292e289c308dc716d12334c949384f1dfe9fb5b17389b63297", &str);
    try std.testing.expectEqualSlices(u8, "cc7b21c95d472561a2092d48c65a0d1e68b772a0e89db188fbe8cbd49dc78bdf", &str2);
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
