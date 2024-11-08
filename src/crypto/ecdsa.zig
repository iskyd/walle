const std = @import("std");
const rand = std.crypto.random;
const modinv = @import("math.zig").modinv;
const math = std.math;
const crypto = @import("crypto.zig");
const is_test = @import("builtin").is_test;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

fn intToHexStr(comptime T: type, data: T, buffer: []u8) !void {
    // Number of characters to represent data in hex
    // log16(data) + 1
    const n: usize = if (data == 0) 1 else @intCast(math.log(T, 16, data) + 1);
    const missing: usize = @intCast(buffer.len - n);
    for (0..missing) |i| {
        buffer[i] = '0';
    }
    _ = try std.fmt.bufPrint(buffer[missing..], "{x}", .{data});
}

pub const Signature = struct {
    s: u256,
    r: u256,

    // Memory ownership to the caller
    // Return hex str
    pub fn derEncode(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        var rh: [64]u8 = undefined;
        try intToHexStr(u256, self.r, &rh);
        var sh: [64]u8 = undefined;
        try intToHexStr(u256, self.s, &sh);

        var cap: usize = 70;
        var rlen: usize = 20;
        if ((self.r >> 248) & 0xFF > 127) { // If the first byte is > 0x7F we need to prepend 0x00
            cap = 71;
            rlen = 21;
        }

        const buffer = try allocator.alloc(u8, cap * 2);
        if (cap <= 70) {
            _ = try std.fmt.bufPrint(buffer, "30{d}02{d}{s}0220{s}", .{ 24 + rlen, rlen, rh, sh });
        } else {
            _ = try std.fmt.bufPrint(buffer, "30{d}02{d}00{s}0220{s}", .{ 24 + rlen, rlen, rh, sh });
        }
        return buffer;
    }
};

// pk is the private key
// z is the hash of the msg we want to sign
// nonce is used in tests to recreate deterministic signature.
pub fn sign(pk: [32]u8, z: [32]u8, comptime nonce_fn: fn (pk: [32]u8, z: [32]u8) u256) Signature {
    const n = crypto.secp256k1_number_of_points;
    while (true) {
        const k: u256 = nonce_fn(pk, z);
        var p = crypto.Secp256k1Point{ .x = crypto.secp256k1_base_point.x, .y = crypto.secp256k1_base_point.y };
        p.multiply(k);
        const r = @mod(p.x, n);
        if (r == 0) {
            continue;
        }
        const uz = std.mem.readInt(u256, &z, .big);
        const d = std.mem.readInt(u256, &pk, .big);
        const invk = modinv(i1024, k, n);
        const s: u256 = @intCast(@mod(@as(i1024, (uz + (@as(i1024, r) * d))) * invk, n));
        if (s == 0) {
            continue;
        }
        const low_s = if (s > crypto.secp256k1_number_of_points / 2) crypto.secp256k1_number_of_points - s else s;

        return Signature{ .r = r, .s = low_s };
    }

    unreachable;
}

// The original implementation can be found here: https://github.com/Raiden1411/zabi/blob/main/src/crypto/Signer.zig#L192
// Thanks Raiden1411
pub fn nonceFnRfc6979(pk: [32]u8, z: [32]u8) u256 {
    // We already ask for the hashed message.
    // message_hash == h1 and x == private_key.
    // Section 3.2.a
    var v: [33]u8 = undefined;
    var k: [32]u8 = undefined;
    var buffer: [97]u8 = undefined;

    // Section 3.2.b
    @memset(v[0..32], 0x01);
    v[32] = 0x00;

    // Section 3.2.c
    @memset(&k, 0x00);

    // Section 3.2.d
    @memcpy(buffer[0..32], v[0..32]);
    buffer[32] = 0x00;

    @memcpy(buffer[33..65], &pk);
    @memcpy(buffer[65..97], &z);

    HmacSha256.create(&k, &buffer, &k);

    // Section 3.2.e
    HmacSha256.create(v[0..32], v[0..32], &k);

    // Section 3.2.f
    @memcpy(buffer[0..32], v[0..32]);
    buffer[32] = 0x01;

    @memcpy(buffer[33..65], &pk);
    @memcpy(buffer[65..97], &z);
    HmacSha256.create(&k, &buffer, &k);

    // Section 3.2.g
    HmacSha256.create(v[0..32], v[0..32], &k);

    // Section 3.2.h
    HmacSha256.create(v[0..32], v[0..32], &k);

    while (true) {
        const k_int = std.mem.readInt(u256, v[0..32], .big);

        // K is within [1,q-1] and is in R value.
        // that is not 0 so we break here.
        if (k_int > 0 and k_int < crypto.secp256k1_number_of_points) {
            break;
        }

        // Keep generating until we found a valid K.
        HmacSha256.create(&k, v[0..], &k);
        HmacSha256.create(v[0..32], v[0..32], &k);
    }

    const n = std.mem.readInt(u256, v[0..32], .big);

    std.debug.print("calculated nonce = {d}\n", .{n});
    return n;
}

fn nonceFn123456789(pk: [32]u8, z: [32]u8) u256 {
    _ = pk;
    _ = z;
    return 123456789;
}

test "sign" {
    var buffer: [32]u8 = undefined;
    rand.bytes(&buffer);
    var bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&buffer, &bytes, .{});

    var pk: [32]u8 = undefined;
    rand.bytes(&pk);
    var pkhex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&pkhex, "{x}", .{std.fmt.fmtSliceHexLower(&bytes)}) catch unreachable;
    const signature = sign(pk, bytes, nonceFnRfc6979);

    try std.testing.expectEqual(true, signature.s >= 1);
    try std.testing.expectEqual(true, signature.r >= 1);
    try std.testing.expectEqual(true, signature.s <= crypto.secp256k1_number_of_points - 1);
    try std.testing.expectEqual(true, signature.r <= crypto.secp256k1_number_of_points - 1);

    const uz = std.mem.readInt(u256, &bytes, .big); // Message
    const upk = std.mem.readInt(u256, &pk, .big); // private key
    var Q = crypto.Secp256k1Point{ .x = crypto.secp256k1_base_point.x, .y = crypto.secp256k1_base_point.y };
    Q.multiply(upk); // public key

    const w = modinv(i1024, signature.s, crypto.secp256k1_number_of_points);

    const uu1: u256 = @intCast(@mod(uz * w, crypto.secp256k1_number_of_points));
    const uu2: u256 = @intCast(@mod(signature.r * w, crypto.secp256k1_number_of_points));

    var p1 = crypto.Secp256k1Point{ .x = crypto.secp256k1_base_point.x, .y = crypto.secp256k1_base_point.y };
    p1.multiply(uu1);
    var p2 = crypto.Secp256k1Point{ .x = Q.x, .y = Q.y };
    p2.multiply(uu2);
    p1.add(p2);
    try std.testing.expectEqual(@mod(p1.x, crypto.secp256k1_number_of_points), signature.r);
}

test "signWithDeterministicNonce" {
    const msghex = "d7b60220e1b9b2c1ab40845118baf515203f7b6f0ad83cbb68d3c89b5b3098a6";
    const privkeyhex = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f";
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, privkeyhex);
    var msg: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, msghex);

    const signature = sign(pk, msg, nonceFn123456789);
    try std.testing.expectEqual(4051293998585674784991639592782214972820158391371785981004352359465450369227, signature.r);
    try std.testing.expectEqual(22928756034338380041288899807245402174768928418361705349511346173579327129676, signature.s);
}

test "derEncode" {
    const allocator = std.testing.allocator;
    const signature = Signature{ .r = 60814256026707795035851733563580772451123242639235623828001822966996257085604, .s = 42543829508311938641100165987203410741729026897852222254335630893556193035246 };
    const serialized = try signature.derEncode(allocator);
    defer allocator.free(serialized);
    const expected = "30450221008673a62d0995c213e1b1455f3fbe66a8774f6ad2cdeebbdf9148c05cadaa18a402205e0ef444dc3b15dc93b25046c62b0bd8dea1463f0dd3df7b6dbea067b09403ee";
    try std.testing.expectEqualStrings(expected, serialized);
    try std.testing.expectEqual(signature.r, 60814256026707795035851733563580772451123242639235623828001822966996257085604);
    try std.testing.expectEqual(signature.s, 42543829508311938641100165987203410741729026897852222254335630893556193035246);

    const signature2 = Signature{ .r = 20563619043091547917171744686276600212876833865692707756359368710575856337166, .s = 53911059558236206164581555165446301142462550061465543326712028582562493425622 };
    const serialized2 = try signature2.derEncode(allocator);
    defer allocator.free(serialized2);
    const expected2 = "304402202d76988e59ac0d668d7e93ad176dc2b8a108e5f92a3ddc3b88afd448e394c10e02207730941108ec58665d78640fcfbbbe06b241b9899ebe85965728ba2aa110e7d6";
    try std.testing.expectEqualStrings(expected2, serialized2);
    try std.testing.expectEqual(signature2.r, 20563619043091547917171744686276600212876833865692707756359368710575856337166);
    try std.testing.expectEqual(signature2.s, 53911059558236206164581555165446301142462550061465543326712028582562493425622);
}

test "generateNonceRfc6979" {
    const msghex = "d7b60220e1b9b2c1ab40845118baf515203f7b6f0ad83cbb68d3c89b5b3098a6";
    const privkeyhex = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f";
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, privkeyhex);
    var msg: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, msghex);

    const s1 = sign(pk, msg, nonceFnRfc6979);
    const s2 = sign(pk, msg, nonceFnRfc6979);
    try std.testing.expectEqual(s1.r, s2.r);
    try std.testing.expectEqual(s1.s, s2.s);
}
