const std = @import("std");
const rand = std.crypto.random;
const modinv = @import("math.zig").modinv;
const math = std.math;
const Secp256k1NumberOfPoints = @import("secp256k1.zig").NUMBER_OF_POINTS;
const Secp256k1Point = @import("secp256k1.zig").Point;
const is_test = @import("builtin").is_test;

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
// I don't like this parameter, using the same nonce can expose the private key, but I havent found any better solution
pub fn sign(pk: [32]u8, z: [32]u8, comptime nonce: ?u256) Signature {
    comptime if (nonce == null and is_test == false) {
        unreachable;
    };
    const n = Secp256k1NumberOfPoints;
    while (true) {
        const k: u256 = if (comptime nonce != null) nonce.? else rand.intRangeAtMost(u256, 0, n - 1);
        // const k = rand.intRangeAtMost(u256, 0, n - 1);
        var p = Secp256k1Point.getBasePoint();
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

        // TODO: always use the low s value
        return Signature{ .r = r, .s = s };
    }

    unreachable;
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
    const signature = sign(pk, bytes, null);

    try std.testing.expectEqual(true, signature.s >= 1);
    try std.testing.expectEqual(true, signature.r >= 1);
    try std.testing.expectEqual(true, signature.s <= Secp256k1NumberOfPoints - 1);
    try std.testing.expectEqual(true, signature.r <= Secp256k1NumberOfPoints - 1);

    const uz = std.mem.readInt(u256, &bytes, .big); // Message
    const upk = std.mem.readInt(u256, &pk, .big); // private key
    var Q = Secp256k1Point.getBasePoint();
    Q.multiply(upk); // public key

    const w = modinv(i1024, signature.s, Secp256k1NumberOfPoints);

    const uu1: u256 = @intCast(@mod(uz * w, Secp256k1NumberOfPoints));
    const uu2: u256 = @intCast(@mod(signature.r * w, Secp256k1NumberOfPoints));

    var p1 = Secp256k1Point.getBasePoint();
    p1.multiply(uu1);
    var p2 = Secp256k1Point{ .x = Q.x, .y = Q.y };
    p2.multiply(uu2);
    p1.add(p2);
    try std.testing.expectEqual(@mod(p1.x, Secp256k1NumberOfPoints), signature.r);
}

test "signWithDeterministicNonce" {
    const msghex = "d7b60220e1b9b2c1ab40845118baf515203f7b6f0ad83cbb68d3c89b5b3098a6";
    const privkeyhex = "7306f5092467981e66eff98b6b03bfe925922c5ecfaf14c4257ef18e81becf1f";
    const nonce: u256 = 123456789;
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, privkeyhex);
    var msg: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, msghex);

    const signature = sign(pk, msg, nonce);
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
