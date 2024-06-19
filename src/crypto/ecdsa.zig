const std = @import("std");
const rand = std.crypto.random;
const modinv = @import("math.zig").modinv;
const Secp256k1NumberOfPoints = @import("secp256k1.zig").NUMBER_OF_POINTS;
const Secp256k1Point = @import("secp256k1.zig").Point;

pub const Signature = struct {
    s: u256,
    r: u256,
};

// pk is the private key
// z is the hash of the msg we want to sign
pub fn sign(pk: [32]u8, z: [32]u8) Signature {
    const n = Secp256k1NumberOfPoints;
    while (true) {
        const k = rand.intRangeAtMost(u256, 0, n - 1);
        var p = Secp256k1Point.getBasePoint();
        p.multiply(k);
        const r = @mod(p.x, n);
        if (r == 0) {
            continue;
        }
        const uz = std.mem.readInt(u256, &z, .big);
        const d = std.mem.readInt(u256, &pk, .big);
        const invk = modinv(i512, k, n);
        const s: u256 = @intCast(@mod(@as(i1024, (uz + (@as(i512, r) * d))) * invk, n));
        if (s == 0) {
            continue;
        }
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
    const signature = sign(pk, bytes);

    try std.testing.expectEqual(true, signature.s >= 1);
    try std.testing.expectEqual(true, signature.r >= 1);
    try std.testing.expectEqual(true, signature.s <= Secp256k1NumberOfPoints - 1);
    try std.testing.expectEqual(true, signature.r <= Secp256k1NumberOfPoints - 1);

    const uz = std.mem.readInt(u256, &bytes, .big); // Message
    const upk = std.mem.readInt(u256, &pk, .big); // private key
    var Q = Secp256k1Point.getBasePoint();
    Q.multiply(upk); // public key

    const w = modinv(i512, signature.s, Secp256k1NumberOfPoints);

    const uu1: u256 = @intCast(@mod(uz * w, Secp256k1NumberOfPoints));
    const uu2: u256 = @intCast(@mod(signature.r * w, Secp256k1NumberOfPoints));

    var p1 = Secp256k1Point.getBasePoint();
    p1.multiply(uu1);
    var p2 = Secp256k1Point{ .x = Q.x, .y = Q.y };
    p2.multiply(uu2);
    p1.add(p2);
    try std.testing.expectEqual(@mod(p1.x, Secp256k1NumberOfPoints), signature.r);
}
