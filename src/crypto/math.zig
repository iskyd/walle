const std = @import("std");

pub fn powmod(base: u256, exponent: u256, modulus: u256) u256 {
    var result: u256 = 1;
    var b: u256 = base;
    var e: u256 = exponent;
    while (e > 0) {
        if (@mod(e, 2) == 1) {
            b = @mod(b, modulus);
            result = @intCast(@mod(@as(u512, result) * b, modulus));
        }
        e = e >> 1;
        b = @mod(b, modulus);
        b = @intCast(@mod(@as(u512, b) * b, modulus));
        b = @mod(b, modulus);
    }
    return @intCast(result);
}

pub fn modinv(comptime T: type, _a: T, _m: T) T {
    var prevy: T = 0;
    var y: T = 1;
    var a: T = _a;
    var m: T = _m;

    if (a < 0) {
        a = @mod(a, m);
    }

    while (a > 1) {
        const q: T = @divFloor(m, a);
        const tmp_y = y;
        y = prevy - q * y;
        prevy = tmp_y;
        const tmp_a = a;
        a = @mod(m, a);
        m = tmp_a;
    }

    return y;
}

test "modinv" {
    try std.testing.expectEqual(modinv(i32, 15, 26), 7);
    try std.testing.expectEqual(modinv(i32, 26, 15), -4);
}

test "powmod" {
    try std.testing.expectEqual(powmod(2, 3, 5), 3);
    try std.testing.expectEqual(powmod(2, 3, 15), 8);
    try std.testing.expectEqual(powmod(49001864144210927699347487322952736965656659160088668794646536877889645920220, 28948022309329048855892746252171976963317496166410141009864396001977208667916, 115792089237316195423570985008687907853269984665640564039457584007908834671663), 45693184488322129798941181810986065111841230370876872108753010948356676618535);
}
