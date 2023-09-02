const std = @import("std");
const math = @import("std").math;

pub const PRIME_MODULUS = math.pow(u512, 2, 256) - math.pow(u256, 2, 32) - math.pow(u256, 2, 9) - math.pow(u256, 2, 8) - math.pow(u256, 2, 7) - math.pow(u256, 2, 6) - math.pow(u256, 2, 4) - 1;
pub const NUMBER_OF_POINTS = 115792089237316195423570985008687907852837564279074904382605163141518161494337;

pub const BASE_POINT = Point{ .x = 55066263022277343669578718895168534326250603453777594175500187360389116729240, .y = 32670510020758816978083085130507043184471273380659243275938904335757337482424 };

pub fn modinv(comptime T: type, _a: T, _m: T) T {
    var prevy: T = 0;
    var y: T = 1;
    var a: T = _a;
    var m: T = _m;
    while (a > 1) {
        var q: T = @divFloor(m, a);
        var tmp_y = y;
        y = prevy - q * y;
        prevy = tmp_y;
        var tmp_a = a;
        a = @mod(m, a);
        m = tmp_a;
    }

    return y;
}

pub const Point = struct {
    x: i512,
    y: i512,

    pub fn isEqual(self: *Point, other: Point) bool {
        return self.x == other.x and self.y == other.y;
    }

    pub fn double(self: *Point) void {
        // slope = (3x^2 + a) / 2y
        const slope = @mod(((3 * math.pow(i512, self.x, 2)) * modinv(i512, 2 * self.y, PRIME_MODULUS)), PRIME_MODULUS);

        const x = @mod(math.pow(i512, slope, 2) - (2 * self.x), PRIME_MODULUS);
        const y = @mod(slope * (self.x - x) - self.y, PRIME_MODULUS);

        self.x = x;
        self.y = y;
    }

    pub fn add(self: *Point, other: Point) void {
        if (self.isEqual(other)) {
            self.double();
        } else {
            const slope = @mod(((self.y - other.y) * modinv(i512, self.x - other.x, PRIME_MODULUS)), PRIME_MODULUS);
            const x = @mod(math.pow(i512, slope, 2) - self.x - other.x, PRIME_MODULUS);
            const y = @mod((slope * (self.x - x)) - self.x, PRIME_MODULUS);

            self.x = x;
            self.y = y;
        }
    }

    pub fn multiply(self: *Point, k: u32) void {
        var current = Point{ .x = self.x, .y = self.y };
        // std.math.log2(x) + 1 -> number of bits required to represent k
        // We need to discard the first bit
        // So we loop from 0 to log2(x)
        for (0..(std.math.log2(k))) |i| {
            var y = std.math.shr(u32, k, i) & 1;

            current.double();

            if (y == 1) {
                current.add(self.*);
            }
        }

        self.x = current.x;
        self.y = current.y;
    }
};

test "modinv" {
    try std.testing.expectEqual(modinv(i32, 15, 26), 7);
    try std.testing.expectEqual(modinv(i32, 26, 15), -4);
}

test "double" {
    var point = Point{ .x = 100, .y = 100 };
    point.double();
    try std.testing.expectEqual(
        point.x,
        22300,
    );
    try std.testing.expectEqual(
        point.y,
        115792089237316195423570985008687907853269984665640564039457584007908831341563,
    );
}

test "add" {
    var p1 = Point{ .x = 100, .y = 100 };
    var p2 = Point{ .x = 100, .y = 100 };
    p1.add(p2);
    try std.testing.expectEqual(p1.x, 22300);
    try std.testing.expectEqual(p1.y, 115792089237316195423570985008687907853269984665640564039457584007908831341563);

    p1 = Point{ .x = 100, .y = 100 };
    p2 = Point{ .x = 200, .y = 100 };
    p1.add(p2);
    try std.testing.expectEqual(p1.x, 115792089237316195423570985008687907853269984665640564039457584007908834671363);
    try std.testing.expectEqual(p1.y, 115792089237316195423570985008687907853269984665640564039457584007908834671563);
}

test "multiply" {
    var p1 = Point{ .x = 100, .y = 100 };
    p1.multiply(4);
    try std.testing.expectEqual(p1.x, 83958751277781481219825361860495351419593385084310388531537482022592812456470);
    try std.testing.expectEqual(p1.y, 91813336768047772184641076719937475964665959333856505805054708940286741019295);
}
