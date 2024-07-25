// Credit to https://github.com/The-King-of-Toasters/zig-bech32

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// Supported encodings
pub const Encoding = enum(u30) {
    bech32 = 1,
    bech32m = 0x2bc830a3,
};

/// TooLong
/// : source exceeds the 90 character limit.
///
/// MixedCase
/// : Both lower and uppercase characters were found in source.
///
/// NoSeperator
/// : The seperator "1" wasn't found in source.
///
/// BadChar
/// : A character in the string is outside the valid range.
///
/// HRPEmpty, HRPTooLong
/// : The HRP provided is empty, or larger than max_hrp_size.
///
/// ChecksumTooShort
/// : Less than six checksum digits found.
///
/// Invalid
/// : The checksum did not equal 1 at the end of decoding.
pub const Error = error{
    TooLong,
    MixedCase,
    NoSeperator,
    BadChar,
    HRPEmpty,
    HRPTooLong,
    InvalidPadding,
    ChecksumTooShort,
    Invalid,
};

pub const bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".*;
pub const max_string_size = 90;
/// Assuming no data.
pub const max_hrp_size = max_string_size - 1 - 6;
/// Assuming one-char HRP.
pub const max_data_len = max_string_size - 1 - 1 - 6;
pub const max_data_size = calcReduction(max_data_len);

/// Standard Bech32/Bech32m codecs, lowercase encoded strings.
pub const standard = struct {
    pub const Encoder = Bech32Encoder(bech32_charset, false);
    pub const Decoder = Bech32Decoder(bech32_charset);
};
/// Standard Bech32/Bech32m codecs, uppercase encoded strings.
pub const standard_uppercase = struct {
    pub const Encoder = Bech32Encoder(bech32_charset, true);
    pub const Decoder = Bech32Decoder(bech32_charset);
};

/// Calculates the space needed for expanding `data` to a sequence of u5s,
/// plus a padding bit if neeeded.
pub inline fn calcExpansion(len: usize) usize {
    const size: usize = len * 8;
    return @divTrunc(size, 5) + @as(u1, @bitCast((@rem(size, 5) > 0)));
}
/// The inverse of ::calcExpansion
pub inline fn calcReduction(len: usize) usize {
    return @divTrunc(len * 5, 8);
}

const Polymod = struct {
    const generator = [5]u30{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    val: u30 = 1,

    inline fn step(self: *Polymod, value: u8) void {
        const bitset = self.val >> 25;
        self.val = (self.val & std.math.maxInt(u25)) << 5;
        self.val ^= value;

        inline for (generator, 0..) |g, i| {
            if (bitset >> @as(u5, @truncate(i)) & 1 != 0)
                self.val ^= g;
        }
    }

    inline fn finish(self: *Polymod, encoding: Encoding) void {
        self.val ^= @intFromEnum(encoding);
    }
};

pub fn Bech32Encoder(comptime set: [32]u8, comptime uppercase: bool) type {
    return struct {
        const charset = if (!uppercase) set else blk: {
            const buf: [32]u8 = undefined;
            for (buf, 0..) |*c, i|
                c.* = std.ascii.toUpper(set[i]);

            break :blk buf;
        };
        const transform = if (!uppercase) std.ascii.toLower else std.ascii.toUpper;

        /// Calculates the space needed for the HRP and the data expansion.
        pub inline fn calcSize(hrp: []const u8, data: []const u8) usize {
            assert(hrp.len > 0 and hrp.len <= max_hrp_size);
            assert(data.len <= max_data_size);
            const result = hrp.len + 1 + calcExpansion(data.len) + 6;
            assert(result <= max_string_size);

            return result;
        }

        pub fn eightToFive(dest: []u5, source: []const u8) []const u5 {
            var acc: u12 = 0;
            var acc_len: u4 = 0;
            var i: usize = 0;

            for (source) |c| {
                acc = acc << 8 | c;
                acc_len += 8;
                while (acc_len >= 5) : (i += 1) {
                    acc_len -= 5;
                    dest[i] = @as(u5, @truncate(acc >> acc_len));
                }
            }
            if (acc_len > 0) {
                dest[i] = @as(u5, @truncate(acc << 5 - acc_len));
                i += 1;
            }

            return dest[0..i];
        }

        /// Encodes the HRP and data into a Bech32 or Bech32m string and stores the result
        /// in dest. The function contains a couple assertions that the caller
        /// should be aware of. The first are limit checks:
        ///
        /// - That the HRP doesn't exceed ::max_hrp_size.
        /// - That the expansion of data doesn't excede max_data_size. See
        ///   ::calcExpansion for how this is done.
        /// - That the full string doesn't exceed 90 chars. See
        ///   ::calcSize to compute this yourself.
        /// - That dest is large enough to hold the full string.
        ///
        /// Finally, the HRP is checked so that it doesn't contain invalid or
        /// mixed-case chars.
        pub fn encode(
            dest: []u8,
            hrp: []const u8,
            data: []const u8,
            version: u5,
            encoding: Encoding,
        ) []const u8 {
            assert(dest.len >= calcSize(hrp, data));

            var polymod = Polymod{};
            var upper = false;
            var lower = false;

            for (hrp, 0..) |c, i| {
                assert(c >= 33 and c <= 126);
                var lc = c;
                switch (c) {
                    'A'...'Z' => {
                        upper = true;
                        lc |= 0b00100000;
                    },
                    'a'...'z' => lower = true,
                    else => {},
                }
                polymod.step(lc >> 5);
                dest[i] = c;
            }
            assert(!(upper and lower));
            polymod.step(0);

            var i: usize = 0;
            while (i < hrp.len) : (i += 1) {
                polymod.step(dest[i] & 31);
                dest[i] = transform(dest[i]);
            }
            dest[i] = '1';
            i += 1;

            dest[i] = charset[version];
            polymod.step(version);
            i += 1;

            var expanded: [max_data_len]u5 = undefined;
            const exp = eightToFive(&expanded, data);
            for (exp) |c| {
                polymod.step(c);
                dest[i] = charset[c];
                i += 1;
            }

            for ([_]u0{0} ** 6) |_| polymod.step(0);
            polymod.finish(encoding);
            for ([6]u5{ 0, 1, 2, 3, 4, 5 }) |n| {
                const shift = 5 * (5 - n);
                dest[i] = charset[@as(u5, @truncate(polymod.val >> shift))];
                i += 1;
            }

            return dest[0..i];
        }
    };
}

pub const Result = struct { hrp: []const u8, data: []const u8, encoding: Encoding, version: u5 };
pub fn Bech32Decoder(comptime set: [32]u8) type {
    return struct {
        const reverse_charset = blk: {
            var buf = [_]?u5{null} ** 256;
            for (set, 0..) |c, i| {
                buf[c] = i;
                buf[std.ascii.toUpper(c)] = i;
            }

            break :blk buf;
        };

        pub fn calcSizeForSlice(source: []const u8) Error!usize {
            if (source.len > max_string_size) return Error.TooLong;
            const sep = std.mem.lastIndexOfScalar(u8, source, '1') orelse
                return Error.NoSeperator;
            if (sep == 0) return Error.HRPEmpty;
            if (sep > max_hrp_size) return Error.HRPTooLong;

            const data = if (source.len - (sep + 1) < 6)
                return Error.ChecksumTooShort
            else
                source[sep + 1 .. source.len - 6];

            return calcReduction(data.len);
        }

        pub fn fiveToEight(dest: []u8, source: []const u5) Error![]const u8 {
            var acc: u12 = 0;
            var acc_len: u4 = 0;
            var i: usize = 0;

            for (source) |c| {
                acc = acc << 5 | c;
                acc_len += 5;
                while (acc_len >= 8) : (i += 1) {
                    acc_len -= 8;
                    dest[i] = @as(u8, @truncate(acc >> acc_len));
                }
            }
            if (acc_len > 5 or @as(u8, @truncate(acc << 8 - acc_len)) != 0)
                return Error.InvalidPadding;

            return dest[0..i];
        }

        /// Decodes and validates a Bech32 or Bech32m string `source`, and writes any
        /// data found to to `dest`. The returned Result has three members:
        ///
        /// - `hrp`, which is a slice of `source`
        /// - `data`, which is a slice of `dest`.
        /// - `encoding`, is the encoding that was detected if valid
        pub fn decode(dest: []u8, source: []const u8) Error!Result {
            assert(dest.len >= try calcSizeForSlice(source));

            const sep = std.mem.lastIndexOfScalar(u8, source, '1') orelse unreachable;
            const hrp = source[0..sep];
            const version = source[sep + 1];
            const data = source[sep + 2 .. source.len - 6];
            const checksum = source[source.len - 6 ..];
            std.debug.print("hrp: {s}, data = {s}, version = {d}, checksum = {s}\n", .{ hrp, data, version, checksum });

            var pmod_buf: [max_hrp_size]u8 = undefined;
            var res = Result{ .hrp = hrp, .data = &[0]u8{}, .encoding = undefined, .version = 0 };
            var polymod = Polymod{};
            var upper = false;
            var lower = false;
            for (hrp, 0..) |c, i| {
                var lc = c;
                switch (c) {
                    0...32, 127...255 => return Error.BadChar,
                    'A'...'Z' => {
                        upper = true;
                        lc |= 0b00100000;
                    },
                    'a'...'z' => lower = true,
                    else => {},
                }
                polymod.step(lc >> 5);
                pmod_buf[i] = c;
            }
            if (upper and lower) return Error.MixedCase;

            polymod.step(0);
            for (pmod_buf[0..hrp.len]) |c| polymod.step(c & 31);

            const versionrev = reverse_charset[version] orelse return Error.BadChar;
            polymod.step(versionrev);
            res.version = @as(u5, @intCast(versionrev));

            var convert_buf: [max_data_len]u5 = undefined;
            for (data, 0..) |c, i| {
                if (std.ascii.isUpper(c)) upper = true;
                if (std.ascii.isLower(c)) lower = true;

                const rev = reverse_charset[c] orelse return Error.BadChar;
                polymod.step(rev);
                convert_buf[i] = rev;
            }
            if (upper and lower) return Error.MixedCase;

            res.data = try fiveToEight(dest, convert_buf[0..data.len]);

            for (checksum) |c| {
                if (std.ascii.isUpper(c)) upper = true;
                if (std.ascii.isLower(c)) lower = true;

                const rev = reverse_charset[c] orelse return Error.BadChar;
                polymod.step(rev);
            }
            if (upper and lower) return Error.MixedCase;

            res.encoding = switch (polymod.val) {
                @intFromEnum(Encoding.bech32) => Encoding.bech32,
                @intFromEnum(Encoding.bech32m) => Encoding.bech32m,
                else => return Error.Invalid,
            };

            return res;
        }
    };
}

test "bech32Encode" {
    const bip32 = @import("bip32.zig");

    var encoded_buf: [max_string_size]u8 = undefined;
    const str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".*;
    const public = try bip32.PublicKey.fromStrCompressed(str);
    const h = try public.toHash();

    var data: [21]u8 = undefined;
    data[0] = 0;
    @memcpy(data[1..], &h);

    const version: u5 = 0;
    const enc = standard.Encoder.encode(&encoded_buf, "bc", &h, version, .bech32);
    const expected = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    try std.testing.expectEqualStrings(expected, enc);
}

test "bech32Decode" {
    const enc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".*;
    var buffer: [20]u8 = undefined;
    const decoded = try standard.Decoder.decode(&buffer, &enc);
    const expectedhex = "751e76e8199196d454941c45d1b3a323f1433bd6".*;
    var expected: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, &expectedhex);

    try std.testing.expectEqualStrings("bc", decoded.hrp);
    try std.testing.expectEqual(decoded.version, 0);
    try std.testing.expectEqualSlices(u8, &expected, decoded.data);
}
