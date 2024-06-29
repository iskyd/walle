const std = @import("std");
const math = std.math;
const unicode = std.unicode;
const base58 = @import("base58");
const Ripemd160 = @import("crypto").Ripemd160;

pub const DecodedCompactSize = struct {
    totalBytes: u8,
    n: u64,
};

pub const EncodedCompactSize = struct {
    compactSizeByte: u8,
    totalBytes: u8,
    n: u64,
};

pub fn intToHexStr(comptime T: type, data: T, buffer: []u8) !void {
    // Number of characters to represent data in hex
    // log16(data) + 1
    const n: usize = if (data == 0) 1 else @intCast(math.log(T, 16, data) + 1);
    const missing: usize = @intCast(buffer.len - n);
    for (0..missing) |i| {
        buffer[i] = '0';
    }
    _ = try std.fmt.bufPrint(buffer[missing..], "{x}", .{data});
}

pub fn toBase58(buffer: []u8, bytes: []const u8) !void {
    const encoder = base58.Encoder.init(.{});
    _ = try encoder.encode(bytes, buffer);
}

pub fn toBase58Allocator(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const encoder = base58.Encoder.init(.{});
    return try encoder.encodeAlloc(allocator, bytes);
}

pub fn fromBase58(encoded: []const u8, buffer: []u8) !void {
    const decoder = base58.Decoder.init(.{});
    _ = try decoder.decode(encoded, buffer);
}

pub fn calculateChecksum(bytes: []const u8) [4]u8 {
    var buffer: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &buffer, .{});
    std.crypto.hash.sha2.Sha256.hash(&buffer, &buffer, .{});
    return buffer[0..4].*;
}

pub fn verifyChecksum(bytes: []const u8, checksum: [4]u8) bool {
    var buffer: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &buffer, .{});
    std.crypto.hash.sha2.Sha256.hash(&buffer, &buffer, .{});

    return std.mem.eql(u8, buffer[0..4], checksum[0..4]);
}

pub fn debugPrintBytes(comptime len: u32, bytes: []const u8) void {
    var buf: [len]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{x}", .{std.fmt.fmtSliceHexLower(bytes)}) catch unreachable;
    std.debug.print("DEBUG PRINT BYTES: {s}\n", .{buf});
}

pub fn doubleSha256(bytes: []const u8) [32]u8 {
    var buffer: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &buffer, .{});
    std.crypto.hash.sha2.Sha256.hash(&buffer, &buffer, .{});
    return buffer;
}

pub fn hash160(bytes: []const u8) [20]u8 {
    var hashed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hashed, .{});
    const r = Ripemd160.hash(&hashed);
    return r.bytes;
}

pub fn encodeutf8(in: []const u8, buffer: []u8) !u16 {
    const v = try unicode.Utf8View.init(in);
    var it = v.iterator();
    var cur: u16 = 0;
    while (it.nextCodepoint()) |codepoint| {
        var b: [4]u8 = undefined;
        const len: u16 = @as(u16, try unicode.utf8Encode(codepoint, &b));
        @memcpy(buffer[cur .. cur + len], b[0..len]);
        cur += len;
    }
    return cur;
}

pub fn decodeCompactSize(v: []u8) DecodedCompactSize {
    return switch (v[0]) {
        0...252 => DecodedCompactSize{ .totalBytes = 1, .n = v[0] },
        253 => {
            const n = std.mem.readInt(u16, v[1..3], .big);
            return DecodedCompactSize{ .totalBytes = 3, .n = n };
        },
        254 => {
            const n = std.mem.readInt(u32, v[1..5], .big);
            return DecodedCompactSize{ .totalBytes = 5, .n = n };
        },
        255 => {
            const n = std.mem.readInt(u64, v[1..9], .big);
            return DecodedCompactSize{ .totalBytes = 9, .n = n };
        },
    };
}

pub fn encodeCompactSize(n: u64) EncodedCompactSize {
    return switch (n) {
        0...252 => EncodedCompactSize{ .compactSizeByte = @intCast(n), .totalBytes = 0, .n = n },
        253...65535 => EncodedCompactSize{ .compactSizeByte = 253, .totalBytes = 2, .n = n },
        65536...4294967295 => EncodedCompactSize{ .compactSizeByte = 254, .totalBytes = 4, .n = n },
        4294967296...18446744073709551615 => EncodedCompactSize{ .compactSizeByte = 255, .totalBytes = 8, .n = n },
    };
}

test "intToHexStr" {
    var buffer: [8]u8 = undefined;
    try intToHexStr(u8, 150, &buffer);
    try std.testing.expectEqualSlices(u8, buffer[0..], "00000096");
    try intToHexStr(u32, 4294967295, &buffer);
    try std.testing.expectEqualSlices(u8, buffer[0..], "ffffffff");

    var buffer2: [8]u8 = undefined;
    try intToHexStr(u8, 0, &buffer2);
    try std.testing.expectEqualSlices(u8, buffer2[0..], "00000000");
}

test "toBase58" {
    const str = "00f57f296d748bb310dc0512b28231e8ebd62454557d5edaef".*;
    var b: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, &str);
    var base58_address: [34]u8 = undefined;
    _ = try toBase58(&base58_address, &b);
    try std.testing.expectEqualSlices(u8, base58_address[0..], "1PP4tMi6tep8qo8NwUDRaNw5cdiDVZYEnJ");
}

test "hash160" {
    var str = "03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5".*;
    var bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &str);
    const r = hash160(bytes[0..]);
    var rstr: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&rstr, "{x}", .{std.fmt.fmtSliceHexLower(&r)});
    try std.testing.expectEqualStrings("286fd267876fb1a24b8fe798edbc6dc6d5e2ea5b", &rstr);
}
