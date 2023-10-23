const std = @import("std");
const math = std.math;
const base58 = @import("base58");

pub fn intToHexStr(comptime T: type, data: T, buffer: []u8) !void {
    // Number of characters to represent data in hex
    // log16(data) + 1
    const n: u32 = @intCast(math.log(T, 16, data) + 1);
    const missing: u32 = @intCast(buffer.len - n);
    for (0..missing) |i| {
        buffer[i] = '0';
    }
    _ = try std.fmt.bufPrint(buffer[missing..], "{x}", .{data});
}

pub fn toBase58(buffer: []u8, bytes: []u8) !void {
    const encoder = base58.Encoder.init(.{});
    _ = try encoder.encode(bytes, buffer);
}

pub fn fromBase58(encoded: []u8, buffer: []u8) !void {
    const decoder = base58.Decoder.init(.{});
    _ = try decoder.decode(encoded, buffer);
}

pub fn verifyChecksum(bytes: []u8, checksum: [4]u8) !bool {
    var buffer: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &buffer, .{});
    std.crypto.hash.sha2.Sha256.hash(&buffer, &buffer, .{});

    return std.mem.eql(u8, buffer[0..4], checksum[0..4]);
}

test "intToHexStr" {
    var buffer: [8]u8 = undefined;
    try intToHexStr(u8, 150, &buffer);
    try std.testing.expectEqualSlices(u8, buffer[0..], "00000096");
    try intToHexStr(u32, 4294967295, &buffer);
    try std.testing.expectEqualSlices(u8, buffer[0..], "ffffffff");
}

test "toBase58" {
    var str = "00f57f296d748bb310dc0512b28231e8ebd62454557d5edaef";
    var b: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, str);
    var base58_address: [34]u8 = undefined;
    _ = try toBase58(&base58_address, &b);
    try std.testing.expectEqualSlices(u8, base58_address[0..], "1PP4tMi6tep8qo8NwUDRaNw5cdiDVZYEnJ");
}
