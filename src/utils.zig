const std = @import("std");
const math = std.math;
const base58 = @import("base58");

pub fn intToHexStr(comptime T: type, data: T, buffer: []u8) !void {
    // Number of characters to represent data in hex
    // log16(data) + 1
    const nCharacters: u32 = @intCast(math.log(T, 16, data) + 1);
    const missingCharacters: u32 = @intCast(buffer.len - nCharacters);
    for (0..missingCharacters) |i| {
        buffer[i] = '0';
    }
    _ = try std.fmt.bufPrint(buffer[missingCharacters..], "{x}", .{data});
}

pub fn printSliceInHex(comptime T: type, slice: []u8) void {
    const v1: T = @as(*align(1) T, @ptrCast(slice.ptr)).*;
    const swapped: T = @byteSwap(v1);
    std.debug.print("{x}\n", .{swapped});
}

pub fn toBase58(buffer: []u8, str: []u8) !void {
    const base58_encoder = base58.Encoder.init(.{});
    _ = try base58_encoder.encode(str, buffer);
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
