const std = @import("std");
const math = std.math;

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

test "intToHexStr" {
    var buffer: [8]u8 = undefined;
    try intToHexStr(u8, 150, &buffer);
    try std.testing.expectEqualSlices(u8, buffer[0..], "00000096");
    try intToHexStr(u32, 4294967295, &buffer);
    try std.testing.expectEqualSlices(u8, buffer[0..], "ffffffff");
}
