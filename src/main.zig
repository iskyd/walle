const std = @import("std");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});
}
