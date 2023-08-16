const std = @import("std");
const bip39 = @import("bip39/bip39.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");
    defer wordlist.deinit();

    var buffer: [24]bip39.String = undefined;
    bip39.getMnemonic(&buffer, wordlist);

    for (buffer) |word| {
        std.debug.print("{s}\n", .{word});
    }
}
