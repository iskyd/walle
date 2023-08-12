const std = @import("std");
const bip39 = @import("bip39/bip39.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");
    defer wordlist.deinit();
    const words = wordlist.getWords();
    std.debug.print("{s}\n", .{words[0]});
}
