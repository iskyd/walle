const std = @import("std");
const bip39 = @import("bip39/bip39.zig");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");

    var buffer: [24][]u8 = undefined;
    try bip39.generateMnemonic(&buffer, wordlist, allocator);
    wordlist.deinit();
    defer for (buffer) |word| allocator.free(word);

    for (buffer) |word| {
        std.debug.print("{s}\n", .{word});
    }
}
