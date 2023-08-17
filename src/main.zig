const std = @import("std");
const bip39 = @import("bip39/bip39.zig");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");

    // const ent: u16 = 256; // Entropy length in bits
    var entropy: [32]u8 = undefined; // 256/8
    bip39.generateEntropy(&entropy);
    const checksum = bip39.generateChecksum(&entropy);
    const u_entropy = std.mem.readIntBig(u264, &(entropy ++ checksum));
    std.debug.print("Entropy: {d}\n", .{u_entropy});

    var buffer: [24][]u8 = undefined;
    try bip39.generateMnemonic(&buffer, u_entropy, wordlist, allocator);
    wordlist.deinit();
    defer for (buffer) |word| allocator.free(word);

    for (buffer) |word| {
        std.debug.print("{s}\n", .{word});
    }
}
