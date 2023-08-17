const std = @import("std");

const FILES = [1][]u8{"wordlist/english.txt"};
pub const MNEMONIC_LENGTH = 24;

pub const WordList = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    data: []const u8,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !WordList {
        const data = try std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize));
        return .{ .allocator = allocator, .path = path, .data = data };
    }

    pub fn deinit(self: WordList) void {
        self.allocator.free(self.data);
    }

    pub fn getWords(self: WordList) [2048][]const u8 {
        var lines = std.mem.split(u8, self.data, "\n");
        var words: [2048][]const u8 = undefined;
        var index: u16 = 0;

        while (lines.next()) |line| {
            words[index] = line;
            index += 1;
        }

        return words;
    }
};

pub fn generateEntropy(buffer: []u8) void {
    const rand = std.crypto.random;
    rand.bytes(buffer);
}

pub fn generateChecksum(data: []u8) [1]u8 {
    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &checksum, .{});
    return checksum[0..1].*;
}

pub fn generateMnemonic(buffer: [][]const u8, entropy: u264, wordlist: WordList, allocator: std.mem.Allocator) !void {
    const mask: u64 = (1 << 11) - 1;
    const words = wordlist.getWords();

    for (0..24) |i| {
        const s = @as(u8, @intCast(i)) * @as(u9, @intCast(11));
        const bits = entropy >> s & mask;
        buffer[23 - i] = try allocator.dupe(u8, words[@intCast(bits)]);
    }
}

// test "wordlist" {
//     const allocator = std.testing.allocator;
//     const wordlist = try WordList.init(allocator, "wordlist/test.txt");
//     defer wordlist.deinit();
//     const words: [2048][]u8 = wordlist.getWords();
//     try std.testing.expectEqualStrings(words[0], "Test");
// }

test "generateMnemonic" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/english.txt");
    defer wordlist.deinit();

    // Test 1
    var e1 = [32]u8{ 0b11110101, 0b10000101, 0b11000001, 0b00011010, 0b11101100, 0b01010010, 0b00001101, 0b10110101, 0b01111101, 0b11010011, 0b01010011, 0b11000110, 0b10010101, 0b01010100, 0b10110010, 0b00011010, 0b10001001, 0b10110010, 0b00001111, 0b10110000, 0b01100101, 0b00001001, 0b01100110, 0b11111010, 0b00001010, 0b10011101, 0b01101111, 0b01110100, 0b11111101, 0b10011000, 0b10011101, 0b10001111 };
    const c1 = generateChecksum(&e1);
    const ue1 = std.mem.readIntBig(u264, &(e1 ++ c1));
    var b1: [24][]u8 = undefined;
    try generateMnemonic(&b1, ue1, wordlist, allocator);
    defer for (b1) |word| allocator.free(word);

    const str1 = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    var expected1 = std.mem.split(u8, str1, " ");
    var i: u16 = 0;
    while (expected1.next()) |word| {
        try std.testing.expectEqualStrings(b1[i], word);
        i += 1;
    }

    // Test 2
    var e2 = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };
    const c2 = generateChecksum(&e2);
    const ue2 = std.mem.readIntBig(u264, &(e2 ++ c2));
    var b2: [24][]u8 = undefined;
    try generateMnemonic(&b2, ue2, wordlist, allocator);
    defer for (b2) |word| allocator.free(word);

    const str2 = "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform";
    var expected2 = std.mem.split(u8, str2, " ");
    i = 0;
    while (expected2.next()) |word| {
        try std.testing.expectEqualStrings(b2[i], word);
        i += 1;
    }
}
