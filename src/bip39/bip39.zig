const std = @import("std");
const ArrayList = std.ArrayList;

pub const String = []const u8;
const FILES = [1]String{"wordlist/english.txt"};
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

    pub fn getWords(self: WordList) [2048]String {
        var lines = std.mem.split(u8, self.data, "\n");
        var words: [2048]String = undefined;
        var index: u16 = 0;

        while (lines.next()) |line| {
            words[index] = line;
            index += 1;
        }

        return words;
    }
};

pub fn getMnemonic(buffer: []String, wordlist: WordList) void {
    const words = wordlist.getWords();
    const rand = std.crypto.random;
    for (0..24) |i| {
        const r = rand.intRangeAtMost(u16, 0, 2047);
        buffer[i] = words[r];
    }
}

test "wordlist" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/test.txt");
    defer wordlist.deinit();
    const words: [2048]String = wordlist.getWords();
    try std.testing.expectEqualStrings(words[0], "Test");
}
