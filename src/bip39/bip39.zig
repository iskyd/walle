const std = @import("std");

const String = []const u8;
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

pub fn getMnemonic(wordlist: WordList) []String {
    const words = wordlist.getWords();
    _ = words;
    var mnemonic: []String = undefined;
    for (0..24) |i| {
        _ = i;
        // Generate random number between 0 and 2048
        // Get word at index
        // Append to mnemonic

    }

    return mnemonic;
}

test "wordlist" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/test.txt");
    defer wordlist.deinit();
    const words: [2048]String = wordlist.getWords();
    try std.testing.expectEqualStrings(words[0], "Test");
}
