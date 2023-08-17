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

pub fn generateMnemonic(buffer: [][]const u8, wordlist: WordList, allocator: std.mem.Allocator) !void {
    const rand = std.crypto.random;
    const ent: u16 = 256; // Entropy length in bits
    var init: [ent / 8]u8 = undefined;
    rand.bytes(&init);
    var checksum: [ent / 8]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&init, &checksum, .{});
    const entropy = init ++ checksum[0..1];
    const u_entropy = @as(u264, @bitCast(entropy.*));
    const mask: u64 = (1 << 11) - 1;

    for (0..24) |i| {
        const s = @as(u8, @intCast(i)) * @as(u9, @intCast(11));
        const bits = u_entropy >> s & mask;
        buffer[i] = try allocator.dupe(u8, wordlist.getWords()[@intCast(bits)]);
    }
}

test "wordlist" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/test.txt");
    defer wordlist.deinit();
    const words: [2048][]u8 = wordlist.getWords();
    try std.testing.expectEqualStrings(words[0], "Test");
}
