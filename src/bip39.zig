const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils.zig");
const builtin = @import("builtin");

const wordseparator = if (builtin.os.tag == .windows) "\r\n" else "\n";

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
        var lines = std.mem.split(u8, self.data, wordseparator);
        var words: [2048][]const u8 = undefined;
        var index: u16 = 0;

        while (lines.next()) |line| {
            words[index] = line;
            index += 1;
        }

        return words;
    }
};

pub fn generateEntropy(buffer: []u8, ent: u16) void {
    assert(ent % 32 == 0);
    assert(ent >= 128);
    assert(ent <= 256);
    const rand = std.crypto.random;
    rand.bytes(buffer);
}

pub fn generateMnemonic(allocator: std.mem.Allocator, entropy: []u8, wordlist: WordList, buffer: [][]const u8) !void {
    // Checksum is 1 bit for every 32 bits of entropy
    const checksum_bits: u8 = @intCast(entropy.len / 4);
    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entropy, &checksum, .{});
    var concatenated = try allocator.alloc(u8, entropy.len + checksum_bits);
    defer allocator.free(concatenated);
    @memcpy(concatenated[0..entropy.len], entropy);
    @memcpy(concatenated[entropy.len..], checksum[0..checksum_bits]);

    const u_entropy: u264 = @byteSwap(@as(*align(1) u264, @ptrCast(concatenated.ptr)).*);
    const mask: u64 = (1 << 11) - 1;
    const words = wordlist.getWords();

    for (0..buffer.len) |i| {
        // u_entropy is 264 bits
        const s = 264 - ((@as(u8, @intCast(i)) + 1) * @as(u9, @intCast(11)));
        const bits = u_entropy >> s & mask;
        buffer[i] = try allocator.dupe(u8, words[@intCast(bits)]);
    }
}

pub fn mnemonicToSeed(allocator: std.mem.Allocator, mnemonic: [][]u8, passphrase: []const u8, buffer: []u8) !void {
    var salt = try allocator.alloc(u8, "mnemonic".len + passphrase.len);
    defer allocator.free(salt);
    @memcpy(salt[0..8], "mnemonic");
    @memcpy(salt["mnemonic".len..], passphrase);

    const prf = std.crypto.auth.hmac.sha2.HmacSha512;

    const m: []u8 = try std.mem.join(allocator, " ", mnemonic);
    defer allocator.free(m);
    try std.crypto.pwhash.pbkdf2(buffer, m, salt, 2048, prf);
}

test "wordlist" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/test.txt");
    defer wordlist.deinit();
    const words: [2048][]const u8 = wordlist.getWords();
    try std.testing.expectEqualStrings("Test", words[0]);
}

test "generateMnemonic" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/english.txt");
    defer wordlist.deinit();

    // Test 1
    var e1 = [32]u8{ 0b11110101, 0b10000101, 0b11000001, 0b00011010, 0b11101100, 0b01010010, 0b00001101, 0b10110101, 0b01111101, 0b11010011, 0b01010011, 0b11000110, 0b10010101, 0b01010100, 0b10110010, 0b00011010, 0b10001001, 0b10110010, 0b00001111, 0b10110000, 0b01100101, 0b00001001, 0b01100110, 0b11111010, 0b00001010, 0b10011101, 0b01101111, 0b01110100, 0b11111101, 0b10011000, 0b10011101, 0b10001111 };
    var b1: [24][]u8 = undefined;
    try generateMnemonic(allocator, e1[0..32], wordlist, &b1);
    defer for (b1) |word| allocator.free(word);

    const str1 = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    var expected1 = std.mem.split(u8, str1, " ");
    var i: u16 = 0;
    while (expected1.next()) |word| {
        try std.testing.expectEqualStrings(word, b1[i]);
        i += 1;
    }

    // Test 2
    var e2 = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };
    var b2: [24][]u8 = undefined;
    try generateMnemonic(allocator, &e2, wordlist, &b2);
    defer for (b2) |word| allocator.free(word);

    const str2 = "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform";
    var expected2 = std.mem.split(u8, str2, " ");
    i = 0;
    while (expected2.next()) |word| {
        try std.testing.expectEqualStrings(word, b2[i]);
        i += 1;
    }

    // Test 3, 12 words mnemonic
    var e3 = [16]u8{ 0b10001011, 0b10010100, 0b11110100, 0b10111001, 0b01110110, 0b11101111, 0b00111101, 0b10000101, 0b10001000, 0b00111101, 0b00001110, 0b10001111, 0b00001000, 0b01110000, 0b11010001, 0b11110011 };
    var b3: [12][]u8 = undefined;
    try generateMnemonic(allocator, &e3, wordlist, &b3);
    defer for (b3) |word| allocator.free(word);
    const str3 = "merit police comic universe video security can peace monitor drum crucial traffic";
    var expected3 = std.mem.split(u8, str3, " ");
    i = 0;
    while (expected3.next()) |word| {
        try std.testing.expectEqualStrings(word, b3[i]);
        i += 1;
    }
}

test "mnemonicToSeed" {
    const allocator = std.testing.allocator;
    const wordlist = try WordList.init(allocator, "wordlist/english.txt");
    defer wordlist.deinit();

    // Test 1
    var e1 = [32]u8{ 0b11110101, 0b10000101, 0b11000001, 0b00011010, 0b11101100, 0b01010010, 0b00001101, 0b10110101, 0b01111101, 0b11010011, 0b01010011, 0b11000110, 0b10010101, 0b01010100, 0b10110010, 0b00011010, 0b10001001, 0b10110010, 0b00001111, 0b10110000, 0b01100101, 0b00001001, 0b01100110, 0b11111010, 0b00001010, 0b10011101, 0b01101111, 0b01110100, 0b11111101, 0b10011000, 0b10011101, 0b10001111 };
    var b1: [24][]u8 = undefined;
    try generateMnemonic(allocator, &e1, wordlist, &b1);
    defer for (b1) |word| allocator.free(word);

    var s1: [64]u8 = undefined;
    try mnemonicToSeed(allocator, &b1, "TREZOR", &s1);
    const actualSeed1 = std.mem.readInt(u512, &s1, .big);
    const expectedSeed1: u512 = 102649027874290713724689767472589284055554927022246786148344662858622900049166640615657055568848458507251256416806294161430513004959825609395163960773016;
    try std.testing.expectEqual(expectedSeed1, actualSeed1);

    // Test 2
    var e2 = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };
    var b2: [24][]u8 = undefined;
    try generateMnemonic(allocator, &e2, wordlist, &b2);
    defer for (b2) |word| allocator.free(word);

    var s2: [64]u8 = undefined;
    try mnemonicToSeed(allocator, &b2, "TREZOR", &s2);
    const actualSeed2 = std.mem.readInt(u512, &s2, .big);
    const expectedSeed2: u512 = 2037984480896257598861395356416471090707367901180776855108909406405800700429254515648977950137835572880251515364603734010368696077549762703902611761338653;
    try std.testing.expectEqual(expectedSeed2, actualSeed2);

    // Test 3, 12 words mnemonic
    var e3 = [16]u8{ 0b10001011, 0b10010100, 0b11110100, 0b10111001, 0b01110110, 0b11101111, 0b00111101, 0b10000101, 0b10001000, 0b00111101, 0b00001110, 0b10001111, 0b00001000, 0b01110000, 0b11010001, 0b11110011 };
    var b3: [12][]u8 = undefined;
    try generateMnemonic(allocator, &e3, wordlist, &b3);
    defer for (b3) |word| allocator.free(word);

    var s3: [64]u8 = undefined;
    try mnemonicToSeed(allocator, &b3, "TREZOR", &s3);
    const actualSeed3 = std.mem.readInt(u512, &s3, .big);
    const expectedSeed3: u512 = 8255326540855321261463521619631741630217762107517752183727119838575482639221952857292840619887401542272957276023929492122223117173190986974270213638571525;
    try std.testing.expectEqual(expectedSeed3, actualSeed3);
}
