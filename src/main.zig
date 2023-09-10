const std = @import("std");
const bip39 = @import("bip39/bip39.zig");
const bip32 = @import("bip32/bip32.zig");
const secp256k1 = @import("secp256k1/secp256k1.zig");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");

    const ent: u16 = 256;
    _ = ent; // Entropy length in bits (at the moment only 256 bit is supported)
    // var entropy: [ent / 8]u8 = undefined; // 256/8
    // bip39.generateEntropy(&entropy, ent);
    var entropy = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };

    var mnemonic: [24][]u8 = undefined;
    try bip39.generateMnemonic(&mnemonic, entropy, wordlist, allocator);
    wordlist.deinit();
    defer for (mnemonic) |word| allocator.free(word);

    std.debug.print("Mnemonic: ", .{});
    for (mnemonic) |word| {
        std.debug.print("{s}, ", .{word});
    }
    std.debug.print("\n", .{});

    var seed: [64]u8 = undefined;
    try bip39.mnemonicToSeed(allocator, &seed, mnemonic, "");

    // std.debug.print("Seed: {b}\n", .{seed});
    const x = std.mem.readIntBig(u512, &seed);
    std.debug.print("Seed {x}\n", .{x});

    var masterPrivateKey: [32]u8 = undefined;
    var masterChainCode: [32]u8 = undefined;
    bip32.generateMasterPrivateKey(seed, &masterPrivateKey, &masterChainCode);

    // std.debug.print("Master private key: {b}\n", .{masterPrivateKey});
    const mi = std.mem.readIntBig(u256, &masterPrivateKey);
    std.debug.print("Master private key {x}\n", .{mi});
    const mc = std.mem.readIntBig(u256, &masterChainCode);
    std.debug.print("Master chain code {x}\n", .{mc});

    const compressedPublicKey = try bip32.generateCompressedPublicKey(masterPrivateKey);
    // std.debug.print("Compressed public key: {d}\n", .{compressedPublicKey});
    const cpk = std.mem.readIntNative(u264, &compressedPublicKey);
    std.debug.print("Compressed public key {x}\n", .{cpk});

    // const uncompressedPublicKey = try bip32.generateUncompressedPublicKey(masterPrivateKey);
    // const ucpk = std.mem.readIntNative(u520, &uncompressedPublicKey);
    // std.debug.print("Uncompressed public key: {x}\n", .{ucpk});

    var childPrivateKey: [32]u8 = undefined;
    var childChainCode: [32]u8 = undefined;
    var childPublicKey: [33]u8 = undefined;
    try bip32.deriveChild(masterPrivateKey, compressedPublicKey, masterChainCode, 0, &childPrivateKey, &childChainCode, &childPublicKey);
}
