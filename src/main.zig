const std = @import("std");
const bip39 = @import("bip39/bip39.zig");
const bip32 = @import("bip32/bip32.zig");
const secp256k1 = @import("secp256k1/secp256k1.zig");

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");

    // Entropy length in bits
    const ent: u16 = 256;
    _ = ent;
    // var entropy: [ent / 8]u8 = undefined; // 256/8
    // var entropy: []u8 = try allocator.alloc(u8, ent / 8);
    // defer allocator.free(entropy);
    var entropy = [32]u8{ 0b11110101, 0b10000101, 0b11000001, 0b00011010, 0b11101100, 0b01010010, 0b00001101, 0b10110101, 0b01111101, 0b11010011, 0b01010011, 0b11000110, 0b10010101, 0b01010100, 0b10110010, 0b00011010, 0b10001001, 0b10110010, 0b00001111, 0b10110000, 0b01100101, 0b00001001, 0b01100110, 0b11111010, 0b00001010, 0b10011101, 0b01101111, 0b01110100, 0b11111101, 0b10011000, 0b10011101, 0b10001111 };
    // bip39.generateEntropy(entropy, ent);
    // var entropy = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };

    var mnemonic: [24][]u8 = undefined;
    try bip39.generateMnemonic(&mnemonic, &entropy, wordlist, allocator);
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

    // // std.debug.print("Master private key: {b}\n", .{masterPrivateKey});
    const mi = std.mem.readIntBig(u256, &masterPrivateKey);
    std.debug.print("Master private key {x}\n", .{mi});
    const mc = std.mem.readIntBig(u256, &masterChainCode);
    std.debug.print("Master chain code {x}\n", .{mc});

    const compressedPublicKey = try bip32.generateCompressedPublicKey(masterPrivateKey);
    // std.debug.print("Compressed public key: {d}\n", .{compressedPublicKey});
    const cpk = std.mem.readIntBig(u264, &compressedPublicKey);
    std.debug.print("Compressed public key {x}\n", .{cpk});

    // try bip32.deriveAddressFromCompressedPublicKey(compressedPublicKey);

    const uncompressedPublicKey = try bip32.generateUncompressedPublicKey(masterPrivateKey);
    const ucpk = std.mem.readIntBig(u520, &uncompressedPublicKey);
    std.debug.print("Uncompressed public key: {x}\n", .{ucpk});

    // var childPrivateKey: [32]u8 = undefined;
    // var childChainCode: [32]u8 = undefined;
    // try bip32.deriveChild(masterPrivateKey, compressedPublicKey, masterChainCode, 0, &childPrivateKey, &childChainCode);
    // const childPublicKey = try bip32.generateCompressedPublicKey(childPrivateKey);

    // const childPrivateKeyInt = std.mem.readIntNative(u256, &childPrivateKey);
    // const childChainCodeInt = std.mem.readIntBig(u256, &childChainCode);
    // const childPublicKeyInt = std.mem.readIntNative(u264, &childPublicKey);

    // std.debug.print("Child private key {x}\n", .{childPrivateKeyInt});
    // std.debug.print("Child chain code {x}\n", .{childChainCodeInt});
    // std.debug.print("Child public key {x}\n", .{childPublicKeyInt});

    // var hardenedChildPrivateKey: [32]u8 = undefined;
    // var hardenedChildChainCode: [32]u8 = undefined;
    // try bip32.deriveChildHardened(masterPrivateKey, masterChainCode, 2147483648, &hardenedChildPrivateKey, &hardenedChildChainCode);
    // const hardenedChildPublicKey = try bip32.generateCompressedPublicKey(hardenedChildPrivateKey);

    // const hardenedChildPrivateKeyInt = std.mem.readIntBig(u256, &hardenedChildPrivateKey);
    // const hardenedChildChainCodeInt = std.mem.readIntBig(u256, &hardenedChildChainCode);
    // const hardenedChildPublicKeyInt = std.mem.readIntNative(u264, &hardenedChildPublicKey);

    // std.debug.print("Hardened Child private key {x}\n", .{hardenedChildPrivateKeyInt});
    // std.debug.print("Hardened Child chain code {x}\n", .{hardenedChildChainCodeInt});
    // std.debug.print("Hardened Child public key {x}\n", .{hardenedChildPublicKeyInt});
}
