const std = @import("std");
const bip39 = @import("bip39/bip39.zig");
const bip32 = @import("bip32/bip32.zig");
const secp256k1 = @import("secp256k1/secp256k1.zig");
const utils = @import("utils.zig");

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

    var seed_hex_str: [128]u8 = undefined;
    _ = try std.fmt.bufPrint(&seed_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&seed)});
    std.debug.print("Seed {s}\n", .{seed_hex_str});

    var masterPrivateKey: [32]u8 = undefined;
    var masterChainCode: [32]u8 = undefined;
    bip32.generateMasterPrivateKey(seed, &masterPrivateKey, &masterChainCode);

    var master_private_key_hex_str: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&master_private_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&masterPrivateKey)});
    std.debug.print("Master private key {s}\n", .{master_private_key_hex_str});
    var master_chain_code_key_hex_str: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&master_chain_code_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&masterChainCode)});
    std.debug.print("Master chain code {s}\n", .{master_chain_code_key_hex_str});

    const compressedPublicKey = try bip32.generateCompressedPublicKey(masterPrivateKey);
    var compressed_public_key_hex_str: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&compressed_public_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&compressedPublicKey)});
    std.debug.print("Compressed public key {s}\n", .{compressed_public_key_hex_str});

    var address: [25]u8 = undefined;
    try bip32.deriveAddressFromCompressedPublicKey(compressedPublicKey, &address);
    var address_hex_str: [50]u8 = undefined;
    _ = try std.fmt.bufPrint(&address_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&address)});
    std.debug.print("Address: {s}\n", .{address_hex_str});

    var bytes_address: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_address, &address_hex_str);
    var base58_address: [34]u8 = undefined;
    try utils.toBase58(&base58_address, &bytes_address);
    std.debug.print("base58 address {s}\n", .{base58_address});

    const uncompressedPublicKey = try bip32.generateUncompressedPublicKey(masterPrivateKey);
    var uncompressed_public_key_hex_str: [130]u8 = undefined;
    _ = try std.fmt.bufPrint(&uncompressed_public_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&uncompressedPublicKey)});
    std.debug.print("Uncompressed public key: {s}\n", .{uncompressed_public_key_hex_str});

    var childPrivateKey: [32]u8 = undefined;
    var childChainCode: [32]u8 = undefined;
    try bip32.deriveChild(masterPrivateKey, compressedPublicKey, masterChainCode, 0, &childPrivateKey, &childChainCode);
    const childPublicKey = try bip32.generateCompressedPublicKey(childPrivateKey);

    var child_private_key_hex_str: [64]u8 = undefined;
    var child_chain_code_key_hex_str: [64]u8 = undefined;
    var child_public_key_hex_str: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&child_private_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&childPrivateKey)});
    _ = try std.fmt.bufPrint(&child_chain_code_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&childChainCode)});
    _ = try std.fmt.bufPrint(&child_public_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&childPublicKey)});

    std.debug.print("Child private key {s}\n", .{child_private_key_hex_str});
    std.debug.print("Child chain code {s}\n", .{child_chain_code_key_hex_str});
    std.debug.print("Child public key {s}\n", .{child_public_key_hex_str});

    var hardenedChildPrivateKey: [32]u8 = undefined;
    var hardenedChildChainCode: [32]u8 = undefined;
    try bip32.deriveChildHardened(masterPrivateKey, masterChainCode, 2147483648, &hardenedChildPrivateKey, &hardenedChildChainCode);
    const hardenedChildPublicKey = try bip32.generateCompressedPublicKey(hardenedChildPrivateKey);

    var child_private_key_hardened_hex_str: [64]u8 = undefined;
    var child_chain_code_hardened_key_hex_str: [64]u8 = undefined;
    var child_public_key_hardened_hex_str: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&child_private_key_hardened_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&hardenedChildPrivateKey)});
    _ = try std.fmt.bufPrint(&child_chain_code_hardened_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&hardenedChildChainCode)});
    _ = try std.fmt.bufPrint(&child_public_key_hardened_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&hardenedChildPublicKey)});

    std.debug.print("Hardened Child private key {s}\n", .{child_private_key_hardened_hex_str});
    std.debug.print("Hardened Child chain code {s}\n", .{child_chain_code_hardened_key_hex_str});
    std.debug.print("Hardened Child public key {s}\n", .{child_public_key_hardened_hex_str});

    var childPublicKey2: [33]u8 = undefined;
    var childChainCode2: [32]u8 = undefined;
    try bip32.deriveChildFromPublicKey(compressedPublicKey, masterChainCode, 0, &childPublicKey2, &childChainCode2);

    var child_chain_code2_key_hex_str: [64]u8 = undefined;
    var child_public_key2_hex_str: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&child_chain_code2_key_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&childChainCode2)});
    _ = try std.fmt.bufPrint(&child_public_key2_hex_str, "{x}", .{std.fmt.fmtSliceHexLower(&childPublicKey2)});

    std.debug.print("Child chain code {s}\n", .{child_chain_code2_key_hex_str});
    std.debug.print("Child public key {s}\n", .{child_public_key2_hex_str});
}
