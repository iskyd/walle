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
    try bip39.generateMnemonic(allocator, &entropy, wordlist, &mnemonic);
    wordlist.deinit();
    defer for (mnemonic) |word| allocator.free(word);

    std.debug.print("Mnemonic: ", .{});
    for (mnemonic) |word| {
        std.debug.print("{s}, ", .{word});
    }
    std.debug.print("\n", .{});

    var seed: [64]u8 = undefined;
    try bip39.mnemonicToSeed(allocator, mnemonic, "", &seed);

    var seed_str: [128]u8 = undefined;
    _ = try std.fmt.bufPrint(&seed_str, "{x}", .{std.fmt.fmtSliceHexLower(&seed)});
    std.debug.print("Seed: {s}\n", .{seed_str});

    const private: bip32.ExtendedPrivateKey = bip32.generateExtendedMasterPrivateKey(seed);

    const str_private = try private.toStrPrivate();
    std.debug.print("Master private key: {s}\n", .{str_private});
    const str_chain = try private.toStrChainCode();
    std.debug.print("Master chain code: {s}\n", .{str_chain});

    const public: secp256k1.Point = bip32.generatePublicKey(private.privatekey);
    const str_compressed = try public.toStrCompressed();
    std.debug.print("Compressed public key: {s}\n", .{str_compressed});
    const str_uncompressed = try public.toStrUncompressed();
    std.debug.print("Uncompressed public key: {s}\n", .{str_uncompressed});

    const address: [25]u8 = try bip32.deriveAddress(public);
    var str_addr: [50]u8 = undefined;
    _ = try std.fmt.bufPrint(&str_addr, "{x}", .{std.fmt.fmtSliceHexLower(&address)});
    std.debug.print("Address: {s}\n", .{str_addr});

    var bytes_addr: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_addr, &str_addr);
    var base58_addr: [34]u8 = undefined;
    try utils.toBase58(&base58_addr, &bytes_addr);
    std.debug.print("base58 address: {s}\n", .{base58_addr});

    const child = try bip32.deriveChildFromExtendedPrivateKey(private, 0);
    const str_child_private = try child.toStrPrivate();
    std.debug.print("Child private key for index {d}: {s}\n", .{ 0, str_child_private });
    const str_child_chain = try child.toStrChainCode();
    std.debug.print("Child chain code for index {d}: {s}\n", .{ 0, str_child_chain });

    const hardened_child = try bip32.deriveHardenedChild(private, 2147483648);
    const str_hardened_child = try hardened_child.toStrPrivate();
    std.debug.print("Hardened child private key for index {d}: {s}\n", .{ 2147483648, str_hardened_child });
    const str_hardened_chain = try hardened_child.toStrChainCode();
    std.debug.print("Hardened child chain code for index {d}: {s}\n", .{ 2147483648, str_hardened_chain });

    const epublic = bip32.ExtendedPublicKey{ .publickey = public, .chaincode = private.chaincode };
    const child_public = try bip32.deriveChildFromExtendedPublicKey(epublic, 0);
    const str_child_public = try child_public.toStrCompressedPublic();
    std.debug.print("Child public key for index {d}: {s}\n", .{ 0, str_child_public });
    const str_child_chain_public = try child_public.toStrChainCode();
    std.debug.print("Child chain code for index {d}: {s}\n", .{ 0, str_child_chain_public });
}
