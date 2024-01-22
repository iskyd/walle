const std = @import("std");
const io = std.io;
const bip39 = @import("bip39/bip39.zig");
const bip32 = @import("bip32/bip32.zig");
const bip38 = @import("bip38/bip38.zig");
const secp256k1 = @import("secp256k1/secp256k1.zig");
const utils = @import("utils.zig");
const Network = @import("const.zig").Network;

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");

    // var e3 = [16]u8{ 0b10001011, 0b10010100, 0b11110100, 0b10111001, 0b01110110, 0b11101111, 0b00111101, 0b10000101, 0b10001000, 0b00111101, 0b00001110, 0b10001111, 0b00001000, 0b01110000, 0b11010001, 0b11110011 };
    // var b3: [12][]u8 = undefined;
    //try bip39.generateMnemonic(allocator, &e3, wordlist, &b3);
    //defer for (b3) |word| allocator.free(word);
    //wordlist.deinit();
    //for (b3) |word| {
    //    std.debug.print("{s}, ", .{word});
    //}

    // Entropy length in bits
    // const ent: u16 = 256;
    // var entropy: []u8 = try allocator.alloc(u8, ent / 8);
    // defer allocator.free(entropy);
    // var entropy = [32]u8{ 0b11110101, 0b10000101, 0b11000001, 0b00011010, 0b11101100, 0b01010010, 0b00001101, 0b10110101, 0b01111101, 0b11010011, 0b01010011, 0b11000110, 0b10010101, 0b01010100, 0b10110010, 0b00011010, 0b10001001, 0b10110010, 0b00001111, 0b10110000, 0b01100101, 0b00001001, 0b01100110, 0b11111010, 0b00001010, 0b10011101, 0b01101111, 0b01110100, 0b11111101, 0b10011000, 0b10011101, 0b10001111 };
    // bip39.generateEntropy(entropy, ent);
    // // var entropy = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };
    //
    const ent = 256;
    var entropy: []u8 = try allocator.alloc(u8, ent / 8);
    defer allocator.free(entropy);
    defer wordlist.deinit();
    var mnemonic: [24][]u8 = undefined;
    try bip39.generateMnemonic(allocator, entropy, wordlist, &mnemonic);
    defer for (mnemonic) |word| allocator.free(word);
    var seed: [64]u8 = undefined;
    try bip39.mnemonicToSeed(allocator, &mnemonic, "", &seed);
    var seed_str: [128]u8 = undefined;
    _ = try std.fmt.bufPrint(&seed_str, "{x}", .{std.fmt.fmtSliceHexLower(&seed)});
    std.debug.print("Seed: {s}\n", .{seed_str});

    const private: bip32.ExtendedPrivateKey = bip32.generateExtendedMasterPrivateKey(seed);
    std.debug.print("{}", .{private});
    const wpk = bip32.WifPrivateKey.fromPrivateKey(private.privatekey, Network.MAINNET, true);
    const wif = try bip32.toWif(wpk);
    std.debug.print("WIF: {s}\n", .{wif});
    try bip38.encrypt(allocator, wpk, "password");
    // _ = try bip32.fromWif(wif);

    // const public: secp256k1.Point = bip32.generatePublicKey(private.privatekey);
    // std.debug.print("#### Public key ####\n{}", .{public});
    // const compressed = try public.toStrCompressed();
    // std.debug.print("Compressed {s}\n", .{compressed});

    // const address: [25]u8 = try bip32.deriveAddress(public);
    // var str_addr: [50]u8 = undefined;
    // _ = try std.fmt.bufPrint(&str_addr, "{x}", .{std.fmt.fmtSliceHexLower(&address)});
    // std.debug.print("#### Address: #### \n{s}\n", .{str_addr});

    // var bytes_addr: [25]u8 = undefined;
    // _ = try std.fmt.hexToBytes(&bytes_addr, &str_addr);
    // var base58_addr: [34]u8 = undefined;
    // try utils.toBase58(&base58_addr, &bytes_addr);
    // std.debug.print("base58 address: {s}\n", .{base58_addr});

    // const child = try bip32.deriveChildFromExtendedPrivateKey(private, 0);
    // std.debug.print("#### Child ####\n{s}", .{child});

    // const hardened_child = try bip32.deriveHardenedChild(private, 2147483648);
    // std.debug.print("#### Hardened Child ####\n{s}", .{hardened_child});

    // const epublic = bip32.ExtendedPublicKey{ .publickey = public, .chaincode = private.chaincode };
    // const child_public = try bip32.deriveChildFromExtendedPublicKey(epublic, 0);
    // const compressed_child = try child_public.publickey.toStrCompressed();
    // std.debug.print("#### Child ####\n{s}", .{child_public});
    // std.debug.print("Compressed {s}\n", .{compressed_child});
}
