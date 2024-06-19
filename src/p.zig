const std = @import("std");
const io = std.io;
const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const bip38 = @import("bip38.zig");
const bip44 = @import("bip44.zig");
//const secp256k1 = @import("secp256k1/secp256k1.zig");
const Secp256k1Point = @import("crypto").Secp256k1Point;
const utils = @import("utils.zig");
const Network = @import("const.zig").Network;
const script = @import("script.zig");
const address = @import("address.zig");

const opcode = enum(u8) {
    OP_FALSE = 0x66,
    OP_NONE = 0x60,
};

fn f(x: opcode) void {
    std.debug.print("{d}\n", .{@intFromEnum(x)});
}

pub fn main() !void {
    std.debug.print("WALL-E. Bitcoin Wallet written in Zig\n", .{});
    f(opcode.OP_FALSE);

    //const n: u32 = 252;
    //switch (n) {
    //    0...252 => std.debug.print("Inclusive\n", .{}),
    //    else => std.debug.print("Exclusive\n", .{}),
    //}
    //
    //var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //const allocator = gpa.allocator();
    //defer std.debug.assert(gpa.deinit() == .ok);
    //
    //const wordlist = try bip39.WordList.init(allocator, "wordlist/english.txt");

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
    //var entropy = [32]u8{ 0b00000110, 0b01101101, 0b11001010, 0b00011010, 0b00101011, 0b10110111, 0b11101000, 0b10100001, 0b11011011, 0b00101000, 0b00110010, 0b00010100, 0b10001100, 0b11101001, 0b10010011, 0b00111110, 0b11101010, 0b00001111, 0b00111010, 0b11001001, 0b01010100, 0b10001101, 0b01111001, 0b00110001, 0b00010010, 0b11011001, 0b10101001, 0b01011100, 0b10010100, 0b00000111, 0b11101111, 0b10101101 };
    //// const ent = 256;
    ////var entropy: []u8 = try allocator.alloc(u8, ent / 8);
    ////defer allocator.free(entropy);
    //defer wordlist.deinit();
    //var mnemonic: [24][]u8 = undefined;
    //try bip39.generateMnemonic(allocator, &entropy, wordlist, &mnemonic);
    //defer for (mnemonic) |word| allocator.free(word);
    //for (mnemonic) |word| {
    //    std.debug.print("{s},", .{word});
    //}
    //var seed: [64]u8 = undefined;
    //try bip39.mnemonicToSeed(allocator, &mnemonic, "", &seed);
    //var seed_str: [128]u8 = undefined;
    //_ = try std.fmt.bufPrint(&seed_str, "{x}", .{std.fmt.fmtSliceHexLower(&seed)});
    //std.debug.print("Seed: {s}\n", .{seed_str});
    //
    //const private: bip32.ExtendedPrivateKey = bip32.generateExtendedMasterPrivateKey(seed);
    //std.debug.print("{}", .{private});
    //const wpk = bip32.WifPrivateKey.fromPrivateKey(private.privatekey, Network.MAINNET, true);
    //const wif = try bip32.toWif(wpk);
    //std.debug.print("WIF: {s}\n", .{wif});
    //const bip38key = try bip38.encrypt(allocator, private.privatekey, "password", Network.MAINNET);
    //std.debug.print("BIP 38 KEY: {s}\n", .{bip38key});
    //
    //const bip38decrypted = try bip38.decrypt(allocator, bip38key, "password", Network.MAINNET);
    //var bip38decryptedhexpk: [64]u8 = undefined;
    //_ = try std.fmt.bufPrint(&bip38decryptedhexpk, "{x}", .{std.fmt.fmtSliceHexLower(&bip38decrypted)});
    //std.debug.print("BIP 38 decrypoted key: {s}\n", .{bip38decryptedhexpk});
    //
    //const seed2 = [64]u8{ 0b10111000, 0b01110011, 0b00100001, 0b00101111, 0b10001000, 0b01011100, 0b11001111, 0b11111011, 0b11110100, 0b01101001, 0b00101010, 0b11111100, 0b10111000, 0b01001011, 0b11000010, 0b11100101, 0b01011000, 0b10000110, 0b11011110, 0b00101101, 0b11111010, 0b00000111, 0b11011001, 0b00001111, 0b01011100, 0b00111100, 0b00100011, 0b10011010, 0b10111100, 0b00110001, 0b11000000, 0b10100110, 0b11001110, 0b00000100, 0b01111110, 0b00110000, 0b11111101, 0b10001011, 0b11110110, 0b10100010, 0b10000001, 0b11100111, 0b00010011, 0b10001001, 0b10101010, 0b10000010, 0b11010111, 0b00111101, 0b11110111, 0b01001100, 0b01111011, 0b10111111, 0b10110011, 0b10110000, 0b01101011, 0b01000110, 0b00111001, 0b10100101, 0b11001110, 0b11100111, 0b01110101, 0b11001100, 0b11001101, 0b00111100 };
    //
    //const epk = bip32.generateExtendedMasterPrivateKey(seed2);
    //var hexpk: [64]u8 = undefined;
    //_ = try std.fmt.bufPrint(&hexpk, "{x}", .{std.fmt.fmtSliceHexLower(&epk.privatekey)});
    //// try std.testing.expectEqualStrings(&hexpk, "b21fcb414b4414e9bcf7ae647a79a4d29280f6b71cba204cb4dd3d6c6568d0fc");
    //
    //// const encrypted = try bip38.encrypt(allocator, epk.privatekey, "password");
    ////std.debug.print("BIP38 key {s}\n", .{encrypted});
    //
    //var bp: [32]u8 = undefined;
    //var pw: [8]u8 = "password".*;
    //const len = try utils.encodeutf8(&pw, &bp);
    //std.debug.print("bp encoded len {d}: {s}\n", .{ len, bp[0..len] });
    //// _ = try bip32.fromWif(wif);
    //
    //const public = bip32.generatePublicKey(private.privatekey);
    //std.debug.print("#### Public key ####\n{}", .{public});
    //const compressed = try public.toStrCompressed();
    //std.debug.print("Compressed {s}\n", .{compressed});
    ////const uncompressed = try public.toStrUncompressed();
    ////std.debug.print("Uncompressed {s}\n", .{uncompressed});
    //const addr1 = try public.toHash();
    //var str_addr: [50]u8 = undefined;
    //_ = try std.fmt.bufPrint(&str_addr, "{x}", .{std.fmt.fmtSliceHexLower(&addr1)});
    //std.debug.print("#### Single sig Address: #### \n{s}\n", .{str_addr});
    //
    //const uncompressed: [130]u8 = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c".*;
    //const s = try script.p2pk(allocator, &uncompressed);
    //defer s.deinit();
    //
    //var scripthexbuf: [134]u8 = undefined;
    ////std.mem.copy(u8, scripthexbuf[0..130], s.stack.items[1].v[0..130]);
    //std.debug.print("hex script: {s}\n", .{s.stack.items[1].v[0..130]});
    ////std.debug.print("hex script: {s}\n", .{scripthexbuf});
    //try s.toHex(&scripthexbuf);
    //std.debug.print("hex script: {s}\n", .{scripthexbuf});
    //
    //// MULTISIG
    //const private1 = private;
    //const private2 = epk;
    //const public1 = bip32.generatePublicKey(private1.privatekey);
    //const public2 = bip32.generatePublicKey(private2.privatekey);
    //
    //std.debug.print("Public key 1 {d}, {d}, Public key 2 {d}, {d}", .{ public1.point.x, public1.point.y, public2.point.x, public2.point.y });
    //// p2ms
    //var p1: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    //var p2: [130]u8 = "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af".*;
    //
    //const pubkeys: [2]bip32.PublicKey = [2]bip32.PublicKey{ public2, public1 };
    //_ = pubkeys;
    //var pubkyesstr: [2][]u8 = [2][]u8{ &p2, &p1 };
    //
    //const script3 = try script.p2ms(allocator, &pubkyesstr, 1, 2);
    //defer script3.deinit();
    //var hexbuf3: [270]u8 = undefined;
    //try script3.toHex(&hexbuf3);
    //std.debug.print("hexbuf3 {s}\n", .{hexbuf3});

    //var multisigaddr: [35]u8 = undefined;
    //try bip32.deriveMultiSigAddress(allocator, &pubkeys, 1, 2, Network.REGTEST, &multisigaddr);
    //std.debug.print("Multisig addr {s}\n", .{multisigaddr});

    //var bp2pkh: [34]u8 = undefined;
    //try address.deriveP2PKHAddress(public1, Network.MAINNET, &bp2pkh);

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

    //const ccc = "02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277".*;
    //const v = try std.fmt.parseInt(u264, &ccc, 16);
    //const c: [33]u8 = @bitCast(@byteSwap(v));
    //const p = try secp256k1.uncompress(c);
    //const pk1 = bip32.PublicKey{ .point = p };
    //const addr = try pk1.toHash();
    //var str1_addr: [50]u8 = undefined;
    //_ = try std.fmt.bufPrint(&str1_addr, "{x}", .{std.fmt.fmtSliceHexLower(&addr)});
    //std.debug.print("#### Single sig Address: #### \n{s}\n", .{str1_addr});

    const serializedAddr = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    // 03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed
    const masterExtendedPrivate = try bip32.ExtendedPrivateKey.fromAddress(serializedAddr);
    const epk1 = try bip32.deriveHardenedChild(masterExtendedPrivate, 84 + 2147483648);
    const epk2 = try bip32.deriveHardenedChild(epk1, 1 + 2147483648);
    const epk3 = try bip32.deriveHardenedChild(epk2, 0 + 2147483648);
    const epk4 = try bip32.deriveChildFromExtendedPrivateKey(epk3, 0);
    const epk5 = try bip32.deriveChildFromExtendedPrivateKey(epk4, 0);
    const public = bip32.generatePublicKey(epk5.privatekey);
    const compressed = try public.toStrCompressed();
    std.debug.print("compressed pub: {s}\n", .{compressed});

    const public2 = try bip44.generateAccount(masterExtendedPrivate, bip44.BIP_84_PURPOSE, 1, 0, 0, 0);
    const compressed2 = try public2.key.toStrCompressed();
    std.debug.print("compressed pub: {s}\n", .{compressed2});

    const buffer = "02aeb803a9ace6dcc5f11d06e8f30e24186c904f463be84f303d15bb7d48d1201f".*;
    const v = try std.fmt.parseInt(u264, &buffer, 16);
    const compressedt: [33]u8 = @bitCast(@byteSwap(v));
    const p = try Secp256k1Point.fromCompressed(compressedt);
    _ = p;
}
