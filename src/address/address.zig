const std = @import("std");
const utils = @import("../utils.zig");
const Network = @import("../const.zig").Network;
const script = @import("../script/script.zig");
const PublicKey = @import("../bip32/bip32.zig").PublicKey;
const ripemd = @import("../ripemd160/ripemd160.zig");

// P2PK and P2MS do not have an address

pub fn deriveP2PKHAddress(pk: PublicKey, n: Network) ![34]u8 {
    const pkh = try pk.toHash();
    var pkwithprefix: [42]u8 = undefined;
    _ = switch (n) {
        Network.MAINNET => try std.fmt.bufPrint(&pkwithprefix, "00{x}", .{std.fmt.fmtSliceHexLower(&pkh)}),
        else => _ = try std.fmt.bufPrint(&pkwithprefix, "6f{x}", .{std.fmt.fmtSliceHexLower(&pkh)}),
    };
    var b: [21]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, &pkwithprefix);

    var checksum: [32]u8 = utils.doubleSha256(&b);
    var addr: [25]u8 = undefined;
    std.mem.copy(u8, addr[0..21], b[0..]);
    std.mem.copy(u8, addr[21..25], checksum[0..4]);

    var base58addr: [34]u8 = undefined;
    try utils.toBase58(&base58addr, &addr);
    return base58addr;
}

pub fn deriveP2SHAddress(allocator: std.mem.Allocator, s: script.Script, n: Network) ![34]u8 {
    const hexCap = s.hexCap();
    var redeemscript = try allocator.alloc(u8, hexCap);
    defer allocator.free(redeemscript);
    try s.toHex(redeemscript);
    var bytes = try allocator.alloc(u8, hexCap / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, redeemscript);
    const r = utils.hash160(bytes);
    var rstr: [42]u8 = undefined;
    _ = switch (n) {
        Network.MAINNET => try std.fmt.bufPrint(&rstr, "05{x}", .{std.fmt.fmtSliceHexLower(&r)}),
        else => _ = try std.fmt.bufPrint(&rstr, "c4{x}", .{std.fmt.fmtSliceHexLower(&r)}),
    };
    var bytes_hashed: [21]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_hashed, &rstr);
    var checksum: [32]u8 = utils.doubleSha256(&bytes_hashed);
    var addr: [25]u8 = undefined;
    std.mem.copy(u8, addr[0..21], bytes_hashed[0..21]);
    std.mem.copy(u8, addr[21..], checksum[0..4]);

    var base58addr: [34]u8 = undefined;
    try utils.toBase58(&base58addr, &addr);

    return base58addr;
}

test "deriveP2PKHAddress" {
    const secp256k1 = @import("../secp256k1/secp256k1.zig");
    const pubkeystr = "02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277".*;
    const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
    var c: [33]u8 = @bitCast(@byteSwap(v));
    const p = try secp256k1.uncompress(c);
    const pk = PublicKey{ .point = p };
    const addr = try deriveP2PKHAddress(pk, Network.MAINNET);
    try std.testing.expectEqualSlices(u8, "13mKVN2PVGYdNLSLG8egVXwnPFrSUtWCTE", &addr);

    const addr2 = try deriveP2PKHAddress(pk, Network.TESTNET);
    try std.testing.expectEqualSlices(u8, "miHGnR7NJHyt9Suwyhd4KTA7FFT9S9Tc9H", &addr2);
}

test "deriveP2SHAddress" {
    const allocator = std.testing.allocator;
    var p1: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var p2: [130]u8 = "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af".*;

    var pubkeys: [2][]u8 = [2][]u8{ &p1, &p2 };
    const s = try script.p2ms(allocator, &pubkeys, 1, 2);
    defer s.deinit();

    // bx script-to-address "1 [0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af] [04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4] 2 checkmultisig" -> 3AkkzXdYcewc2ipTU4uUJxgmbGDmPQT6AU
    const addr = try deriveP2SHAddress(allocator, s, Network.MAINNET);
    try std.testing.expectEqualSlices(u8, "3AkkzXdYcewc2ipTU4uUJxgmbGDmPQT6AU", &addr);
}
