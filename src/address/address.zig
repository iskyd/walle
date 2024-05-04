const std = @import("std");
const utils = @import("../utils.zig");
const Network = @import("../const.zig").Network;
const script = @import("../script/script.zig");
const PublicKey = @import("../bip32/bip32.zig").PublicKey;

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

//pub fn deriveP2PKHAddress(pubkey: secp256k1.Point, network: Network, buffer: []u8) !void {
//    const pkc = try pubkey.toStrCompressed();
//    var bytes: [33]u8 = undefined;
//    _ = try std.fmt.hexToBytes(&bytes, &pkc);
//    var pubkeyhash = utils.hash160(&bytes);
//    var ppk: [42]u8 = undefined; // Public key hash with prefix
//    // 0x00 is mainnet
//    // 0x?? is testnet
//    _ = switch (network) {
//        Network.MAINNET => try std.fmt.bufPrint(&ppk, "00{x}", .{std.fmt.fmtSliceHexLower(&pubkeyhash)}),
//        else => _ = try std.fmt.bufPrint(&ppk, "00{x}", .{std.fmt.fmtSliceHexLower(&pubkeyhash)}),
//    };
//
//    var ppkbytes: [21]u8 = undefined;
//    _ = try std.fmt.hexToBytes(&ppkbytes, &ppk);
//    const checkpubkey = utils.calculateChecksum(&ppkbytes);
//    var addr: [50]u8 = undefined;
//    _ = try std.fmt.bufPrint(&addr, "{s}{x}", .{ ppk, std.fmt.fmtSliceHexLower(&checkpubkey) });
//    var addrbytes: [25]u8 = undefined;
//    _ = try std.fmt.hexToBytes(&addrbytes, &addr);
//    try utils.toBase58(buffer, &addrbytes);
//}
//
//// Required m keys of n
//pub fn deriveP2MSAddress(pubkeys: []secp256k1.Point, network: Network, m: u8, n: u8, buffer: []u8) !void {
//    _ = buffer;
//    _ = n;
//    _ = m;
//    _ = network;
//    _ = pubkeys;
//}

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
