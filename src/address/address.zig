const std = @import("std");
const secp256k1 = @import("../secp256k1/secp256k1.zig");
const utils = @import("../utils.zig");
const Network = @import("../const.zig").Network;
const script = @import("../script/script.zig");

pub fn deriveP2PKHAddress(pubkey: secp256k1.Point, network: Network, buffer: []u8) !void {
    const pkc = try pubkey.toStrCompressed();
    var bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &pkc);
    var pubkeyhash = utils.hash160(&bytes);
    var ppk: [42]u8 = undefined; // Public key hash with prefix
    // 0x00 is mainnet
    // 0x?? is testnet
    _ = switch (network) {
        Network.MAINNET => try std.fmt.bufPrint(&ppk, "00{x}", .{std.fmt.fmtSliceHexLower(&pubkeyhash)}),
        else => _ = try std.fmt.bufPrint(&ppk, "00{x}", .{std.fmt.fmtSliceHexLower(&pubkeyhash)}),
    };

    var ppkbytes: [21]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ppkbytes, &ppk);
    const checkpubkey = utils.calculateChecksum(&ppkbytes);
    var addr: [50]u8 = undefined;
    _ = try std.fmt.bufPrint(&addr, "{s}{x}", .{ ppk, std.fmt.fmtSliceHexLower(&checkpubkey) });
    var addrbytes: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&addrbytes, &addr);
    try utils.toBase58(buffer, &addrbytes);
}

test "deriveP2PKHAddress" {
    const public1 = secp256k1.Point{ .x = 37253515490154515672784401628327921438582067191679050515845431690448956984277, .y = 76208137199335099197411179139200193700449258875686614565584339213655359189545 };
    var address: [34]u8 = undefined;
    try deriveP2PKHAddress(public1, Network.MAINNET, &address);
    try std.testing.expectEqualSlices(u8, "14gozCHHpk7d6zhkxN1388i4gsnjrsLWpH", &address);
}
