const std = @import("std");
const Network = @import("const.zig").Network;
const utils = @import("utils.zig");

pub const WifPrivateKey = struct {
    key: [32]u8,
    net: [1]u8,
    suffix: [1]u8,

    pub fn fromPrivateKey(key: [32]u8, net: Network, compressed: bool) WifPrivateKey {
        const netslice: [1]u8 = switch (net) {
            Network.mainnet => [1]u8{0b10000000},
            Network.testnet => [1]u8{0b11101111},
            Network.regtest => [1]u8{0b11101111},
            else => unreachable,
        };

        const suffix = switch (compressed) {
            true => [1]u8{0b00000001},
            false => [1]u8{0b00000000},
        };

        return WifPrivateKey{
            .key = key,
            .net = netslice,
            .suffix = suffix,
        };
    }

    pub fn toBase58(self: WifPrivateKey) ![52]u8 {
        var extended: [34]u8 = undefined;
        @memcpy(extended[0..1], self.net[0..1]);
        @memcpy(extended[1..33], self.key[0..]);
        @memcpy(extended[33..], self.suffix[0..]);

        var str: [68]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "{x}", .{std.fmt.fmtSliceHexLower(&extended)});

        var bytes: [34]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, &str);

        var checksum: [32]u8 = utils.doubleSha256(&bytes);

        var wif: [38]u8 = undefined;
        @memcpy(wif[0..34], bytes[0..]);
        @memcpy(wif[34..], checksum[0..4]);

        var wif_base58: [52]u8 = undefined;
        try utils.toBase58(&wif_base58, &wif);

        return wif_base58;
    }

    pub fn fromBase58(wif: [52]u8) !WifPrivateKey {
        var decoded: [38]u8 = undefined;
        try utils.fromBase58(&wif, &decoded);

        const net: [1]u8 = [1]u8{decoded[0]};
        const key: [32]u8 = decoded[1..33].*;
        const suffix: [1]u8 = [1]u8{decoded[33]};
        const checksum: [4]u8 = decoded[34..38].*;

        var str: [68]u8 = undefined;
        _ = try std.fmt.bufPrint(&str, "{x}{x}{x}", .{ std.fmt.fmtSliceHexLower(&net), std.fmt.fmtSliceHexLower(&key), std.fmt.fmtSliceHexLower(&suffix) });

        var bytes: [34]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, &str);

        const ok = utils.verifyChecksum(&bytes, checksum);
        if (ok == false) {
            std.debug.print("Error: Invalid checksum\n", .{});
            return error.InvalidChecksum;
        }

        return WifPrivateKey{
            .key = key,
            .net = net,
            .suffix = suffix,
        };
    }
};

test "toWif" {
    const privkey_hex = "b21fcb414b4414e9bcf7ae647a79a4d29280f6b71cba204cb4dd3d6c6568d0fc";
    var privkey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&privkey, privkey_hex);
    const wpk = WifPrivateKey.fromPrivateKey(privkey, Network.mainnet, true);
    const wif_base58 = try wpk.toBase58();
    try std.testing.expectEqualSlices(u8, "L3BxhCBNNLihRFeZVEa6846is2Qe5YHpvddiLb83aNyUDpGumiiq", &wif_base58);
}

test "fromWif" {
    const base58: [52]u8 = "L3BxhCBNNLihRFeZVEa6846is2Qe5YHpvddiLb83aNyUDpGumiiq".*;
    const wif = try WifPrivateKey.fromBase58(base58);

    try std.testing.expectEqualSlices(u8, &[1]u8{0b10000000}, &wif.net);
    try std.testing.expectEqualSlices(u8, &[1]u8{0b00000001}, &wif.suffix);

    var keystr: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&keystr, "{x}", .{std.fmt.fmtSliceHexLower(&wif.key)});
    try std.testing.expectEqualSlices(u8, "b21fcb414b4414e9bcf7ae647a79a4d29280f6b71cba204cb4dd3d6c6568d0fc", &keystr);
}
