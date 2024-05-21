const std = @import("std");
const utils = @import("../utils.zig");
const Network = @import("../const.zig").Network;
const script = @import("../script/script.zig");
const PublicKey = @import("../bip32/bip32.zig").PublicKey;
const ripemd = @import("../ripemd160/ripemd160.zig");

pub const Address = struct {
    val: []u8,
    n: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, comptime n: usize, val: [n]u8) !Address {
        var s = try allocator.alloc(u8, n);
        errdefer comptime unreachable; // From now on, no more error
        std.mem.copy(u8, s[0..], &val);
        return Address{ .allocator = allocator, .val = s, .n = n };
    }

    pub fn deinit(self: Address) void {
        self.allocator.free(self.val);
    }
};

// P2PK and P2MS do not have an address

pub fn deriveP2PKHAddress(allocator: std.mem.Allocator, pk: PublicKey, n: Network) !Address {
    const pkh = try pk.toHash();
    var pkwithprefix: [42]u8 = undefined;
    _ = switch (n) {
        Network.MAINNET => try std.fmt.bufPrint(&pkwithprefix, "00{x}", .{std.fmt.fmtSliceHexLower(&pkh)}),
        else => _ = try std.fmt.bufPrint(&pkwithprefix, "6f{x}", .{std.fmt.fmtSliceHexLower(&pkh)}),
    };
    var b: [21]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, &pkwithprefix);

    var checksum: [4]u8 = utils.calculateChecksum(&b);
    var addr: [25]u8 = undefined;
    std.mem.copy(u8, addr[0..21], b[0..]);
    std.mem.copy(u8, addr[21..25], &checksum);

    var base58addr: [34]u8 = undefined;
    try utils.toBase58(&base58addr, &addr);
    return try Address.init(allocator, 34, base58addr);
}

pub fn deriveP2SHAddress(allocator: std.mem.Allocator, s: script.Script, n: Network) !Address {
    const cap = s.hexCapBytes();
    var bytes = try allocator.alloc(u8, cap);
    try s.toBytes(allocator, bytes);
    defer allocator.free(bytes);

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

    return switch (n) {
        Network.MAINNET => {
            var base58addr: [34]u8 = undefined;
            try utils.toBase58(&base58addr, &addr);
            return try Address.init(allocator, 34, base58addr);
        },
        else => {
            var base58addr: [35]u8 = undefined;
            try utils.toBase58(&base58addr, &addr);
            return try Address.init(allocator, 35, base58addr);
        },
    };
}

test "deriveP2PKHAddress" {
    const allocator = std.testing.allocator;
    const secp256k1 = @import("../secp256k1/secp256k1.zig");

    const pubkeys = [4][66]u8{ "02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277".*, "0398426aee0ea0f493af6082689368cac9cdc58e2211f9278b83137489361506e0".*, "021300826a376a51bfa57dc472d9f4a8aee66a9fe17a6d2e3a8377de4497313603".*, "02e54fd5846317beee43336707872879e28df4c6a47cddfe21deaf95eb85d64610".* };
    const expected: [8][]u8 = [8][]u8{ @constCast("13mKVN2PVGYdNLSLG8egVXwnPFrSUtWCTE"), @constCast("miHGnR7NJHyt9Suwyhd4KTA7FFT9S9Tc9H"), @constCast("15VfPhqqqHE4x8tNdka1RjHK1bnVr8D8Fi"), @constCast("mk1cgkvpeJfKjFMzMKYPFeVdsbPCiCDEDc"), @constCast("1Q9Eb1cy93vTVN7sGwqHPAZjT46wSBpSou"), @constCast("n4fBt4hwx5MiGUbUzWofD5n4K3heLRMmVC"), @constCast("1FsadxqoEcJLf8u6grqBQttDD95NNr8We8"), @constCast("mvPXw1vn3djbSFNiQRoZEp6Y58g5HXZ8yC") };

    var i: u8 = 0;
    for (pubkeys) |pubkeystr| {
        const v = try std.fmt.parseInt(u264, &pubkeystr, 16);
        var c: [33]u8 = @bitCast(@byteSwap(v));
        const p = try secp256k1.uncompress(c);
        const pk = PublicKey{ .point = p };
        const addrmainnet = try deriveP2PKHAddress(allocator, pk, Network.MAINNET);
        const addrtestnet = try deriveP2PKHAddress(allocator, pk, Network.TESTNET);
        defer addrmainnet.deinit();
        defer addrtestnet.deinit();

        try std.testing.expectEqualSlices(u8, expected[i], addrmainnet.val);
        try std.testing.expectEqual(addrmainnet.n, 34);
        i += 1;
        try std.testing.expectEqualSlices(u8, expected[i], addrtestnet.val);
        try std.testing.expectEqual(addrtestnet.n, 34);
        i += 1;
    }
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
    defer addr.deinit();
    try std.testing.expectEqualSlices(u8, "3AkkzXdYcewc2ipTU4uUJxgmbGDmPQT6AU", addr.val);
    try std.testing.expectEqual(addr.n, 34);

    const addr2 = try deriveP2SHAddress(allocator, s, Network.TESTNET);
    defer addr2.deinit();
    try std.testing.expectEqualSlices(u8, "2N2Jy4GZaE7SxEWT19CXLvug2ocRw6CAD8U", addr2.val);
    try std.testing.expectEqual(addr2.n, 35);
}
