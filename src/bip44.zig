const std = @import("std");
const assert = std.debug.assert;
const bip32 = @import("bip32.zig");
const utils = @import("utils.zig");

pub const bip_44_purpose = 44;
pub const bip_84_purpose = 84; // Segwit
pub const change_external_chain = 0; // Address visible outside the wallet
pub const change_internal_chain = 1; // Not visible outside the wallet, return transaction change
pub const bitcoin_coin_type = 0;
pub const bitcoin_testnet_coin_type = 1;

pub fn KeyPath(comptime depth: u8) type {
    comptime assert(depth <= 5);
    return struct {
        path: [depth]u32,

        const Self = @This();

        pub fn getStrCap(self: Self, comptime max_depth: ?u8) usize {
            comptime {
                if (max_depth != null) {
                    assert(depth >= max_depth.?);
                }
            }
            var cap: usize = self.path.len - 1; // number of /
            for (self.path, 0..) |d, i| {
                cap += if (d != 0) std.math.log10(d) + 1 else 1;

                // We need to add ' for the first 3 elements since they use hardened derivation
                if (i <= 2) {
                    cap += 1;
                }
                if (comptime max_depth != null) {
                    if (max_depth.? <= i + 2) {
                        break;
                    }
                }
            }

            return cap;
        }

        pub fn toStr(self: Self, allocator: std.mem.Allocator, comptime max_depth: ?u8) ![]u8 {
            comptime {
                if (max_depth != null) {
                    assert(depth >= max_depth.?);
                }
            }
            var buffer = try allocator.alloc(u8, self.getStrCap(max_depth));
            var current: usize = 0;
            for (self.path, 0..) |d, i| {
                const currentcap = if (d != 0) std.math.log10(d) + 1 else 1;
                _ = try std.fmt.bufPrint(buffer[current .. current + currentcap], "{d}", .{d});
                current += currentcap;
                if (i <= 2) {
                    buffer[current] = '\'';
                    current += 1;
                }

                if (comptime max_depth != null) {
                    if (max_depth.? <= i + 1) {
                        break;
                    }
                }

                if (i < self.path.len - 1) {
                    buffer[current] = '/';
                }
                current += 1;
            }

            return buffer;
        }

        pub fn fromStr(str: []const u8) !Self {
            var path: [depth]u32 = undefined;
            var current: usize = 0;
            for (0..depth) |i| {
                const delimiter_index: ?usize = std.mem.indexOf(u8, str[current..], "/");
                if (delimiter_index == null) {
                    // We are at the last child or we have an invalid keypath
                    if (i == depth - 1) {
                        var end = str.len;
                        if (i <= 2) {
                            end -= 1;
                        }
                        const v = try std.fmt.parseInt(u32, str[current..end], 10);
                        path[i] = v;
                        break;
                    }
                    return error.InvalidKeyPath;
                }
                var end = current + delimiter_index.?;
                if (i <= 2) {
                    assert(str[end - 1] == '\'');
                    end -= 1; // -1 because we need to remove the hardened symbol '
                }
                const v = try std.fmt.parseInt(u32, str[current..end], 10);
                path[i] = v;

                if (i <= 2) {
                    current = end + 2;
                } else {
                    current = end + 1;
                }
            }

            return Self{ .path = path };
        }

        pub fn getNext(self: Self, v: u32) Self {
            var path: [depth]u32 = undefined;
            for (self.path, 0..) |p, i| {
                path[i] = p;
            }

            path[depth - 1] = path[depth - 1] + v;
            return Self{ .path = path };
        }
    };
}

pub const Descriptor = struct {
    extended_key: [111]u8,
    keypath: KeyPath(3),
    private: bool,
};

// Purpose, cointype, and account use hardened derivation
// 2147483648 is added to the passed values for this fields.
pub fn generateAccount(extended_privkey: bip32.ExtendedPrivateKey, purpose: u32, cointype: u32, account: u32, change: u32, index: u32) !bip32.ExtendedPublicKey {
    const purpose_extended_privkey = try bip32.deriveHardenedChild(extended_privkey, purpose + 2147483648);
    const cointype_extended_privkey = try bip32.deriveHardenedChild(purpose_extended_privkey, cointype + 2147483648);

    // Add check that avoid creation of this account if previous account has no transaction associated
    // as specified in bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#account
    const account_extended_privkey = try bip32.deriveHardenedChild(cointype_extended_privkey, account + 2147483648);

    const pubkey = bip32.generatePublicKey(account_extended_privkey.privatekey);
    const account_extended_pubkey = bip32.ExtendedPublicKey{ .key = pubkey, .chaincode = account_extended_privkey.chaincode };

    const change_extended_pubkey = try bip32.deriveChildFromExtendedPublicKey(account_extended_pubkey, change);
    const index_extended_pubkey = try bip32.deriveChildFromExtendedPublicKey(change_extended_pubkey, index);

    return index_extended_pubkey;
}

// Purpose, cointype, and account use hardened derivation
// 2147483648 is added to the passed values for this fields.
pub fn generateAccountPrivate(extended_privkey: bip32.ExtendedPrivateKey, purpose: u32, cointype: u32, account: u32, change: u32, index: u32) !bip32.ExtendedPrivateKey {
    const purpose_extended_privkey = try bip32.deriveHardenedChild(extended_privkey, purpose + 2147483648);
    const cointype_extended_privkey = try bip32.deriveHardenedChild(purpose_extended_privkey, cointype + 2147483648);

    // Add check that avoid creation of this account if previous account has no transaction associated
    // as specified in bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#account
    const account_extended_privkey = try bip32.deriveHardenedChild(cointype_extended_privkey, account + 2147483648);

    const change_extended_privkey = try bip32.deriveChildFromExtendedPrivateKey(account_extended_privkey, change);
    const index_extended_privkey = try bip32.deriveChildFromExtendedPrivateKey(change_extended_privkey, index);

    return index_extended_privkey;
}

pub fn generatePublicFromAccountPublicKey(extended_pubkey: bip32.ExtendedPublicKey, change: u32, index: u32) !bip32.PublicKey {
    const change_extended_pubkey = try bip32.deriveChildFromExtendedPublicKey(extended_pubkey, change);
    const index_extended_pubkey = try bip32.deriveChildFromExtendedPublicKey(change_extended_pubkey, index);

    return index_extended_pubkey.key;
}

test "generateAccount" {
    const addr_serialized = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    const master_extended_privkey = try bip32.ExtendedPrivateKey.fromAddress(addr_serialized);
    const extended_pubkey = try generateAccount(master_extended_privkey, bip_84_purpose, 1, 0, 0, 0);
    const compressed = try extended_pubkey.key.toStrCompressed();
    const expected = "03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed";
    try std.testing.expectEqualStrings(expected, &compressed);
}

test "generatePrivateAccount" {
    const addr_serialized = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    const master_extended_privkey = try bip32.ExtendedPrivateKey.fromAddress(addr_serialized);
    const extended_privkey = try generateAccountPrivate(master_extended_privkey, bip_84_purpose, 1, 0, 0, 0);
    const public = bip32.generatePublicKey(extended_privkey.privatekey);
    const compressed = try public.toStrCompressed();
    const expected = "03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed";
    try std.testing.expectEqualStrings(expected, &compressed);
}

test "keypath" {
    const allocator = std.testing.allocator;
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    try std.testing.expectEqual(k1.path[0], 84);
    try std.testing.expectEqual(k1.path[1], 0);
    try std.testing.expectEqual(k1.path[2], 0);
    try std.testing.expectEqual(k1.path[3], 0);
    try std.testing.expectEqual(k1.path[4], 1);

    const k1str = try k1.toStr(allocator, null);
    defer allocator.free(k1str);
    const e1 = "84'/0'/0'/0/1".*;
    try std.testing.expectEqualStrings(&e1, k1str);

    const k2 = try KeyPath(3).fromStr("84'/0'/0'");
    try std.testing.expectEqual(k2.path[0], 84);
    try std.testing.expectEqual(k2.path[1], 0);
    try std.testing.expectEqual(k2.path[2], 0);

    const e2 = "84'/0'/0'".*;
    const k2str = try k2.toStr(allocator, null);
    defer allocator.free(k2str);
    try std.testing.expectEqualStrings(&e2, k2str);
}

test "keypathToStrCapMaxDepth" {
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    const res = k1.getStrCap(3);
    try std.testing.expectEqual(9, res);
}

test "keypathToStrMaxDepth" {
    const allocator = std.testing.allocator;
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    const res = try k1.toStr(allocator, 3);
    try std.testing.expectEqualStrings("84'/0'/0'", res);
    defer allocator.free(res);
}
