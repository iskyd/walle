const std = @import("std");
const assert = std.debug.assert;
const bip32 = @import("bip32.zig");
const Network = @import("const.zig").Network;
const utils = @import("utils.zig");

pub const BIP_44_PURPOSE = 44;
pub const BIP_84_PURPOSE = 84; // Segwit
pub const CHANGE_EXTERNAL_CHAIN = 0; // Address visible outside the wallet
pub const CHANGE_INTERNAL_CHAIN = 1; // Not visible outside the wallet, return transaction change
pub const BITCOIN_COIN_TYPE = 0;
pub const BITCOIN_TESTNET_COIN_TYPE = 1;

pub const KeyPath = struct {
    purpose: u32,
    cointype: u32,
    account: u32,
    change: u32,
    index: u32,

    // Memory ownership to the caller
    pub fn toStr(self: KeyPath, allocator: std.mem.Allocator) ![]u8 {
        var cap: usize = 4; // 4 = number of /
        const purposeCap = if (self.purpose != 0) std.math.log10(self.purpose) + 2 else 2; // We add +1 to save ' to indicate it's hardened derived
        const cointypeCap = if (self.cointype != 0) std.math.log10(self.cointype) + 2 else 2; // We add +1 to save ' to indicate it's hardened derived
        const accountCap = if (self.account != 0) std.math.log10(self.account) + 2 else 2; // We add +1 to save ' to indicate it's hardened derived
        const changeCap = if (self.change != 0) std.math.log10(self.change) + 1 else 1;
        const indexCap = if (self.index != 0) std.math.log10(self.index) + 1 else 1;
        cap += purposeCap + cointypeCap + accountCap + changeCap + indexCap;

        var buffer = try allocator.alloc(u8, cap);
        var current: usize = 0;
        _ = try std.fmt.bufPrint(buffer[current .. current + purposeCap + 1], "{d}'/", .{self.purpose});
        current += purposeCap + 1;
        _ = try std.fmt.bufPrint(buffer[current .. current + cointypeCap + 1], "{d}'/", .{self.cointype});
        current += cointypeCap + 1;
        _ = try std.fmt.bufPrint(buffer[current .. current + accountCap + 1], "{d}'/", .{self.account});
        current += accountCap + 1;
        _ = try std.fmt.bufPrint(buffer[current .. current + changeCap + 1], "{d}/", .{self.change});
        current += changeCap + 1;
        _ = try std.fmt.bufPrint(buffer[current .. current + indexCap], "{d}", .{self.index});
        current += indexCap;

        return buffer;
    }

    pub fn fromStr(str: []const u8) !KeyPath {
        var current: usize = 0;
        var delimiterIndex: ?usize = std.mem.indexOf(u8, str, "/");
        if (delimiterIndex == null) {
            return error.InvalidKeyPath;
        }
        const purpose = try std.fmt.parseInt(u32, str[current .. current + delimiterIndex.? - 1], 10); // -1 because we need to remove the hardened symbol '
        current = delimiterIndex.? + 1;
        delimiterIndex = std.mem.indexOf(u8, str[current..], "/");
        if (delimiterIndex == null) {
            return error.InvalidKeyPath;
        }
        const cointype = try std.fmt.parseInt(u32, str[current .. current + delimiterIndex.? - 1], 10);
        current = current + delimiterIndex.? + 1;
        delimiterIndex = std.mem.indexOf(u8, str[current..], "/");
        if (delimiterIndex == null) {
            return error.InvalidKeyPath;
        }
        const account = try std.fmt.parseInt(u32, str[current .. current + delimiterIndex.? - 1], 10);
        current = current + delimiterIndex.? + 1;
        delimiterIndex = std.mem.indexOf(u8, str[current..], "/");
        if (delimiterIndex == null) {
            return error.InvalidKeyPath;
        }
        const change = try std.fmt.parseInt(u32, str[current .. current + delimiterIndex.?], 10);
        current = current + delimiterIndex.? + 1;
        const index = try std.fmt.parseInt(u32, str[current..], 10);
        return KeyPath{
            .purpose = purpose,
            .cointype = cointype,
            .account = account,
            .change = change,
            .index = index,
        };
    }
};

// Purpose, cointype, and account use hardened derivation
// 2147483648 is added to the passed values for this fields.
pub fn generateAccount(epk: bip32.ExtendedPrivateKey, purpose: u32, cointype: u32, account: u32, change: u32, index: u32) !bip32.ExtendedPublicKey {
    const purposeepk = try bip32.deriveHardenedChild(epk, purpose + 2147483648);
    const cointypeepk = try bip32.deriveHardenedChild(purposeepk, cointype + 2147483648);

    // Add check that avoid creation of this account if previous account has no transaction associated
    // as specified in bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#account
    const accountepk = try bip32.deriveHardenedChild(cointypeepk, account + 2147483648);

    const public = bip32.generatePublicKey(accountepk.privatekey);
    const accountextendedpublic = bip32.ExtendedPublicKey{ .key = public, .chaincode = accountepk.chaincode };

    const changepk = try bip32.deriveChildFromExtendedPublicKey(accountextendedpublic, change);
    const indexepk = try bip32.deriveChildFromExtendedPublicKey(changepk, index);

    return indexepk;
}

// Purpose, cointype, and account use hardened derivation
// 2147483648 is added to the passed values for this fields.
pub fn generateAccountPrivate(epk: bip32.ExtendedPrivateKey, purpose: u32, cointype: u32, account: u32, change: u32, index: u32) !bip32.ExtendedPrivateKey {
    const purposeepk = try bip32.deriveHardenedChild(epk, purpose + 2147483648);
    const cointypeepk = try bip32.deriveHardenedChild(purposeepk, cointype + 2147483648);

    // Add check that avoid creation of this account if previous account has no transaction associated
    // as specified in bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#account
    const accountepk = try bip32.deriveHardenedChild(cointypeepk, account + 2147483648);

    const changepk = try bip32.deriveChildFromExtendedPrivateKey(accountepk, change);
    const indexepk = try bip32.deriveChildFromExtendedPrivateKey(changepk, index);

    return indexepk;
}

pub fn generatePublicFromAccountPublicKey(pk: bip32.ExtendedPublicKey, change: u32, index: u32) !bip32.PublicKey {
    const changepk = try bip32.deriveChildFromExtendedPublicKey(pk, change);
    const indexepk = try bip32.deriveChildFromExtendedPublicKey(changepk, index);

    return indexepk.key;
}

test "generateAccount" {
    const serializedAddr = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    const masterExtendedPrivate = try bip32.ExtendedPrivateKey.fromAddress(serializedAddr);
    const public = try generateAccount(masterExtendedPrivate, BIP_84_PURPOSE, 1, 0, 0, 0);
    const compressed = try public.key.toStrCompressed();
    const expected = "03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed";
    try std.testing.expectEqualStrings(expected, &compressed);
}

test "generatePrivateAccount" {
    const serializedAddr = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    const masterExtendedPrivate = try bip32.ExtendedPrivateKey.fromAddress(serializedAddr);
    const private = try generateAccountPrivate(masterExtendedPrivate, BIP_84_PURPOSE, 1, 0, 0, 0);
    const public = bip32.generatePublicKey(private.privatekey);
    const compressed = try public.toStrCompressed();
    const expected = "03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed";
    try std.testing.expectEqualStrings(expected, &compressed);
}

test "keypathToStr" {
    const allocator = std.testing.allocator;
    const kp = KeyPath{ .purpose = 84, .cointype = BITCOIN_COIN_TYPE, .account = 0, .change = CHANGE_EXTERNAL_CHAIN, .index = 0 };

    const kpstr = try kp.toStr(allocator);
    defer allocator.free(kpstr);

    const expected = "84'/0'/0'/0/0".*;
    try std.testing.expectEqualStrings(&expected, kpstr);
}

test "keypathFromStr" {
    const str = "84'/0'/0'/0/0".*;
    const kp = try KeyPath.fromStr(&str);

    try std.testing.expectEqual(kp.purpose, 84);
    try std.testing.expectEqual(kp.cointype, 0);
    try std.testing.expectEqual(kp.account, 0);
    try std.testing.expectEqual(kp.change, 0);
    try std.testing.expectEqual(kp.index, 0);
}
