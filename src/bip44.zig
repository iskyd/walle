const std = @import("std");
const assert = std.debug.assert;
const bip32 = @import("bip32.zig");
const Network = @import("const.zig").Network;
const utils = @import("utils.zig");

pub const BIP_44_PURPOSE = 44;
pub const BIP_84_PURPOSE = 84; // Segwit
pub const CHANGE_EXTERNAL_CHAIN = 0; // Address visible outside the wallet
pub const CHANGE_INTERNAL_CHAIN = 1; // Not visible outside the wallet, return transaction change
pub const BITCOIN_COIN_TYPE = 0x80000000;
pub const BITCOIN_TESTNET_COIN_TYPE = 0x80000001;

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

test "generateAccount" {
    const serializedAddr = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    const masterExtendedPrivate = try bip32.ExtendedPrivateKey.fromAddress(serializedAddr);
    const public = try generateAccount(masterExtendedPrivate, BIP_84_PURPOSE, 1, 0, 0, 0);
    const compressed = try public.key.toStrCompressed();
    const expected = "03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed".*;
    try std.testing.expectEqualStrings(expected, compressed);
}

test "generatePrivateAccount" {
    const serializedAddr = "tprv8ZgxMBicQKsPefj8cBDzcXJYcnvWBLQwG9sAvKyAYRPiLtdZXvdAmqtjzeHbX7ZX2LY8Sfb7SaLSJbGCFBPMFZdnmv4D7UebvyLTC974BA4".*;
    const masterExtendedPrivate = try bip32.ExtendedPrivateKey.fromAddress(serializedAddr);
    const private = try generateAccountPrivate(masterExtendedPrivate, BIP_84_PURPOSE, 1, 0, 0, 0);
    const public = bip32.generatePublicKey(private.privatekey);
    const compressed = try public.toStrCompressed();
    const expected = "03c260ee3c4975bf34ae63854c0f9309302d27cf588984ec943c2b1139aa7984ed".*;
    try std.testing.expectEqualStrings(expected, compressed);
}
