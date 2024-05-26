const std = @import("std");
const bip32 = @import("../bip32/bip32.zig");
const Network = @import("../const.zig").Network;
const utils = @import("../utils.zig");

const BIP_44_PURPOSE = 44;
const CHANGE_EXTERNAL_CHAIN = 0; // Address visible outside the wallet
const CHANGE_INTERNAL_CHAIN = 1; // Not visible outside the wallet, return transaction change
const BITCOIN_COIN_TYPE = 0x80000000;
const BITCOIN_TESTNET_COIN_TYPE = 0x80000001;

pub fn generateAccount(epk: bip32.ExtendedPrivateKey, purpose: u32, cointype: u32, account: u32, change: u32, index: u32) !bip32.ExtendedPublicKey {
    const purposeepk = try bip32.deriveHardenedChild(epk, purpose);
    const cointypeepk = try bip32.deriveHardenedChild(purposeepk, cointype);

    // Add check that avoid creation of this account if previous account has no transaction associated
    // as specified in bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#account
    const accountepk = try bip32.deriveHardenedChild(cointypeepk, account);

    const public = bip32.generatePublicKey(accountepk.privatekey);
    const accountextendedpublic = bip32.ExtendedPublicKey{ .key = public, .chaincode = accountepk.chaincode };

    const changepk = try bip32.deriveChildFromExtendedPublicKey(accountextendedpublic, change);
    const indexepk = try bip32.deriveChildFromExtendedPublicKey(changepk, index);

    return indexepk;
}

pub fn generateExternalBitcoinAccount(epk: bip32.ExtendedPrivateKey, n: Network, account: u32, index: u32) !bip32.ExtendedPublicKey {
    const cointype: u32 = switch (n) {
        Network.MAINNET => BITCOIN_COIN_TYPE,
        else => BITCOIN_TESTNET_COIN_TYPE,
    };
    const purpose: u32 = @intCast(BIP_44_PURPOSE + 2147483648);
    return generateAccount(epk, purpose, cointype, account, CHANGE_EXTERNAL_CHAIN, index);
}

pub fn generateInternalBitcoinAccount(n: Network, index: u32) !bip32.ExtendedPublicKey {
    const cointype = switch (n) {
        Network.MAINNET => BITCOIN_COIN_TYPE,
        else => BITCOIN_TESTNET_COIN_TYPE,
    };
    const purpose: u32 = @intCast(BIP_44_PURPOSE + 2147483648);
    return generateAccount(purpose, cointype, CHANGE_INTERNAL_CHAIN, index);
}

test "generateExternalBitcoinAccount" {
    // https://iancoleman.io/bip39/
    const seedhex = "81a79e3c7df2fc3376b087b5d5db952eb3c29eaf958b73aaad4ebc9eedb29e55abd8880457171d73ee4adeeaa3950812e6d1d935202f4ecc4aa62d8974665bcf".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = bip32.generateExtendedMasterPrivateKey(seed);
    const acc1 = try generateExternalBitcoinAccount(epk, Network.MAINNET, 2147483648, 0);
    const pkstr = try acc1.key.toStrCompressed();
    try std.testing.expectEqualStrings("02abc7c9d90f41a37ec14714b7e1db16231e08bc733b938aee44167192f31670ce", &pkstr);
}

test "test" {
    const seedhex = "81a79e3c7df2fc3376b087b5d5db952eb3c29eaf958b73aaad4ebc9eedb29e55abd8880457171d73ee4adeeaa3950812e6d1d935202f4ecc4aa62d8974665bcf".*;
    var seed: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, &seedhex);
    const epk = bip32.generateExtendedMasterPrivateKey(seed);
    const child = try bip32.deriveHardenedChild(epk, 2147483648 + 44); // 44'
    const child2 = try bip32.deriveHardenedChild(child, 2147483648);
    const child3 = try bip32.deriveHardenedChild(child2, 2147483648);
    const expectedprivatekeyaddr = "xprv9xibuu9WWWf3fYnGiKY6sqk8rvNHCZMjbLLDcF2Qj8N3WcNzw2AknNGapkd79mUuU2BwC5kvqcFuC5VAujGHBuT2gujogoMq1A4qDasdxVM".*;
    const expectedpublicaddr = "xpub6G3vxdEYuhYffVX9HjJrdDaQdeyG2bm2LCCM8FP7QcH5xtXkND1FPzEHYmWL9STdzZodqxyWBBXWV3BNRbJkhwMZBjZYmfwm1D5tVYwWfZ8".*;
    const expectedprivate = try bip32.ExtendedPrivateKey.fromAddress(expectedprivatekeyaddr);
    const expectedpublic = try bip32.ExtendedPublicKey.fromAddress(expectedpublicaddr);

    const public = bip32.generatePublicKey(child3.privatekey);
    const extendedpublic = bip32.ExtendedPublicKey{ .key = public, .chaincode = child3.chaincode };
    const child4 = try bip32.deriveChildFromExtendedPublicKey(extendedpublic, 0);
    const child5 = try bip32.deriveChildFromExtendedPublicKey(child4, 0);

    try std.testing.expectEqualSlices(u8, &expectedprivate.privatekey, &child3.privatekey);
    try std.testing.expectEqual(child5.key.point, expectedpublic.key.point);
}
