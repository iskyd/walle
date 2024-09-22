pub const Network = enum { mainnet, testnet, regtest, simnet };
pub const SighashType = enum(u8) {
    sighash_all = 0x1,
    sighash_none = 0x2,
    sighash_single = 0x3,
    sighash_all_anyonecanpay = 0x81,
    sighash_none_anyonecanpay = 0x82,
    sighash_single_anyonecanpay = 0x83,
};
