const std = @import("std");
// This must be public in order to be used by the test (refAllDecls(@This()))
pub const bip39 = @import("src/bip39/bip39.zig");
pub const bip32 = @import("src/bip32/bip32.zig");
pub const bip38 = @import("src/bip38/bip38.zig");
pub const secp256k1 = @import("src/secp256k1/secp256k1.zig");
pub const utils = @import("src/utils.zig");
pub const script = @import("src/script/script.zig");
pub const tx = @import("src/tx/tx.zig");
pub const address = @import("src/address/address.zig");

test {
    std.testing.refAllDecls(@This());
}
