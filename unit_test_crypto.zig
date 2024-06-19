const std = @import("std");
// This must be public in order to be used by the test (refAllDecls(@This()))
pub const secp256k1 = @import("src/crypto/secp256k1.zig");
pub const ripemd160 = @import("src/crypto/ripemd160.zig");

test {
    std.testing.refAllDecls(@This());
}
