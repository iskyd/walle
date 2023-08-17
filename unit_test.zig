const std = @import("std");
pub const bip39 = @import("src/bip39/bip39.zig");

test {
    std.testing.refAllDecls(@This());
}
