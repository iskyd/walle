const std = @import("std");

pub const Block = struct {
    hash: [32]u8,
    height: usize,
};
