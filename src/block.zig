const std = @import("std");

pub const Block = struct {
    hash: [64]u8,
    height: usize,
};
