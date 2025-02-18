const std = @import("std");

pub const Block = struct {
    hash: [32]u8,
    height: usize,
};

pub const RpcBlock = struct {
    allocator: std.mem.Allocator,
    hash: [32]u8,
    height: usize,
    previous_hash: [32]u8,
    raw_transactions: [][]u8,

    pub fn deinit(self: RpcBlock) void {
        self.allocator.free(self.raw_transactions);
    }
};
