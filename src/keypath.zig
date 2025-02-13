const std = @import("std");
const assert = std.debug.assert;
const bip32 = @import("bip32.zig");
const utils = @import("utils.zig");

pub const bip_44_purpose = 44;
pub const bip_84_purpose = 84; // Segwit
pub const change_external_chain = 0; // Address visible outside the wallet
pub const change_internal_chain = 1; // Not visible outside the wallet, return transaction change
pub const bitcoin_coin_type = 0;
pub const bitcoin_testnet_coin_type = 1;

pub const KeyPathElement = struct {
    value: u32,
    is_hardened: bool,
};

pub fn KeyPath(comptime depth: u8) type {
    comptime assert(depth <= 5);
    return struct {
        path: [depth]KeyPathElement,

        const Self = @This();

        pub fn getStrCap(self: Self, comptime max_depth: ?u8) usize {
            comptime {
                if (max_depth != null) {
                    assert(depth >= max_depth.?);
                }
            }
            var cap: usize = self.path.len - 1; // number of /
            for (self.path, 0..) |d, i| {
                cap += if (d.value != 0) std.math.log10(d.value) + 1 else 1;
                if (d.is_hardened == true) {
                    cap += 1;
                }
                if (comptime max_depth != null) {
                    if (max_depth.? <= i + 2) {
                        break;
                    }
                }
            }

            return cap;
        }

        pub fn toStr(self: Self, allocator: std.mem.Allocator, comptime max_depth: ?u8) ![]u8 {
            comptime {
                if (max_depth != null) {
                    assert(depth >= max_depth.?);
                }
            }
            var buffer = try allocator.alloc(u8, self.getStrCap(max_depth));
            var current: usize = 0;
            for (self.path, 0..) |d, i| {
                const currentcap = if (d.value != 0) std.math.log10(d.value) + 1 else 1;
                _ = try std.fmt.bufPrint(buffer[current .. current + currentcap], "{d}", .{d.value});
                current += currentcap;
                if (d.is_hardened == true) {
                    buffer[current] = '\'';
                    current += 1;
                }

                if (comptime max_depth != null) {
                    if (max_depth.? <= i + 1) {
                        break;
                    }
                }

                if (i < self.path.len - 1) {
                    buffer[current] = '/';
                }
                current += 1;
            }

            return buffer;
        }

        pub fn fromStr(str: []const u8) !Self {
            var path: [depth]KeyPathElement = undefined;
            var current: usize = 0;
            for (0..depth) |i| {
                const delimiter_index: ?usize = std.mem.indexOf(u8, str[current..], "/");
                if (delimiter_index == null and i != depth - 1) {
                    // We should be at the last child but it is not matching the depth, we have an invalid keypath
                    return error.InvalidKeyPath;
                }
                var end = str.len;
                if (delimiter_index != null) {
                    end = current + delimiter_index.?;
                }
                var is_hardened = false;
                if (str[end - 1] == '\'') {
                    is_hardened = true;
                    end -= 1;
                }

                const v = try std.fmt.parseInt(u32, str[current..end], 10);
                path[i] = KeyPathElement{ .value = v, .is_hardened = is_hardened };

                if (is_hardened) {
                    current = end + 2;
                } else {
                    current = end + 1;
                }
            }

            return Self{ .path = path };
        }

        pub fn getNext(self: Self, v: u32) Self {
            var path: [depth]KeyPathElement = undefined;
            for (self.path, 0..) |p, i| {
                path[i] = .{ .value = p.value, .is_hardened = p.is_hardened };
            }

            path[depth - 1].value = path[depth - 1].value + v;
            return Self{ .path = path };
        }
    };
}

pub const Descriptor = struct {
    extended_key: [111]u8,
    keypath: KeyPath(3),
    private: bool,
};

test "keypath" {
    const allocator = std.testing.allocator;
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    try std.testing.expectEqual(k1.path[0].value, 84);
    try std.testing.expectEqual(k1.path[0].is_hardened, true);
    try std.testing.expectEqual(k1.path[1].value, 0);
    try std.testing.expectEqual(k1.path[1].is_hardened, true);
    try std.testing.expectEqual(k1.path[2].value, 0);
    try std.testing.expectEqual(k1.path[2].is_hardened, true);
    try std.testing.expectEqual(k1.path[3].value, 0);
    try std.testing.expectEqual(k1.path[3].is_hardened, false);
    try std.testing.expectEqual(k1.path[4].value, 1);
    try std.testing.expectEqual(k1.path[4].is_hardened, false);

    const k1str = try k1.toStr(allocator, null);
    defer allocator.free(k1str);
    const e1 = "84'/0'/0'/0/1".*;
    try std.testing.expectEqualStrings(&e1, k1str);

    const k2 = try KeyPath(3).fromStr("84'/0'/0'");
    try std.testing.expectEqual(k2.path[0].value, 84);
    try std.testing.expectEqual(k2.path[0].is_hardened, true);
    try std.testing.expectEqual(k2.path[1].value, 0);
    try std.testing.expectEqual(k2.path[1].is_hardened, true);
    try std.testing.expectEqual(k2.path[2].value, 0);
    try std.testing.expectEqual(k2.path[2].is_hardened, true);

    const e2 = "84'/0'/0'".*;
    const k2str = try k2.toStr(allocator, null);
    defer allocator.free(k2str);
    try std.testing.expectEqualStrings(&e2, k2str);
}

test "keypathToStrCapMaxDepth" {
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    const res = k1.getStrCap(3);
    try std.testing.expectEqual(9, res);
}

test "keypathToStrMaxDepth" {
    const allocator = std.testing.allocator;
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    const res = try k1.toStr(allocator, 3);
    try std.testing.expectEqualStrings("84'/0'/0'", res);
    defer allocator.free(res);
}

test "keyPathGetNext" {
    const k1 = try KeyPath(5).fromStr("84'/0'/0'/0/1");
    const k2 = k1.getNext(1);
    try std.testing.expectEqual(k1.path[0].value, k2.path[0].value);
    try std.testing.expectEqual(k1.path[0].is_hardened, k2.path[0].is_hardened);
    try std.testing.expectEqual(k1.path[1].value, k2.path[1].value);
    try std.testing.expectEqual(k1.path[1].is_hardened, k2.path[1].is_hardened);
    try std.testing.expectEqual(k1.path[2].value, k2.path[2].value);
    try std.testing.expectEqual(k1.path[2].is_hardened, k2.path[2].is_hardened);
    try std.testing.expectEqual(k1.path[3].value, k2.path[3].value);
    try std.testing.expectEqual(k1.path[3].is_hardened, k2.path[3].is_hardened);
    try std.testing.expectEqual(k1.path[4].value + 1, k2.path[4].value);
    try std.testing.expectEqual(k1.path[4].is_hardened, k2.path[4].is_hardened);
}
