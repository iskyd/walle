const std = @import("std");
const assert = std.debug.assert;

pub const ScriptType = enum(u8) {
    p2wpkh,
};

pub const Opcode = enum(u8) {
    // constants
    op_false = 0x00,
    op_pushdata1 = 0x4c,
    op_pushdata2 = 0x4d,
    op_pushdata4 = 0x4e,
    op_1negate = 0x4f,
    op_true = 0x51, // OP_TRUE == OP_1
    op_2 = 0x52,
    op_3 = 0x53,
    op_4 = 0x54,
    op_5 = 0x55,
    op_6 = 0x56,
    op_7 = 0x57,
    op_8 = 0x58,
    op_9 = 0x59,
    op_10 = 0x5a,
    op_11 = 0x5b,
    op_12 = 0x5c,
    op_13 = 0x5d,
    op_14 = 0x5e,
    op_15 = 0x5f,
    op_16 = 0x60,

    // Flow control
    op_nop = 0x61,
    op_if = 0x63,
    op_else = 0x64,
    op_endif = 0x68,
    op_verify = 0x69,
    op_return = 0x6a,

    // Stack
    op_totalstacl = 0x6b,
    op_fromaltstack = 0x6c,
    op_ifdup = 0x73,
    op_depth = 0x74,
    op_drop = 0x75,
    op_dup = 0x76,
    op_nip = 0x77,
    op_over = 0x78,
    op_pick = 0x79,
    op_roll = 0x7a,
    op_rot = 0x7b,
    op_swap = 0x7c,
    op_tuck = 0x7d,
    op_2drop = 0x6d,
    op_2dup = 0x6e,
    op_3dup = 0x6f,
    op_2over = 0x70,
    op_2rot = 0x71,
    op_2swap = 0x72,

    // Splice
    op_size = 0x82,

    // Bitwise logic
    op_invert = 0x83,
    op_and = 0x84,
    op_or = 0x85,
    op_xor = 0x86,
    op_equal = 0x87,
    op_equalverify = 0x88,

    // Arithmetic
    op_1add = 0x8b,
    op_1sub = 0x8c,
    op_negate = 0x8f,
    op_abs = 0x90,
    op_not = 0x91,
    op_0notequal = 0x92,
    op_add = 0x93,
    op_sub = 0x94,
    op_booland = 0x9a,
    op_numequal = 0x9c,
    op_numequalverify = 0x9d,
    op_numnotequal = 0x9e,
    op_lessthan = 0x9f,
    op_greaterthan = 0xa0,
    op_lessthanorequal = 0xa1,
    op_greaterthanorequal = 0xa2,
    op_min = 0xa3,
    op_max = 0xa4,
    op_within = 0xa5,

    // Crypto
    op_ripemd160 = 0xa6,
    op_sha1 = 0xa7,
    op_sha256 = 0xa8,
    op_hash160 = 0xa9,
    op_hash256 = 0xaa,
    op_codeseparator = 0xab,
    op_checksig = 0xac,
    op_checksigverify = 0xad,
    op_checkmultisig = 0xae,
    op_checkmultisigverify = 0xaf,
    op_checksigadd = 0xba,

    // Locktime
    op_checklocktimeverify = 0xb1,
    op_checksequenceverify = 0xb2,

    // Pseudowords
    op_pubkeyhash = 0xfd,
    op_pubkey = 0xfe,
    op_invalidopcode = 0xff,

    // Reserved words
    op_reserved = 0x50,
    op_ver = 0x62,
    op_verif = 0x65,
    op_vernotif = 0x66,
    op_reserved1 = 0x89,
    op_reserved2 = 0x8a,

    // n <= 16
    pub fn fromNum(n: u8) Opcode {
        assert(n <= 16);
        return switch (n) {
            0 => Opcode.op_false,
            1 => Opcode.op_true,
            2 => Opcode.op_2,
            3 => Opcode.op_3,
            4 => Opcode.op_4,
            5 => Opcode.op_5,
            6 => Opcode.op_6,
            7 => Opcode.op_7,
            8 => Opcode.op_8,
            9 => Opcode.op_9,
            10 => Opcode.op_10,
            11 => Opcode.op_11,
            12 => Opcode.op_12,
            13 => Opcode.op_13,
            14 => Opcode.op_14,
            15 => Opcode.op_15,
            16 => Opcode.op_16,
            else => unreachable,
        };
    }
};

pub const ScriptOp = union(enum) { op: Opcode, v: []const u8, push_bytes: usize };

pub const Script = struct {
    allocator: std.mem.Allocator,

    // Script stack is a LIFO (as the data structure imply) during execution
    // To execute a script we must start from the latest element
    stack: std.ArrayList(ScriptOp),

    pub fn init(allocator: std.mem.Allocator) Script {
        return .{ .allocator = allocator, .stack = std.ArrayList(ScriptOp).init(allocator) };
    }

    pub fn deinit(self: Script) void {
        self.stack.deinit();
    }

    pub fn push(self: *Script, op: ScriptOp) !void {
        try self.stack.append(op);
    }

    pub fn toHex(self: Script, buffer: []u8) !void {
        var cur: usize = 0;
        for (0..self.stack.items.len) |i| {
            const scriptop = self.stack.items[i];
            switch (scriptop) {
                ScriptOp.op => |op| {
                    const opv = @intFromEnum(op);
                    var opbuf: [2]u8 = undefined;
                    if (opv <= 15) {
                        _ = try std.fmt.bufPrint(&opbuf, "0{x}", .{opv});
                    } else {
                        _ = try std.fmt.bufPrint(&opbuf, "{x}", .{opv});
                    }
                    @memcpy(buffer[cur .. cur + 2], opbuf[0..2]);
                    cur += 2;
                },
                ScriptOp.v => |v| {
                    @memcpy(buffer[cur .. cur + v.len], v);
                    cur += v.len;
                },
                ScriptOp.push_bytes => |pb| {
                    var push_bytes_buffer: [2]u8 = undefined;
                    _ = try std.fmt.bufPrint(&push_bytes_buffer, "{x}", .{pb});
                    @memcpy(buffer[cur .. cur + 2], push_bytes_buffer[0..2]);
                    cur += 2;
                },
            }
        }
    }

    pub fn hexCap(self: Script) usize {
        var cap: usize = 0;
        for (0..self.stack.items.len) |i| {
            const scriptop = self.stack.items[i];
            switch (scriptop) {
                ScriptOp.op => |_| {
                    cap += 2;
                },
                ScriptOp.v => |v| {
                    cap += v.len;
                },
                ScriptOp.push_bytes => |_| {
                    cap += 2;
                },
            }
        }
        return cap;
    }

    pub fn hexCapBytes(self: Script) usize {
        return self.hexCap() / 2;
    }

    pub fn toBytes(self: Script, allocator: std.mem.Allocator, buffer: []u8) !void {
        const c = self.hexCap();
        const redeem_script = try allocator.alloc(u8, c);
        defer allocator.free(redeem_script);
        try self.toHex(redeem_script);
        _ = try std.fmt.hexToBytes(buffer, redeem_script);
    }

    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Script {
        var script = Script.init(allocator);
        var current: usize = 0;
        while (current < bytes.len) {
            const v = bytes[current];
            current += 1;
            // It is a valid opcode
            if (v == 0 or v >= 76) {
                const op: Opcode = @enumFromInt(v);
                try script.push(ScriptOp{ .op = op });
            } else { // it is a push_bytes
                try script.push(ScriptOp{ .push_bytes = v });
                const data = bytes[current .. current + v];
                try script.push(ScriptOp{ .v = data });
                current += v;
            }
        }

        return script;
    }

    pub fn getTotalValues(self: Script) usize {
        var cap: usize = 0;
        for (0..self.stack.items.len) |i| {
            const item = self.stack.items[i];
            switch (item) {
                ScriptOp.v => cap += 1,
                else => continue,
            }
        }

        return cap;
    }

    // Memory ownership to the caller
    pub fn getValues(self: Script, allocator: std.mem.Allocator) ![][40]u8 {
        var values = try allocator.alloc([40]u8, self.getTotalValues());
        var current: usize = 0;
        for (0..self.stack.items.len) |i| {
            const item = self.stack.items[i];
            switch (item) {
                ScriptOp.v => |v| {
                    values[current] = v[0..40].*;
                    current += 1;
                },
                else => continue,
            }
        }

        return values;
    }

    pub fn getType(self: Script) !ScriptType {
        if (self.stack.items.len == 3 and self.stack.items[0].op == Opcode.op_false and self.stack.items[1].push_bytes == 20) {
            return ScriptType.p2wpkh;
        }

        return error.InvalidScript;
    }

    pub fn format(self: Script, actual_fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = actual_fmt;
        _ = options;

        for (0..self.stack.items.len) |i| {
            const scriptop = self.stack.items[i];
            switch (scriptop) {
                ScriptOp.op => |op| {
                    try writer.print("{s} ", .{@tagName(op)});
                },
                ScriptOp.v => |v| {
                    try writer.print("{s} ", .{v});
                },
                ScriptOp.push_bytes => |pb| {
                    try writer.print("OP_PUSHBYTES_{d} ", .{pb});
                },
            }
        }
    }
};

// pubkey as str
pub fn p2pk(allocator: std.mem.Allocator, pubkey: []const u8) !Script {
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .push_bytes = pubkey.len / 2 });
    try script.push(ScriptOp{ .v = pubkey });
    try script.push(ScriptOp{ .op = Opcode.op_checksig });

    return script;
}

// pubkeys as str
pub fn p2ms(allocator: std.mem.Allocator, pubkeys: [][]const u8, m: u8, n: u8) !Script {
    assert(m <= n);
    assert(m != 0);
    assert(n <= 16);

    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = Opcode.fromNum(m) });
    for (pubkeys) |pubkey| {
        try script.push(ScriptOp{ .push_bytes = pubkey.len / 2 });
        try script.push(ScriptOp{ .v = pubkey });
    }
    try script.push(ScriptOp{ .op = Opcode.fromNum(n) });
    try script.push(ScriptOp{ .op = Opcode.op_checkmultisig });

    return script;
}

// NOT TESTED
pub fn p2pkh(allocator: std.mem.Allocator, pkeyhash: []const u8) !Script {
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = Opcode.op_dup });
    try script.push(ScriptOp{ .op = Opcode.op_hash160 });
    try script.push(ScriptOp{ .push_bytes = 20 });
    try script.push(ScriptOp{ .v = pkeyhash });
    try script.push(ScriptOp{ .op = Opcode.op_equalverify });
    try script.push(ScriptOp{ .op = Opcode.op_checksig });

    return script;
}

// pay to witness pubkey hash
pub fn p2wpkh(allocator: std.mem.Allocator, pubkeyhash: []const u8) !Script {
    assert(pubkeyhash.len == 40);
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = Opcode.op_false });
    try script.push(ScriptOp{ .push_bytes = 20 });
    try script.push(ScriptOp{ .v = pubkeyhash[0..] });

    return script;
}

// to implement p2pkh, p2sh
test "test p2pk" {
    const uncompressedpubkey: [130]u8 = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c".*;
    const allocator = std.testing.allocator;
    const script = try p2pk(allocator, &uncompressedpubkey);
    defer script.deinit();

    try std.testing.expectEqual(Opcode.op_checksig, script.stack.items[2].op);
    try std.testing.expectEqualSlices(u8, &uncompressedpubkey, script.stack.items[1].v);
    try std.testing.expectEqual(script.stack.items[0].push_bytes, 65);
}

test "test p2ms" {
    var p1: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var p2: [130]u8 = "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af".*;

    var pubkeys: [2][]u8 = [2][]u8{ &p1, &p2 };
    const allocator = std.testing.allocator;
    const script = try p2ms(allocator, &pubkeys, 1, 2);
    defer script.deinit();

    try std.testing.expectEqual(Opcode.op_checkmultisig, script.stack.items[6].op);
    try std.testing.expectEqual(Opcode.op_2, script.stack.items[5].op);
    try std.testing.expectEqualSlices(u8, &p2, script.stack.items[4].v);
    try std.testing.expectEqual(script.stack.items[3].push_bytes, 65);
    try std.testing.expectEqualSlices(u8, &p1, script.stack.items[2].v);
    try std.testing.expectEqual(script.stack.items[1].push_bytes, 65);
    try std.testing.expectEqual(Opcode.op_true, script.stack.items[0].op);
}

test "test hexCap" {
    var p1: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var p2: [130]u8 = "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af".*;

    var pubkeys: [2][]u8 = [2][]u8{ &p1, &p2 };
    const allocator = std.testing.allocator;
    const script = try p2ms(allocator, &pubkeys, 1, 2);
    defer script.deinit();

    try std.testing.expectEqual(script.hexCap(), 270);
}

test "toHex" {
    const uncompressed_pubkey: [130]u8 = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c".*;
    const compressed_pubkey: [66]u8 = "03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5".*;
    const expected_hex: [134]u8 = "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac".*;
    const expected_hex2: [70]u8 = "2103525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5ac".*;
    const allocator = std.testing.allocator;
    const script = try p2pk(allocator, &uncompressed_pubkey);
    defer script.deinit();

    var hexbuf: [134]u8 = undefined;
    try script.toHex(&hexbuf);
    try std.testing.expectEqualSlices(u8, &expected_hex, &hexbuf);

    const script2 = try p2pk(allocator, &compressed_pubkey);
    defer script2.deinit();

    var hexbuf2: [70]u8 = undefined;
    try script2.toHex(&hexbuf2);
    try std.testing.expectEqualSlices(u8, &expected_hex2, &hexbuf2);

    // p2ms
    var p1: [130]u8 = "04d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a2".*;
    var p2: [130]u8 = "04ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb1".*;
    var p3: [130]u8 = "04b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e7".*;

    var pubkeys: [3][]u8 = [3][]u8{ &p1, &p2, &p3 };
    const script3 = try p2ms(allocator, &pubkeys, 2, 3);
    defer script3.deinit();

    var hexbuf3: [402]u8 = undefined;
    try script3.toHex(&hexbuf3);
    const expectedhex3: [402]u8 = "524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae".*;
    try std.testing.expectEqualSlices(u8, &expectedhex3, &hexbuf3);
}

test "p2wpkh" {
    const allocator = std.testing.allocator;
    const hash: [40]u8 = "64cb674c9fdcb5c033ccb5d860978974ff02f400".*;
    const script = try p2wpkh(allocator, &hash);
    defer script.deinit();
    try std.testing.expectEqualStrings(&hash, script.stack.items[2].v);
    try std.testing.expectEqual(20, script.stack.items[1].push_bytes);
    try std.testing.expectEqual(Opcode.op_false, script.stack.items[0].op);
    const cap = script.hexCap();
    const buffer = try allocator.alloc(u8, cap);
    defer allocator.free(buffer);
    try script.toHex(buffer);
    const expected_hex: [44]u8 = "001464cb674c9fdcb5c033ccb5d860978974ff02f400".*;
    try std.testing.expectEqualStrings(&expected_hex, buffer);
}

test "decode" {
    const allocator = std.testing.allocator;
    const hex = "76a9143134047164cbf22f9f54fe738853de24a9f3cf1b88ac".*;
    const script = try Script.decode(allocator, &hex);
    defer script.deinit();

    const e1 = "3134047164cbf22f9f54fe738853de24a9f3cf1b".*;
    try std.testing.expectEqual(script.stack.items[0].op, Opcode.op_dup);
    try std.testing.expectEqual(script.stack.items[1].op, Opcode.op_hash160);
    try std.testing.expectEqual(script.stack.items[2].push_bytes, 20);
    try std.testing.expectEqualStrings(script.stack.items[3].v, &e1);
    try std.testing.expectEqual(script.stack.items[4].op, Opcode.op_equalverify);
    try std.testing.expectEqual(script.stack.items[5].op, Opcode.op_checksig);

    const hex2 = "0014199b7da15e4b0da4e62b5c3a01dd41255b8c45d6".*;
    const script2 = try Script.decode(allocator, &hex2);
    defer script2.deinit();
    const e2 = "199b7da15e4b0da4e62b5c3a01dd41255b8c45d6".*;
    try std.testing.expectEqual(script2.stack.items[0].op, Opcode.op_false);
    try std.testing.expectEqual(script2.stack.items[1].push_bytes, 20);
    try std.testing.expectEqualStrings(script2.stack.items[2].v, &e2);
}

test "getScriptType" {
    const allocator = std.testing.allocator;
    const hash: [40]u8 = "64cb674c9fdcb5c033ccb5d860978974ff02f400".*;
    const s = try p2wpkh(allocator, &hash);
    defer s.deinit();
    const t = try s.getType();
    try std.testing.expectEqual(t, ScriptType.p2wpkh);

    const hex = "0014841b80d2cc75f5345c482af96294d04fdd66b2b7".*;
    const decoded = try Script.decode(allocator, &hex);
    defer decoded.deinit();
    const t2 = try decoded.getType();
    try std.testing.expectEqual(t2, ScriptType.p2wpkh);
}
