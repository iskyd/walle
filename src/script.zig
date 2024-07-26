const std = @import("std");
const assert = std.debug.assert;

pub const ScriptType = enum(u8) {
    P2WPKH,
};

pub const opcode = enum(u8) {
    // constants
    OP_FALSE = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_TRUE = 0x51, // OP_TRUE == OP_1
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Flow control
    OP_NOP = 0x61,
    OP_IF = 0x63,
    OP_ELSE = 0x64,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,

    // Splice
    OP_SIZE = 0x82,

    // Bitwise logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    // Arithmetic
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_BOOLAND = 0x9a,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,

    // Crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    OP_CHECKSIGADD = 0xba,

    // Locktime
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,

    // Pseudowords
    OP_PUBKEYHASH = 0xfd,
    OP_PUBKEY = 0xfe,
    OP_INVALIDOPCODE = 0xff,

    // Reserved words
    OP_RESERVED = 0x50,
    OP_VER = 0x62,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // n <= 16
    pub fn fromNum(n: u8) opcode {
        assert(n <= 16);
        return switch (n) {
            0 => opcode.OP_FALSE,
            1 => opcode.OP_TRUE,
            2 => opcode.OP_2,
            3 => opcode.OP_3,
            4 => opcode.OP_4,
            5 => opcode.OP_5,
            6 => opcode.OP_6,
            7 => opcode.OP_7,
            8 => opcode.OP_8,
            9 => opcode.OP_9,
            10 => opcode.OP_10,
            11 => opcode.OP_11,
            12 => opcode.OP_12,
            13 => opcode.OP_13,
            14 => opcode.OP_14,
            15 => opcode.OP_15,
            16 => opcode.OP_16,
            else => unreachable,
        };
    }
};

const ScriptOp = union(enum) { op: opcode, v: []const u8, pushbytes: usize };

pub const Script = struct {
    allocator: std.mem.Allocator,

    // Script stack is a LIFO (as the data structur imply) during execution
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
                ScriptOp.pushbytes => |pb| {
                    var pbbuf: [2]u8 = undefined;
                    _ = try std.fmt.bufPrint(&pbbuf, "{x}", .{pb});
                    @memcpy(buffer[cur .. cur + 2], pbbuf[0..2]);
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
                ScriptOp.pushbytes => |_| {
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
        const redeemscript = try allocator.alloc(u8, c);
        defer allocator.free(redeemscript);
        try self.toHex(redeemscript);
        _ = try std.fmt.hexToBytes(buffer, redeemscript);
    }

    pub fn decode(allocator: std.mem.Allocator, hex: []const u8) !Script {
        var script = Script.init(allocator);
        var current: usize = 0;
        while (current < hex.len) {
            const v = try std.fmt.parseInt(u32, hex[current .. current + 2], 16);
            current += 2;
            // It is a valid opcode
            if (v == 0 or v >= 76) {
                const op: opcode = @enumFromInt(v);
                try script.push(ScriptOp{ .op = op });
            } else { // it is a pushbytes
                try script.push(ScriptOp{ .pushbytes = v });
                const data = hex[current .. current + (v * 2)];
                try script.push(ScriptOp{ .v = data });
                current += v * 2;
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
        if (self.stack.items.len == 3 and self.stack.items[0].op == opcode.OP_FALSE and self.stack.items[1].pushbytes == 20) {
            return ScriptType.P2WPKH;
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
                ScriptOp.pushbytes => |pb| {
                    try writer.print("OP_PUSHBYTES_{d} ", .{pb});
                },
            }
        }
        //try writer.print("\n");
    }
};

// pubkey as str
pub fn p2pk(allocator: std.mem.Allocator, pubkey: []const u8) !Script {
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .pushbytes = pubkey.len / 2 });
    try script.push(ScriptOp{ .v = pubkey });
    try script.push(ScriptOp{ .op = opcode.OP_CHECKSIG });

    return script;
}

// pubkeys as str
pub fn p2ms(allocator: std.mem.Allocator, pubkeys: [][]const u8, m: u8, n: u8) !Script {
    assert(m <= n);
    assert(m != 0);
    assert(n <= 16);

    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = opcode.fromNum(m) });
    for (pubkeys) |pubkey| {
        try script.push(ScriptOp{ .pushbytes = pubkey.len / 2 });
        try script.push(ScriptOp{ .v = pubkey });
    }
    try script.push(ScriptOp{ .op = opcode.fromNum(n) });
    try script.push(ScriptOp{ .op = opcode.OP_CHECKMULTISIG });

    return script;
}

// NOT TESTED
pub fn p2pkh(allocator: std.mem.Allocator, pkeyhash: []const u8) !Script {
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = opcode.OP_DUP });
    try script.push(ScriptOp{ .op = opcode.OP_HASH160 });
    try script.push(ScriptOp{ .pushbytes = 20 });
    try script.push(ScriptOp{ .v = pkeyhash });
    try script.push(ScriptOp{ .op = opcode.OP_EQUALVERIFY });
    try script.push(ScriptOp{ .op = opcode.OP_CHECKSIG });

    return script;
}

// pay to witness pubkey hash
pub fn p2wpkh(allocator: std.mem.Allocator, pubkeyhash: []const u8) !Script {
    assert(pubkeyhash.len == 40);
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = opcode.OP_FALSE });
    try script.push(ScriptOp{ .pushbytes = 20 });
    try script.push(ScriptOp{ .v = pubkeyhash[0..] });

    return script;
}

// to implement p2pkh, p2sh
test "test p2pk" {
    const uncompressedpubkey: [130]u8 = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c".*;
    const allocator = std.testing.allocator;
    const script = try p2pk(allocator, &uncompressedpubkey);
    defer script.deinit();

    try std.testing.expectEqual(opcode.OP_CHECKSIG, script.stack.items[2].op);
    try std.testing.expectEqualSlices(u8, &uncompressedpubkey, script.stack.items[1].v);
    try std.testing.expectEqual(script.stack.items[0].pushbytes, 65);
}

test "test p2ms" {
    var p1: [130]u8 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4".*;
    var p2: [130]u8 = "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af".*;

    var pubkeys: [2][]u8 = [2][]u8{ &p1, &p2 };
    const allocator = std.testing.allocator;
    const script = try p2ms(allocator, &pubkeys, 1, 2);
    defer script.deinit();

    try std.testing.expectEqual(opcode.OP_CHECKMULTISIG, script.stack.items[6].op);
    try std.testing.expectEqual(opcode.OP_2, script.stack.items[5].op);
    try std.testing.expectEqualSlices(u8, &p2, script.stack.items[4].v);
    try std.testing.expectEqual(script.stack.items[3].pushbytes, 65);
    try std.testing.expectEqualSlices(u8, &p1, script.stack.items[2].v);
    try std.testing.expectEqual(script.stack.items[1].pushbytes, 65);
    try std.testing.expectEqual(opcode.OP_TRUE, script.stack.items[0].op);
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
    const uncompressedpubkey: [130]u8 = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c".*;
    const compressedpubkey: [66]u8 = "03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5".*;
    const expectedhex: [134]u8 = "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac".*;
    const expectedhex2: [70]u8 = "2103525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5ac".*;
    const allocator = std.testing.allocator;
    const script = try p2pk(allocator, &uncompressedpubkey);
    defer script.deinit();

    var hexbuf: [134]u8 = undefined;
    try script.toHex(&hexbuf);
    try std.testing.expectEqualSlices(u8, &expectedhex, &hexbuf);

    const script2 = try p2pk(allocator, &compressedpubkey);
    defer script2.deinit();

    var hexbuf2: [70]u8 = undefined;
    try script2.toHex(&hexbuf2);
    try std.testing.expectEqualSlices(u8, &expectedhex2, &hexbuf2);

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
    try std.testing.expectEqual(20, script.stack.items[1].pushbytes);
    try std.testing.expectEqual(opcode.OP_FALSE, script.stack.items[0].op);
    const cap = script.hexCap();
    const buffer = try allocator.alloc(u8, cap);
    defer allocator.free(buffer);
    try script.toHex(buffer);
    const expectedhex: [44]u8 = "001464cb674c9fdcb5c033ccb5d860978974ff02f400".*;
    try std.testing.expectEqualStrings(&expectedhex, buffer);
}

test "decode" {
    const allocator = std.testing.allocator;
    const hex = "76a9143134047164cbf22f9f54fe738853de24a9f3cf1b88ac".*;
    const script = try Script.decode(allocator, &hex);
    defer script.deinit();

    const e1 = "3134047164cbf22f9f54fe738853de24a9f3cf1b".*;
    try std.testing.expectEqual(script.stack.items[0].op, opcode.OP_DUP);
    try std.testing.expectEqual(script.stack.items[1].op, opcode.OP_HASH160);
    try std.testing.expectEqual(script.stack.items[2].pushbytes, 20);
    try std.testing.expectEqualStrings(script.stack.items[3].v, &e1);
    try std.testing.expectEqual(script.stack.items[4].op, opcode.OP_EQUALVERIFY);
    try std.testing.expectEqual(script.stack.items[5].op, opcode.OP_CHECKSIG);

    const hex2 = "0014199b7da15e4b0da4e62b5c3a01dd41255b8c45d6".*;
    const script2 = try Script.decode(allocator, &hex2);
    defer script2.deinit();
    const e2 = "199b7da15e4b0da4e62b5c3a01dd41255b8c45d6".*;
    try std.testing.expectEqual(script2.stack.items[0].op, opcode.OP_FALSE);
    try std.testing.expectEqual(script2.stack.items[1].pushbytes, 20);
    try std.testing.expectEqualStrings(script2.stack.items[2].v, &e2);
}

test "getScriptType" {
    const allocator = std.testing.allocator;
    const hash: [40]u8 = "64cb674c9fdcb5c033ccb5d860978974ff02f400".*;
    const s = try p2wpkh(allocator, &hash);
    defer s.deinit();
    const t = try s.getType();
    try std.testing.expectEqual(t, ScriptType.P2WPKH);

    const hex = "0014841b80d2cc75f5345c482af96294d04fdd66b2b7".*;
    const decoded = try Script.decode(allocator, &hex);
    defer decoded.deinit();
    const t2 = try decoded.getType();
    try std.testing.expectEqual(t2, ScriptType.P2WPKH);
}
