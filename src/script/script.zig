const std = @import("std");

pub const opcode = enum(u8) {
    // constants
    OP_FALSE = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_TRUE = 0x51,

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
};

const ScriptOp = union(enum) { op: opcode, v: []const u8, pushbytes: usize };

const Script = struct {
    allocator: std.mem.Allocator,
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
            const scriptop = self.stack.items[self.stack.items.len - i - 1];
            switch (scriptop) {
                ScriptOp.op => |op| {
                    const opv = @intFromEnum(op);
                    var opbuf: [2]u8 = undefined;
                    _ = try std.fmt.bufPrint(&opbuf, "{x}", .{opv});
                    std.mem.copy(u8, buffer[cur .. cur + 2], opbuf[0..2]);
                    cur += 2;
                },
                ScriptOp.v => |v| {
                    std.mem.copy(u8, buffer[cur .. cur + v.len], self.stack.items[1].v);
                    cur += v.len;
                },
                ScriptOp.pushbytes => |pb| {
                    var pbbuf: [2]u8 = undefined;
                    _ = try std.fmt.bufPrint(&pbbuf, "{x}", .{pb});
                    std.mem.copy(u8, buffer[cur .. cur + 2], pbbuf[0..2]);
                    cur += 2;
                },
            }
        }
    }
};

pub fn p2pk(allocator: std.mem.Allocator, pubkey: []const u8) !Script {
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = opcode.OP_CHECKSIG });
    try script.push(ScriptOp{ .v = pubkey });
    try script.push(ScriptOp{ .pushbytes = pubkey.len / 2 });
    return script;
}

pub fn p2ms(m: u8, n: u8, pubkeys: [][33]u8) void {
    _ = pubkeys;
    _ = n;
    _ = m;
}

// to implement p2pkh, p2sh
test "test p2pk" {
    const uncompressedpubkey: [130]u8 = "04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c".*;
    const allocator = std.testing.allocator;
    const script = try p2pk(allocator, &uncompressedpubkey);
    defer script.deinit();

    try std.testing.expectEqual(opcode.OP_CHECKSIG, script.stack.items[0].op);
    try std.testing.expectEqualSlices(u8, &uncompressedpubkey, script.stack.items[1].v);
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
}
