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

const ScriptOp = union { op: opcode, v: []const u8 };

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
};

pub fn p2pk(allocator: std.mem.Allocator, pubkey: [33]u8) !Script {
    var script = Script.init(allocator);
    try script.push(ScriptOp{ .op = opcode.OP_CHECKSIG });
    try script.push(ScriptOp{ .v = &pubkey });
    return script;
}

pub fn p2ms(m: u8, n: u8, pubkeys: [][33]u8) void {
    _ = pubkeys;
    _ = n;
    _ = m;
}

// to implement p2pkh, p2sh
test "test p2pk" {
    var pubkey: [33]u8 = undefined;
    const strpubkey: [66]u8 = "03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5".*;
    _ = try std.fmt.hexToBytes(&pubkey, &strpubkey);
    const allocator = std.testing.allocator;
    const script = try p2pk(allocator, pubkey);
    defer script.deinit();

    try std.testing.expectEqual(opcode.OP_CHECKSIG, script.stack.items[0].op);
    try std.testing.expectEqualSlices(u8, &pubkey, script.stack.items[1].v);
}
