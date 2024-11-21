const std = @import("std");
const sqlite = @import("sqlite");
const Output = @import("../tx.zig").Output;
const Input = @import("../tx.zig").Input;
const KeyPath = @import("../bip44.zig").KeyPath;
const Descriptor = @import("../bip44.zig").Descriptor;
const Block = @import("../block.zig").Block;
const assert = std.debug.assert;

pub fn openDB() !sqlite.Db {
    const db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "./walle.db" },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });

    return db;
}

pub fn closeDB(db: sqlite.Db) void {
    _ = db;
}

pub fn initDB(db: *sqlite.Db) !void {
    const sql_blocks = "CREATE TABLE IF NOT EXISTS blocks(hash VARCHAR(64) UNIQUE NOT NULL, height INTEGER UNIQUE NOT NULL);";
    var stmt_blocks = try db.prepare(sql_blocks);
    defer stmt_blocks.deinit();

    const sql_transactions = "CREATE TABLE IF NOT EXISTS transactions(txid VARCHAR(64) PRIMARY KEY, raw TEXT NOT NULL, block_height INTEGER NOT NULL, is_coinbase INTEGER NOT NULL);";
    var stmt_transactions = try db.prepare(sql_transactions);
    defer stmt_transactions.deinit();

    const sql_outputs = "CREATE TABLE IF NOT EXISTS outputs(txid VARCHAR(64), vout INTEGER NOT NULL, amount INTEGER NOT NULL, unspent INTEGER, path TEXT NOT NULL, PRIMARY KEY(txid, vout));";
    var stmt_outputs = try db.prepare(sql_outputs);
    defer stmt_outputs.deinit();

    const sql_inputs = "CREATE TABLE IF NOT EXISTS inputs(txid VARCHAR(64), reference_output_txid VARCHAR(64) NOT NULL, reference_output_vout INTEGER NOT NULL, PRIMARY KEY(txid, reference_output_txid, reference_output_vout));";
    var stmt_inputs = try db.prepare(sql_inputs);
    defer stmt_inputs.deinit();

    const sql_descriptors = "CREATE TABLE IF NOT EXISTS descriptors(extended_key VARCHAR(111) PRIMARY KEY, path TEXT NOT NULL, private INTEGER NOT NULL)";
    var stmt_descriptors = try db.prepare(sql_descriptors);
    defer stmt_descriptors.deinit();

    const sql_begin = "BEGIN TRANSACTION;";
    var stmt_begin = try db.prepare(sql_begin);
    defer stmt_begin.deinit();
    const sql_commit = "COMMIT;";
    var stmt_commit = try db.prepare(sql_commit);
    defer stmt_commit.deinit();

    try stmt_begin.exec(.{}, .{});
    try stmt_blocks.exec(.{}, .{});
    try stmt_transactions.exec(.{}, .{});
    try stmt_outputs.exec(.{}, .{});
    try stmt_inputs.exec(.{}, .{});
    try stmt_descriptors.exec(.{}, .{});
    try stmt_commit.exec(.{}, .{});
}

pub fn saveBlock(db: *sqlite.Db, blockhash: [64]u8, height: usize) !void {
    const sql_block = "INSERT OR IGNORE INTO blocks(hash, height) VALUES(?, ?);";
    var stmt_block = try db.prepare(sql_block);
    try stmt_block.exec(.{}, .{ .blockhash = blockhash, .height = height });
}

pub fn saveOutputs(allocator: std.mem.Allocator, db: *sqlite.Db, outputs: std.AutoHashMap([72]u8, Output)) !void {
    const sql_begin = "BEGIN TRANSACTION;";
    var stmt_begin = try db.prepare(sql_begin);
    defer stmt_begin.deinit();
    const sql_commit = "COMMIT;";
    var stmt_commit = try db.prepare(sql_commit);
    defer stmt_commit.deinit();

    try stmt_begin.exec(.{}, .{});

    var it = outputs.valueIterator();
    while (it.next()) |o| {
        assert(o.keypath != null);
        const sql_output = "INSERT OR IGNORE INTO outputs(txid, vout, amount, unspent, path) VALUES(?, ?, ?, true, ?)";
        var stmt_output = try db.prepare(sql_output);
        defer stmt_output.deinit();

        const keypath = try o.keypath.?.toStr(allocator, null);
        try stmt_output.exec(.{}, .{ .txid = o.txid, .vout = o.vout, .amount = o.amount, .path = keypath });
    }

    try stmt_commit.exec(.{}, .{});
}

pub fn saveInputsAndMarkOutputs(db: *sqlite.Db, inputs: std.ArrayList(Input)) !void {
    const sql_begin = "BEGIN TRANSACTION;";
    var stmt_begin = try db.prepare(sql_begin);
    defer stmt_begin.deinit();
    const sql_commit = "COMMIT;";
    var stmt_commit = try db.prepare(sql_commit);
    defer stmt_commit.deinit();

    try stmt_begin.exec(.{}, .{});

    for (0..inputs.items.len) |i| {
        const input = inputs.items[i];
        const sql_input = "INSERT OR IGNORE INTO inputs(txid, reference_output_txid, reference_output_vout) VALUES(?, ?, ?);";
        var stmt_input = try db.prepare(sql_input);
        defer stmt_input.deinit();
        try stmt_input.exec(.{}, .{ .txid = input.txid, .reference_output_txid = input.output_txid, .reference_output_vout = input.output_vout });

        const sql_output = "UPDATE outputs SET unspent = false WHERE txid = ? AND vout = ?;";
        var stmt_output = try db.prepare(sql_output);
        defer stmt_output.deinit();
        try stmt_output.exec(.{}, .{ .txid = input.output_txid, .vout = input.output_vout });
    }

    try stmt_commit.exec(.{}, .{});
}

pub fn existsOutput(db: *sqlite.Db, txid: [64]u8, vout: u32) !bool {
    const sql = "SELECT COUNT(*) AS total FROM  outputs WHERE txid = ? AND vout = ?";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.one(struct { total: usize }, .{}, .{ .txid = txid, .vout = vout });
    return row.?.total > 0;
}

pub fn getOutput(allocator: std.mem.Allocator, db: *sqlite.Db, txid: [64]u8, vout: u32) !?Output {
    const sql_output = "SELECT txid, vout, amount, unspent, path FROM outputs WHERE txid = ? AND vout = ?";
    var stmt = try db.prepare(sql_output);
    defer stmt.deinit();
    const row = try stmt.oneAlloc(struct { txid: [64]u8, vout: u32, amount: u64, unspent: bool, path: []u8 }, allocator, .{}, .{ .txid = txid, .vout = vout });

    if (row != null) {
        defer allocator.free(row.?.path);
        return Output{
            .txid = row.?.txid,
            .vout = row.?.vout,
            .amount = row.?.amount,
            .unspent = row.?.unspent,
            .keypath = try KeyPath(5).fromStr(row.?.path),
        };
    }

    return null;
}

pub fn getOutputDescriptorPath(allocator: std.mem.Allocator, db: *sqlite.Db, txid: [64]u8, vout: u32) !KeyPath(5) {
    const sql_output = "SELECT path FROM outputs WHERE txid = ? AND vout = ?";
    var stmt = try db.prepare(sql_output);
    defer stmt.deinit();
    const row = try stmt.oneAlloc(struct { path: []u8 }, allocator, .{}, .{ .txid = txid, .vout = vout });
    if (row != null) {
        defer allocator.free(row.?.path);
        return KeyPath(5).fromStr(row.?.path);
    }

    return error.DescriptorNotFound;
}

pub fn saveTransaction(db: *sqlite.Db, txid: [64]u8, transaction_raw: []u8, is_coinbase: bool, block_height: usize) !void {
    const sql_transaction = "INSERT OR IGNORE INTO transactions(txid, raw, block_height, is_coinbase) VALUES(?, ?, ?, ?)";
    var stmt_transaction = try db.prepare(sql_transaction);
    defer stmt_transaction.deinit();
    try stmt_transaction.exec(.{}, .{ .txid = txid, .raw = transaction_raw, .block_height = block_height, .is_coinbase = is_coinbase });
}

pub fn getLastBlock(db: *sqlite.Db) !?Block {
    const sql_block = "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1;";
    var stmt = try db.prepare(sql_block);
    defer stmt.deinit();
    const row = try stmt.one(struct { height: usize, hash: [64]u8 }, .{}, .{});
    if (row != null) {
        return Block{ .hash = row.?.hash, .height = row.?.block_height };
    }
    return null;
}

pub fn getBlock(db: *sqlite.Db, height: usize) !Block {
    const sql_block = "SELECT height AS block_height, hash FROM blocks WHERE height = ?;";
    var stmt = try db.prepare(sql_block);
    defer stmt.deinit();
    const row = try stmt.one(struct { block_height: usize, hash: [64]u8 }, .{}, .{ .height = height });
    if (row != null) {
        return Block{ .hash = row.?.hash, .height = row.?.block_height };
    }
    return error.BlockNotFound;
}

pub fn getBalance(db: *sqlite.Db, current_block: usize) !u64 {
    const sql = "SELECT SUM(o.amount) AS balance FROM outputs o JOIN transactions t ON t.txid = o.txid WHERE ((t.block_height <= ? AND is_coinbase is true) OR (is_coinbase is false)) AND unspent = true;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.one(struct { balance: u64 }, .{}, .{ .block_height = current_block - 100 });
    if (row != null) {
        return row.?.balance;
    }
    return 0;
}

// Memory ownership to the caller
pub fn getDescriptors(allocator: std.mem.Allocator, db: *sqlite.Db, private: bool) ![]Descriptor {
    const sql = "SELECT extended_key, path, private FROM descriptors WHERE private = ?;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const rows = try stmt.all(struct { extended_key: [111]u8, path: []const u8, private: bool }, allocator, .{}, .{ .private = private });
    defer {
        for (rows) |row| {
            allocator.free(row.path);
        }
        allocator.free(rows);
    }

    var descriptors = try allocator.alloc(Descriptor, rows.len);
    for (rows, 0..) |row, i| {
        descriptors[i] = Descriptor{ .extended_key = row.extended_key, .keypath = try KeyPath(3).fromStr(row.path), .private = row.private };
    }

    return descriptors;
}

pub fn getDescriptor(allocator: std.mem.Allocator, db: *sqlite.Db, path: []const u8, private: bool) !?Descriptor {
    const sql = "SELECT extended_key, path, private FROM descriptors WHERE path=? AND private=? LIMIT 1;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.oneAlloc(struct { extended_key: [111]u8, path: []const u8, private: bool }, allocator, .{}, .{ .path = path, .private = private });
    if (row != null) {
        defer allocator.free(row.?.path);
        return Descriptor{ .extended_key = row.?.extended_key, .keypath = try KeyPath(3).fromStr(row.?.path), .private = row.?.private };
    }

    return null;
}

pub fn saveDescriptor(allocator: std.mem.Allocator, db: *sqlite.Db, descriptor: Descriptor) !void {
    const sql = "INSERT INTO descriptors(extended_key, path, private) VALUES(?,?,?);";
    const path = try descriptor.keypath.toStr(allocator, null);
    defer allocator.free(path);

    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ .extended_key = descriptor.extended_key, .path = path, .private = descriptor.private });
}

pub fn countDescriptors(db: *sqlite.Db) !usize {
    const sql = "SELECT COUNT(*) as total FROM descriptors;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.one(struct { total: usize }, .{}, .{});
    return row.?.total;
}

pub fn getUsedKeyPaths(allocator: std.mem.Allocator, db: *sqlite.Db) ![]KeyPath(5) {
    const sql = "SELECT DISTINCT(path) AS path FROM outputs;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const rows = try stmt.all(struct { path: []const u8 }, allocator, .{}, .{});
    defer {
        for (rows) |row| {
            allocator.free(row.path);
        }
        allocator.free(rows);
    }

    var keypaths = try allocator.alloc(KeyPath(5), rows.len);
    for (rows, 0..) |row, i| {
        keypaths[i] = try KeyPath(5).fromStr(row.path);
    }
    return keypaths;
}

fn sqliteKeypathLastIndex(str: []const u8) u32 {
    const k = KeyPath(5).fromStr(str) catch return 0;
    return k.path[4];
}

pub fn getLastUsedIndexFromOutputs(db: *sqlite.Db, base_path: []u8) !?u32 {
    const sql_count = "SELECT COUNT(*) as total from outputs WHERE path LIKE ?;";
    var stmt_count = try db.prepare(sql_count);
    defer stmt_count.deinit();
    const row_count = try stmt_count.one(struct { total: usize }, .{}, .{base_path});
    if (row_count.?.total == 0) {
        return null;
    }

    try db.createScalarFunction("KEYPATH_LAST_INDEX", sqliteKeypathLastIndex, .{});
    const sql = "SELECT MAX(KEYPATH_LAST_INDEX(path)) AS last FROM outputs WHERE path LIKE ?;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.one(struct { last: u32 }, .{}, .{base_path});
    assert(row != null); // a row must exists since the count is > 0
    return row.?.last;
}

pub fn getUnspentOutputs(allocator: std.mem.Allocator, db: *sqlite.Db) ![]Output {
    const sql = "SELECT txid, vout, amount, unspent, path FROM outputs WHERE unspent = true";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const rows = try stmt.all(struct { txid: [64]u8, vout: u32, amount: u64, unspent: bool, path: []u8 }, allocator, .{}, .{});

    defer {
        for (rows) |row| {
            allocator.free(row.path);
        }
        allocator.free(rows);
    }

    var outputs = try allocator.alloc(Output, rows.len);
    for (rows, 0..) |row, i| {
        outputs[i] = Output{ .txid = row.txid, .vout = row.vout, .amount = row.amount, .unspent = row.unspent, .keypath = try KeyPath(5).fromStr(row.path) };
    }
    return outputs;
}

pub fn deleteOutputsFromBlockHeight(db: *sqlite.Db, block_height: usize) !void {
    const sql = "DELETE FROM ouputs o JOIN transactions t ON t.txid = o.txid WHERE t.block_height > ?;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ .block_height = block_height });
}

pub fn deleteInputsFromBlockHeight(db: *sqlite.Db, block_height: usize) !void {
    const sql = "DELETE FROM inputs i JOIN transactions t ON t.txid = i.txid WHERE t.block_height > ?;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ .block_height = block_height });
}

pub fn deleteTransactionsFromBlockHeight(db: *sqlite.Db, block_height: usize) !void {
    const sql = "DELETE FROM transactions WHERE block_height > ?;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ .block_height = block_height });
}

pub fn deleteBlocksFromBlockHeight(db: *sqlite.Db, block_height: usize) !void {
    const sql = "DELETE FROM blocks WHERE height > ?;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ .height = block_height });
}
