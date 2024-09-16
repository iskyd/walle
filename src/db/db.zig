const std = @import("std");
const sqlite = @import("sqlite");
const Output = @import("../tx.zig").Output;
const Input = @import("../tx.zig").Input;
const KeyPath = @import("../bip44.zig").KeyPath;
const Descriptor = @import("../bip44.zig").Descriptor;
const assert = std.debug.assert;

pub fn openDB() !sqlite.Db {
    const db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "./test.db" },
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
    const sqlBlocks = "CREATE TABLE IF NOT EXISTS blocks(hash VARCHAR(64) UNIQUE NOT NULL, heigth INTEGER UNIQUE NOT NULL);";
    var stmtBlocks = try db.prepare(sqlBlocks);
    defer stmtBlocks.deinit();

    const sqlTxs = "CREATE TABLE IF NOT EXISTS transactions(txid VARCHAR(64) PRIMARY KEY, rawtx TEXT NOT NULL, block_heigth INTEGER NOT NULL, is_coinbase INTEGER NOT NULL);";
    var stmtTxs = try db.prepare(sqlTxs);
    defer stmtTxs.deinit();

    const sqlOutputs = "CREATE TABLE IF NOT EXISTS outputs(txid VARCHAR(64), n INTEGER, amount INTEGER NOT NULL, unspent INTEGER, path TEXT NOT NULL, PRIMARY KEY(txid, n));";
    var stmtOutputs = try db.prepare(sqlOutputs);
    defer stmtOutputs.deinit();

    const sqlInputs = "CREATE TABLE IF NOT EXISTS inputs(txid VARCHAR(64), reference_output_txid VARCHAR(64) NOT NULL, reference_output_n INTEGER NOT NULL, PRIMARY KEY(txid, reference_output_txid, reference_output_n));";
    var stmtInputs = try db.prepare(sqlInputs);
    defer stmtInputs.deinit();

    const sqlDescriptors = "CREATE TABLE IF NOT EXISTS descriptors(extended_key VARCHAR(111) PRIMARY KEY, path TEXT NOT NULL, private INTEGER NOT NULL)";
    var stmtDescriptors = try db.prepare(sqlDescriptors);
    defer stmtDescriptors.deinit();

    const sqlBegin = "BEGIN TRANSACTION;";
    var stmtBegin = try db.prepare(sqlBegin);
    defer stmtBegin.deinit();
    const sqlCommit = "COMMIT;";
    var stmtCommit = try db.prepare(sqlCommit);
    defer stmtCommit.deinit();

    try stmtBegin.exec(.{}, .{});
    try stmtBlocks.exec(.{}, .{});
    try stmtTxs.exec(.{}, .{});
    try stmtOutputs.exec(.{}, .{});
    try stmtInputs.exec(.{}, .{});
    try stmtDescriptors.exec(.{}, .{});
    try stmtCommit.exec(.{}, .{});
}

pub fn saveBlock(db: *sqlite.Db, blockhash: [64]u8, heigth: usize) !void {
    const blockSql = "INSERT OR IGNORE INTO blocks(hash, heigth) VALUES(?, ?);";
    var stmtBlock = try db.prepare(blockSql);

    const sqlBegin = "BEGIN TRANSACTION;";
    var stmtBegin = try db.prepare(sqlBegin);
    defer stmtBegin.deinit();
    const sqlCommit = "COMMIT;";
    var stmtCommit = try db.prepare(sqlCommit);
    defer stmtCommit.deinit();

    try stmtBegin.exec(.{}, .{});
    try stmtBlock.exec(.{}, .{ .blockhash = blockhash, .heigth = heigth });
    try stmtCommit.exec(.{}, .{});
}

pub fn saveOutputs(allocator: std.mem.Allocator, db: *sqlite.Db, outputs: std.AutoHashMap([64]u8, Output)) !void {
    const sqlBegin = "BEGIN TRANSACTION;";
    var stmtBegin = try db.prepare(sqlBegin);
    defer stmtBegin.deinit();
    const sqlCommit = "COMMIT;";
    var stmtCommit = try db.prepare(sqlCommit);
    defer stmtCommit.deinit();

    try stmtBegin.exec(.{}, .{});

    var it = outputs.valueIterator();
    while (it.next()) |o| {
        assert(o.keypath != null);
        const sqlOutput = "INSERT OR IGNORE INTO outputs(txid, n, amount, unspent, path) VALUES(?, ?, ?, true, ?)";
        var stmtOutput = try db.prepare(sqlOutput);
        defer stmtOutput.deinit();

        const kp = try o.keypath.?.toStr(allocator);
        try stmtOutput.exec(.{}, .{ .txid = o.txid, .n = o.n, .amount = o.amount, .path = kp });
    }

    try stmtCommit.exec(.{}, .{});
}

pub fn saveInputs(db: *sqlite.Db, inputs: std.ArrayList(Input)) !void {
    const sqlBegin = "BEGIN TRANSACTION;";
    var stmtBegin = try db.prepare(sqlBegin);
    defer stmtBegin.deinit();
    const sqlCommit = "COMMIT;";
    var stmtCommit = try db.prepare(sqlCommit);
    defer stmtCommit.deinit();

    try stmtBegin.exec(.{}, .{});

    for (0..inputs.items.len) |i| {
        const input = inputs.items[i];
        const sqlInput = "INSERT OR IGNORE INTO inputs(txid, reference_output_txid, reference_output_n) VALUES(?, ?, ?)";
        var stmtInput = try db.prepare(sqlInput);
        defer stmtInput.deinit();
        try stmtInput.exec(.{}, .{ .txid = input.txid, .reference_output_txid = input.outputtxid, .reference_output_n = input.outputn });

        const sqlOutput = "UPDATE outputs SET unspent = false WHERE txid = ? AND n = ?";
        var stmtOutput = try db.prepare(sqlOutput);
        defer stmtOutput.deinit();
        try stmtOutput.exec(.{}, .{ .txid = input.outputtxid, .n = input.outputn });
    }

    try stmtCommit.exec(.{}, .{});
}

pub fn getOutput(db: *sqlite.Db, txid: [64]u8, n: u32) !?Output {
    const sqlOutput = "SELECT txid, n, amount AS c FROM outputs WHERE txid = ? AND n = ?";
    var stmt = try db.prepare(sqlOutput);
    defer stmt.deinit();
    const row = try stmt.one(struct { txid: [64]u8, n: u32, amount: u64 }, .{}, .{ .txid = txid, .n = n });
    if (row != null) {
        return Output{
            .txid = row.?.txid,
            .n = row.?.n,
            .amount = row.?.amount,
        };
    }
    return null;
}

pub fn getOutputDescriptorPath(allocator: std.mem.Allocator, db: *sqlite.Db, txid: [64]u8, n: u32) !KeyPath(5) {
    const sqlOutput = "SELECT path AS c FROM outputs WHERE txid = ? AND n = ?";
    var stmt = try db.prepare(sqlOutput);
    defer stmt.deinit();
    const row = try stmt.one(struct { path: []u8 }, .{}, .{ .txid = txid, .n = n }, allocator);
    if (row != null) {
        defer allocator.free(row.path);
        return KeyPath(5).fromStr(row.path);
    }

    return null;
}

pub fn saveTransaction(db: *sqlite.Db, block_heigth: usize, transactions: std.AutoHashMap([64]u8, bool), rawtransactionsmap: std.AutoHashMap([64]u8, []u8)) !void {
    const sqlBegin = "BEGIN TRANSACTION;";
    var stmtBegin = try db.prepare(sqlBegin);
    defer stmtBegin.deinit();
    const sqlCommit = "COMMIT;";
    var stmtCommit = try db.prepare(sqlCommit);
    defer stmtCommit.deinit();

    try stmtBegin.exec(.{}, .{});

    var it = transactions.keyIterator();
    while (it.next()) |txid| {
        const raw = rawtransactionsmap.get(txid.*);
        const sqlTx = "INSERT OR IGNORE INTO transactions(txid, rawtx, block_heigth, is_coinbase) VALUES(?, ?, ?, ?)";
        var stmtTx = try db.prepare(sqlTx);
        defer stmtTx.deinit();
        const isCoinbase = transactions.get(txid.*).?;
        try stmtTx.exec(.{}, .{ .txid = txid, .rawtx = raw.?, .block_heigth = block_heigth, .is_coinbase = isCoinbase });
    }

    try stmtCommit.exec(.{}, .{});
}

pub fn getCurrentBlockHeigth(db: *sqlite.Db) !?usize {
    const sqlBlock = "SELECT MAX(heigth) AS block_height FROM blocks;";
    var stmt = try db.prepare(sqlBlock);
    defer stmt.deinit();
    const row = try stmt.one(struct { block_heigth: usize }, .{}, .{});
    if (row != null) {
        return row.?.block_heigth;
    }
    return null;
}

pub fn getBalance(db: *sqlite.Db, current_block: usize) !u64 {
    const sql = "SELECT SUM(o.amount) AS balance FROM outputs o JOIN transactions t ON t.txid = o.txid WHERE ((t.block_heigth <= ? AND is_coinbase is true) OR (is_coinbase is false)) AND unspent = true;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.one(struct { balance: u64 }, .{}, .{ .block_heigth = current_block - 100 });
    if (row != null) {
        return row.?.balance;
    }
    return 0;
}

// Memory ownership to the caller
pub fn getDescriptors(allocator: std.mem.Allocator, db: *sqlite.Db) ![]Descriptor {
    const sql = "SELECT extended_key, path, private FROM descriptors;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const rows = try stmt.all(struct { extended_key: [111]u8, path: []const u8, private: bool }, allocator, .{}, .{});
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

pub fn getDescriptor(allocator: std.mem.Allocator, db: *sqlite.Db, path: []u8) !?Descriptor {
    const sql = "SELECT extended_key, path, private FROM descriptor WHERE path=? LIMIT 1;";
    var stmt = try db.prepare(sql);
    defer stmt.deinit();
    const row = try stmt.one(struct { extended_key: [111]u8, path: []const u8, private: bool }, allocator, .{}, .{ .path = path });
    if (row != null) {
        defer allocator.free(row.path);
        return Descriptor{ .extended_key = row.extended_key, .keypath = try KeyPath(3).fromStr(row.path), .private = row.private };
    }

    return null;
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
