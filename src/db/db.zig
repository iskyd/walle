const std = @import("std");
const sqlite = @import("sqlite");
const Output = @import("../tx.zig").Output;
const Input = @import("../tx.zig").Input;
const assert = std.debug.assert;

pub fn openDB() !sqlite.Db {
    const db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "/home/mattia/dev/walle/test.db" },
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
