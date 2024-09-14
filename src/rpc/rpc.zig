const std = @import("std");
const Block = @import("../block.zig").Block;

const RpcParams = union(enum) { num: usize, str: []u8 };

const GetBlockRawTxResult = struct {
    result: struct {
        tx: []struct {
            hex: []u8,
        },
    },
};

pub fn generateAuth(allocator: std.mem.Allocator, user: []const u8, pass: []const u8) ![]u8 {
    const buffer = try allocator.alloc(u8, user.len + pass.len + 1);
    defer allocator.free(buffer);
    @memcpy(buffer[0..user.len], user);
    buffer[user.len] = ':';
    @memcpy(buffer[user.len + 1 ..], pass);
    const encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');
    const authorization_buffer: []u8 = try allocator.alloc(u8, encoder.calcSize(buffer.len) + 6);
    _ = encoder.encode(authorization_buffer[6..], buffer);
    const b = "Basic ".*;
    @memcpy(authorization_buffer[0..6], &b);
    return authorization_buffer;
}

fn generateBody(allocator: std.mem.Allocator, rpcId: []const u8, method: []const u8, params: ?std.ArrayList(RpcParams)) ![]const u8 {
    // Number of chars in rpc body (static ones).
    var cap: usize = 49;
    cap += rpcId.len + method.len;
    var paramsCap: usize = 0;
    if (params != null) {
        // Number of commas in params.
        cap += params.?.items.len - 1;
        paramsCap += params.?.items.len - 1;
        // Number of chars in each param.
        for (0..params.?.items.len) |i| {
            const item = params.?.items[i];
            switch (item) {
                RpcParams.num => |num| {
                    const currentcap = if (num != 0) std.math.log10(num) + 1 else 1;
                    cap += currentcap;
                    paramsCap += currentcap;
                },
                RpcParams.str => |str| {
                    cap += str.len + 2;
                    paramsCap += str.len + 2; // 2 is for ""
                },
            }
        }
    }

    const buffer = try allocator.alloc(u8, cap);
    if (params != null) {
        var paramsBuffer = try allocator.alloc(u8, paramsCap);
        defer allocator.free(paramsBuffer);
        var current: usize = 0;
        for (0..params.?.items.len) |i| {
            const param: RpcParams = params.?.items[i];
            switch (param) {
                RpcParams.num => {
                    const currentcap = if (param.num != 0) std.math.log10(param.num) + 1 else 1;
                    _ = try std.fmt.bufPrint(paramsBuffer[current .. current + currentcap], "{d}", .{param.num});
                    current += currentcap;
                },
                RpcParams.str => {
                    paramsBuffer[current] = '"';
                    @memcpy(paramsBuffer[current + 1 .. current + param.str.len + 1], param.str);
                    paramsBuffer[current + param.str.len + 1] = '"';
                    current += param.str.len + 2;
                },
            }
            if (i < params.?.items.len - 1) {
                // not the last param, add comma
                paramsBuffer[current] = ',';
                current += 1;
            }
        }
        _ = try std.fmt.bufPrint(buffer, "{{\"jsonrpc\":\"1.0\",\"id\":\"{s}\",\"method\":\"{s}\",\"params\":[{s}]}}", .{ rpcId, method, paramsBuffer });
    } else {
        _ = try std.fmt.bufPrint(buffer, "{{\"jsonrpc\":\"1.0\",\"id\":\"{s}\",\"method\":\"{s}\",\"params\":[]}}", .{ rpcId, method });
    }
    return buffer;
}

fn req(client: *std.http.Client, uri: std.Uri, auth: []const u8, body: []const u8) !std.http.Client.Request {
    var server_header_buffer: [1024]u8 = undefined;
    const content_type = std.http.Client.Request.Headers.Value{ .override = "text/plain" };
    const authorization = std.http.Client.Request.Headers.Value{ .override = auth };
    const headers = std.http.Client.Request.Headers{ .content_type = content_type, .authorization = authorization };
    var request = try client.open(.POST, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = headers,
    });
    request.transfer_encoding = .chunked;
    try request.send();
    try request.writeAll(body);
    try request.finish();
    try request.wait();
    return request;
}

pub fn getBlockCount(allocator: std.mem.Allocator, client: *std.http.Client, location: []const u8, auth: []const u8) !usize {
    const uri = try std.Uri.parse(location);
    const rpcId = "walle".*;
    const rpcMethod = "getblockcount".*;
    const body = try generateBody(allocator, &rpcId, &rpcMethod, null);
    defer allocator.free(body);
    var request = try req(client, uri, auth, body);
    defer request.deinit();
    const response = try request.reader().readAllAlloc(allocator, 8192);
    defer allocator.free(response);
    const start: usize = 10;
    var end: usize = 10;
    while (end < response.len) {
        if (response[end] == '"') {
            break;
        }
        end += 1;
    }
    const blockcount = try std.fmt.parseInt(usize, response[start .. end - 1], 10);
    return blockcount;
}

pub fn getBlockHash(allocator: std.mem.Allocator, client: *std.http.Client, location: []const u8, auth: []const u8, blockcount: usize) ![64]u8 {
    const uri = try std.Uri.parse(location);
    const rpcId = "walle".*;
    const rpcMethod = "getblockhash".*;
    var params = std.ArrayList(RpcParams).init(allocator);
    defer params.deinit();
    const p = RpcParams{ .num = blockcount };
    try params.append(p);
    const body = try generateBody(allocator, &rpcId, &rpcMethod, params);
    defer allocator.free(body);
    var request = try req(client, uri, auth, body);
    defer request.deinit();
    const response = try request.reader().readAllAlloc(allocator, 8192);
    defer allocator.free(response);
    return response[11..75].*;
}

pub fn getBlockRawTx(allocator: std.mem.Allocator, client: *std.http.Client, location: []const u8, auth: []const u8, blockhash: [64]u8) ![][]u8 {
    const uri = try std.Uri.parse(location);
    const rpcId = "walle".*;
    const rpcMethod = "getblock".*;
    var params = std.ArrayList(RpcParams).init(allocator);
    defer params.deinit();
    const p1 = RpcParams{ .str = @constCast(&blockhash) };
    const p2 = RpcParams{ .num = 2 }; // verbosity
    try params.append(p1);
    try params.append(p2);
    const body = try generateBody(allocator, &rpcId, &rpcMethod, params);
    defer allocator.free(body);
    var request = try req(client, uri, auth, body);
    defer request.deinit();
    const response = try request.reader().readAllAlloc(allocator, 8192);
    defer allocator.free(response);
    const parsed = try std.json.parseFromSlice(GetBlockRawTxResult, allocator, response, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
    defer parsed.deinit();
    const result = try allocator.alloc([]u8, parsed.value.result.tx.len);
    for (0..parsed.value.result.tx.len) |i| {
        const tx = parsed.value.result.tx[i];
        result[i] = try allocator.dupe(u8, tx.hex);
    }
    return result;
}

pub fn sendRawTx(allocator: std.mem.Allocator, client: *std.http.Client, location: []const u8, auth: []const u8, signedTxHex: []u8) !void {
    const uri = try std.Uri.parse(location);
    const rpcId = "walle".*;
    const rpcMethod = "getblock".*;
    var params = std.ArrayList(RpcParams).init(allocator);
    defer params.deinit();
    const p = RpcParams{ .str = signedTxHex };
    try params.append(p);
    const body = try generateBody(allocator, &rpcId, &rpcMethod, params);
    defer allocator.free(body);
    var request = try req(client, uri, auth, body);
    defer request.deinit();
    const response = try request.reader().readAllAlloc(allocator, 8192);
    defer allocator.free(response);
}

// test "generateAuth" {
//     const user = "walle".*;
//     const pass = "password".*;
//     const expected = "Basic d2FsbGU6cGFzc3dvcmQ=".*;
//     const allocator = std.testing.allocator;
//     const auth = try generateAuth(allocator, &user, &pass);
//     defer allocator.free(auth);
//     try std.testing.expectEqualStrings(&expected, auth);
// }

// test "generateBodyNoParams" {
//     const allocator = std.testing.allocator;
//     const rpcId = "walle".*;
//     const method = "getblockcount".*;
//     const body = try generateBody(allocator, &rpcId, &method, null);
//     defer allocator.free(body);
//     const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"getblockcount\",\"params\":[]}".*;
//     try std.testing.expectEqualStrings(&expectedString, body);
// }

// test "generateBodyParams" {
//     const allocator = std.testing.allocator;
//     const rpcId = "walle".*;
//     const method = "getblockcount".*;
//     var params = std.ArrayList(RpcParams).init(allocator);
//     defer params.deinit();
//     const p = RpcParams{ .num = 300 };
//     try params.append(p);
//     const body = try generateBody(allocator, &rpcId, &method, params);
//     defer allocator.free(body);
//     const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"getblockcount\",\"params\":[300]}".*;
//     try std.testing.expectEqualStrings(&expectedString, body);
// }

// test "generateBodyMultipleParams" {
//     const allocator = std.testing.allocator;
//     const rpcId = "walle".*;
//     const method = "test".*;
//     var params = std.ArrayList(RpcParams).init(allocator);
//     defer params.deinit();
//     var p3str = "2031c78ac5e8aaafd25f6697eb23564238cce4b24116b2750e96808bc0311384".*;
//     const p1 = RpcParams{ .num = 300 };
//     const p2 = RpcParams{ .num = 500 };
//     const p3 = RpcParams{ .str = &p3str };
//     try params.append(p1);
//     try params.append(p2);
//     try params.append(p3);
//     const body = try generateBody(allocator, &rpcId, &method, params);
//     defer allocator.free(body);
//     const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"test\",\"params\":[300,500,\"2031c78ac5e8aaafd25f6697eb23564238cce4b24116b2750e96808bc0311384\"]}".*;
//     try std.testing.expectEqualStrings(&expectedString, body);
// }

// test "getBlockCount" {
//     const allocator = std.testing.allocator;
//     var client = std.http.Client{ .allocator = allocator };
//     defer client.deinit();
//     const location = "http://0.0.0.0:18444".*;
//     const user = "walle".*;
//     const pass = "password".*;
//     const auth = try generateAuth(allocator, &user, &pass);
//     defer allocator.free(auth);
//     const blockcount = try getBlockCount(allocator, &client, &location, auth);
//     std.debug.print("blockcount = {d}\n", .{blockcount});
//     try std.testing.expect(blockcount >= 0);
// }

// test "getBlockHash" {
//     const allocator = std.testing.allocator;
//     var client = std.http.Client{ .allocator = allocator };
//     defer client.deinit();
//     const location = "http://0.0.0.0:18444".*;
//     const user = "walle".*;
//     const pass = "password".*;
//     const auth = try generateAuth(allocator, &user, &pass);
//     defer allocator.free(auth);
//     const blockhash = try getBlockHash(allocator, &client, &location, auth, 300);
//     std.debug.print("blockhash: {s}\n", .{blockhash});
// }

// test "getBlockRawTx" {
//     const allocator = std.testing.allocator;
//     var client = std.http.Client{ .allocator = allocator };
//     defer client.deinit();
//     const location = "http://0.0.0.0:18444".*;
//     const user = "walle".*;
//     const pass = "password".*;
//     const auth = try generateAuth(allocator, &user, &pass);
//     defer allocator.free(auth);
//     const blockhash = "2031c78ac5e8aaafd25f6697eb23564238cce4b24116b2750e96808bc0311384".*;
//     const rawtxs = try getBlockRawTx(allocator, &client, &location, auth, blockhash);
//     defer {
//         for (0..rawtxs.len) |i| {
//             allocator.free(rawtxs[i]);
//         }
//         allocator.free(rawtxs);
//     }
//     for (0..rawtxs.len) |i| {
//         const raw = rawtxs[i];
//         std.debug.print("raw tx {s}\n", .{raw});
//     }
// }

test "sendRawTx" {
    const allocator = std.testing.allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const location = "http://0.0.0.0:18444".*;
    const user = "walle".*;
    const pass = "password".*;
    const auth = try generateAuth(allocator, &user, &pass);
    defer allocator.free(auth);
    // signedTxHex will come from createRawTransaction -> signRawTransaction. 
    var signedTxHex = "02000000000101c9da25a9134de631ee967523754c40703c88c86ebbbc94a7a94e4ad662f342610000000000fdffffff0200e1f50500000000160014c1923b56142275220f6958bcd5a16c2ae168a7e9c0ce0024010000001600142ca650dd0c82613aecf8ebf919e939f6d02d022c024730440220265e553a43b74bf963318bb0ac37ab330fffe54febd5c7ec970a51732420bac502204abcc9ee828b80b6eeccb253be7bfa6a40f1dcaaded7d29893c2d071f00889630121034413af7dca04880769b28def55063935e85cf01a0fb329154961fb6264eca70300000000".*;
    try sendRawTx(allocator, &client, &location, auth, &signedTxHex);
}
