const std = @import("std");
const Block = @import("../block.zig").Block;

const RpcParams = union(enum) { num: usize };

const BlockCount = struct {
    result: usize,
    @"error": ?[]u8,
    id: []u8,
};

const BlockHash = struct {
    result: []u8,
    @"error": ?[]u8,
    id: []u8,
};

fn generateAuth(allocator: std.mem.Allocator, user: []const u8, pass: []const u8) ![]u8 {
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
        // Number of chars in each param.
        for (0..params.?.items.len) |i| {
            const item = params.?.items[i];
            switch (item) {
                RpcParams.num => |num| {
                    if (num == 0) {
                        cap += 1;
                        paramsCap += 1;
                    } else {
                        cap += std.math.log10(num) + 1;
                        paramsCap += std.math.log10(num) + 1;
                    }
                },
                // RpcParams.str => |str| {
                //     return str.len;
                // }
            }
            // cap += paramCap;
        }
    }

    // std.debug.print("{s}", .{paramsJSON});
    const buffer = try allocator.alloc(u8, cap);
    if (params != null) {
        var paramsBuffer = try allocator.alloc(u8, paramsCap);
        defer allocator.free(paramsBuffer);
        _ = try std.fmt.bufPrint(paramsBuffer[0..], "{d}", .{params.?.items[0].num});
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
    const parsed = try std.json.parseFromSlice(BlockCount, allocator, response, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    return parsed.value.result;
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
    const parsed = try std.json.parseFromSlice(BlockCount, allocator, response, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    return parsed.value.result;
}

//pub fn getBlockHash(allocator: std.mem.Allocator, client: RpcClient, blockN: usize) ![]u8 {
//    const rpcMethod = "getblockhash".*;
//
//    var params = std.ArrayList(RpcParams).init(allocator);
//    defer params.deinit();
//    try params.append(RpcParams{ .num = blockN });
//
//    const body = try generateBody(allocator, client.rpcId, &rpcMethod, params);
//    defer allocator.free(body);
//    std.debug.print("{s}", .{body});
//    var server_header_buffer = allocator.alloc(u8, 1024);
//    defer allocator.free(server_header_buffer);
//    const response = try client.request(allocator, .{ .headers = client.headers, .server_header_buffer = &server_header_buffer }, body);
//    defer allocator.free(response);
//
//    std.debug.print("{s}", .{response});
//
//    const parsed = try std.json.parseFromSlice(BlockHash, allocator, response, .{ .allocate = .alloc_always });
//    defer parsed.deinit();
//    std.debug.print("{s}", .{parsed.value.result});
//    return parsed.value.result;
//}

// pub fn getBlock(client: RpcClient, hash: [64]u8) !Block {
//     const params = std.ArrayList([64]u8).init(client.allocator);
//     params.append(hash);
//     const data = try client.request(.{}, generateBody("getblock", params));
//     const parsed = try std.json.parseFromSlice(Block, client.allocator, data, .{ .allocate = .alloc_always });
//     defer parsed.deinit();
//     return parsed.value;
// }

//test "generateBodyNoParams" {
//    const allocator = std.testing.allocator;
//    const uri = "http://localhost:18444".*;
//    const userpassbuff = "walle:password".*;
//    const rpcId = "walle".*;
//    const method = "getblockcount".*;
//    const client = try RpcClient.init(allocator, &uri, &userpassbuff, &rpcId);
//    defer client.deinit();
//    const body = try generateBody(allocator, client.rpcId, &method, null);
//    defer allocator.free(body);
//    const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"getblockcount\",\"params\":[]}".*;
//    try std.testing.expectEqualStrings(&expectedString, body);
//}

// test "generateBodyNumericParam" {
//     const allocator = std.testing.allocator;
//     const uri = "http://localhost:1844".*;
//     const userpassbuff = "walle:password".*;
//     const rpcId = "walle".*;
//     const method = "getblockcount".*;
//     const blockN: usize = 0;
//     const client = try RpcClient.init(allocator, &uri, &userpassbuff, &rpcId);
//     defer client.deinit();
//     var params = std.ArrayList(RpcParams).init(allocator);
//     defer params.deinit();
//     try params.append(RpcParams{ .num = blockN });
//     const body = try generateBody(allocator, client.rpcId, &method, params);
//     defer allocator.free(body);
//     const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"getblockcount\",\"params\":[0]}".*;
//     try std.testing.expectEqualString(&expectedString, body);
// }

//test "getBlockCount" {
//    const allocator = std.testing.allocator;
//    var client = std.http.Client{ .allocator = allocator };
//    defer client.deinit();
//    const location = "http://0.0.0.0:18444".*;
//    const user = "walle".*;
//    const pass = "password".*;
//    const auth = try generateAuth(allocator, &user, &pass);
//    defer allocator.free(auth);
//    const blockCount = try getBlockCount(allocator, &client, &location, auth);
//    std.debug.print("block: {d}\n", .{blockCount});
//    try std.testing.expect(blockCount >= 0);
//}

// test "getBlockHash" {
//     const allocator = std.testing.allocator;
//     const uri = "http://0.0.0.0:18444".*;
//     const userpassbuff = "walle:password".*;
//     const rpcId = "walle".*;
//     const client = try RpcClient.init(allocator, &uri, &userpassbuff, &rpcId);
//     defer client.deinit();
//     const blockHash = try getBlockHash(allocator, client, 0);
//     std.debug.print("block hash: {s}", .{blockHash});
//     try std.testing.expect(blockHash.len > 0);
// }

test "generateAuth" {
    const user = "walle".*;
    const pass = "password".*;
    const expected = "Basic d2FsbGU6cGFzc3dvcmQ=".*;
    const allocator = std.testing.allocator;
    const auth = try generateAuth(allocator, &user, &pass);
    defer allocator.free(auth);
    try std.testing.expectEqualStrings(&expected, auth);
}

test "generateBodyParams" {
    const allocator = std.testing.allocator;
    const rpcId = "walle".*;
    const method = "getblockcount".*;
    var params = std.ArrayList(RpcParams).init(allocator);
    defer params.deinit();
    const p = RpcParams{ .num = 300 };
    try params.append(p);
    const body = try generateBody(allocator, &rpcId, &method, params);
    defer allocator.free(body);
    const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"getblockcount\",\"params\":[300]}".*;
    try std.testing.expectEqualStrings(&expectedString, body);
}
