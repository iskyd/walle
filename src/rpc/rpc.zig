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

const RpcClient = struct {
    allocator: std.mem.Allocator,
    httpClient: std.http.Client,
    uri: std.Uri,
    headers: std.http.Client.Request.Headers,
    rpcId: []const u8,
    authorization_buffer: []const u8,

    method: std.http.Method,

    pub fn init(allocator: std.mem.Allocator, uri: []const u8, userpassbuff: []const u8, rpcId: []const u8) !RpcClient {
        const uriParsed = std.Uri.parse(uri) catch unreachable;
        const client = std.http.Client{ .allocator = allocator };

        const encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, null);
        const authorization_buffer: []u8 = try allocator.alloc(u8, encoder.calcSize(userpassbuff.len));
        defer allocator.free(authorization_buffer);

        const encoded = encoder.encode(authorization_buffer, userpassbuff);
        // 7 u8 is for "Basic " and "="
        const buffer = try allocator.alloc(u8, 7 + encoded.len);
        _ = try std.fmt.bufPrint(buffer, "Basic {s}=", .{encoded});

        const content_type = std.http.Client.Request.Headers.Value{ .override = "text/plain" };
        const authorization = std.http.Client.Request.Headers.Value{ .override = buffer };
        const headers = std.http.Client.Request.Headers{ .content_type = content_type, .authorization = authorization };

        return .{
            .allocator = allocator,
            .httpClient = client,
            .uri = uriParsed,
            .headers = headers,
            .rpcId = rpcId,
            .authorization_buffer = buffer,
            .method = std.http.Method.POST,
        };
    }

    pub fn deinit(self: RpcClient) void {
        var client: *std.http.Client = @constCast(&self.httpClient);
        client.deinit();

        self.allocator.free(self.authorization_buffer);
    }

    fn request(self: RpcClient, allocator: std.mem.Allocator, options: std.http.Client.RequestOptions, body: []const u8) ![]u8 {
        var client: *std.http.Client = @constCast(&self.httpClient);
        var req = try client.open(self.method, self.uri, options);
        defer req.deinit();
        req.transfer_encoding = .chunked;
        try req.send();
        try req.writer().writeAll(body);
        try req.finish();
        try req.wait();

        return try req.reader().readAllAlloc(allocator, 8192);
    }
};

fn generateBody(allocator: std.mem.Allocator, rpcId: []const u8, method: []const u8, params: ?std.ArrayList(RpcParams)) ![]const u8 {
    // Number of chars in rpc body (static ones).
    var cap: usize = 49;
    cap += rpcId.len + method.len;

    // Stringify parameters in order to bring them into the final buffer;
    var paramsJSON = std.ArrayList(u8).init(allocator);
    defer paramsJSON.deinit();

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
                    } else {
                        cap += std.math.log10(num);
                    }
                    const stringedNum = try std.fmt.allocPrint(allocator, "{d}", .{num});
                    try paramsJSON.appendSlice(stringedNum);
                    try paramsJSON.appendSlice(",");
                    allocator.free(stringedNum);
                },
                // RpcParams.str => |str| {
                //     return str.len;
                // }
            }
            // cap += paramCap;
        }
        _ = paramsJSON.pop();
    }
    std.debug.print("{s}", .{paramsJSON});
    const buffer = try allocator.alloc(u8, cap);
    _ = try std.fmt.bufPrint(buffer, "{{\"jsonrpc\":\"1.0\",\"id\":\"{s}\",\"method\":\"{s}\",\"params\":[{s}]}}", .{ rpcId, method, paramsJSON });
    return buffer;
}

pub fn getBlockCount(allocator: std.mem.Allocator, client: RpcClient) !usize {
    const rpcMethod = "getblockcount".*;

    const body = try generateBody(allocator, client.rpcId, &rpcMethod, null);
    defer allocator.free(body);

    var server_header_buffer: [1024]u8 = undefined;
    const response = try client.request(allocator, .{ .headers = client.headers, .server_header_buffer = &server_header_buffer }, body);
    defer allocator.free(response);

    const parsed = try std.json.parseFromSlice(BlockCount, allocator, response, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    return parsed.value.result;
}

pub fn getBlockHash(allocator: std.mem.Allocator, client: RpcClient, blockN: usize) ![]u8 {
    const rpcMethod = "getblockhash".*;

    var params = std.ArrayList(RpcParams).init(allocator);
    defer params.deinit();
    try params.append(RpcParams{ .num = blockN });

    const body = try generateBody(allocator, client.rpcId, &rpcMethod, params);
    defer allocator.free(body);
    std.debug.print("{s}", .{body});
    var server_header_buffer: [1024]u8 = undefined;
    const response = try client.request(allocator, .{ .headers = client.headers, .server_header_buffer = &server_header_buffer }, body);
    defer allocator.free(response);

    std.debug.print("{s}", .{response});

    const parsed = try std.json.parseFromSlice(BlockHash, allocator, response, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    std.debug.print("{s}", .{parsed.value.result});
    return parsed.value.result;
}

// pub fn getBlock(client: RpcClient, hash: [64]u8) !Block {
//     const params = std.ArrayList([64]u8).init(client.allocator);
//     params.append(hash);
//     const data = try client.request(.{}, generateBody("getblock", params));
//     const parsed = try std.json.parseFromSlice(Block, client.allocator, data, .{ .allocate = .alloc_always });
//     defer parsed.deinit();
//     return parsed.value;
// }

test "generateBodyNoParams" {
    const allocator = std.testing.allocator;
    const uri = "http://localhost:18444".*;
    const userpassbuff = "walle:password".*;
    const rpcId = "walle".*;
    const method = "getblockcount".*;
    const client = try RpcClient.init(allocator, &uri, &userpassbuff, &rpcId);
    defer client.deinit();
    const body = try generateBody(allocator, client.rpcId, &method, null);
    defer allocator.free(body);
    const expectedString = "{\"jsonrpc\":\"1.0\",\"id\":\"walle\",\"method\":\"getblockcount\",\"params\":[]}".*;
    try std.testing.expectEqualStrings(&expectedString, body);
}

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

// test "getBlockCount" {
//     const allocator = std.testing.allocator;
//     const uri = "http://0.0.0.0:18444".*;
//     const userpassbuff = "walle:password".*;
//     const rpcId = "walle".*;
//     const client = try RpcClient.init(allocator, &uri, &userpassbuff, &rpcId);
//     defer client.deinit();
//     const blockCount = try getBlockCount(allocator, client);
//     std.debug.print("block: {d}\n", .{blockCount});
//     try std.testing.expect(blockCount >= 0);
// }

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
