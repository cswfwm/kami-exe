const std = @import("std");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// 服务端 ECDSA 公钥（X.509 SPKI 的 DER，base64）
const SERVER_PUBKEY_B64 =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgxbmKjxvbzeI3AsJm0LNid4MOrKj" ++
    "imR93TDcB2T6hWSBrQjhJpBkYHsMRdDK/XZLCeCSCCC9UxEXyuwvuqn+fw==";

// 服务端地址与公钥均以异或形式存放，运行时才解出，
// 静态 strings 搜不到，避免「改一行字符串指向私服」。
const URL_MASK: u8 = 0x5A;
const BASE_ENC = [_]u8{ 0x32,0x2E,0x2E,0x2A,0x29,0x60,0x75,0x75,0x22,0x22,0x22,0x22,0x22,0x77,0x22,0x74,0x2F,0x2F,0x31,0x74,0x2A,0x2A,0x74,0x2F,0x3B };

fn decodeBase(buf: *[64]u8) []u8 {
    const n = BASE_ENC.len;
    for (BASE_ENC, 0..) |b, i| buf[i] = b ^ URL_MASK;
    return buf[0..n];
}

// 服务端 EC 公钥（SEC1 未压缩点，65 字节，0x04 开头）
const SERVER_PUB_ENC = [_]u8{ 0x5E,0xD2,0x09,0x7C,0x2F,0xF8,0x2A,0xFD,0x6E,0x9C,0x5D,0xBE,0x5E,0x0D,0xD3,0x66,0x74,0x2C,0x0E,0xEE,0xE7,0xCB,0x6B,0x1B,0x7F,0x36,0x22,0x7F,0x1C,0xA0,0x94,0x11,0xCB,0x39,0x83,0xEE,0x90,0x8B,0xFA,0x50,0x47,0xA4,0xF6,0x2B,0x0A,0x1D,0x0B,0xC2,0xA4,0x0A,0xA2,0x5B,0x44,0x3E,0x45,0x3D,0x79,0x3B,0xCF,0x34,0x6D,0x5B,0x2D,0x39,0x50 };

fn serverPub() [65]u8 {
    var out: [65]u8 = undefined;
    for (SERVER_PUB_ENC, 0..) |b, i| out[i] = b ^ URL_MASK;
    return out;
}

const HKDF_INFO = "kami-v1";

/// ECIES：每次请求生成临时密钥对，与服务端公钥做 ECDH 协商出会话密钥。
/// 抓包者只能看到临时公钥，没有服务端私钥就推不出共享密钥。
const Sealed = struct {
    epk: [65]u8,
    salt: [16]u8,
    iv: [12]u8,
    ct: []u8,
    tag: [16]u8,
    session_key: [32]u8,

    fn deinit(self: Sealed, a: std.mem.Allocator) void {
        a.free(self.ct);
    }
};

fn eciesSeal(a: std.mem.Allocator, plain: []const u8) !Sealed {
    const P256 = std.crypto.ecc.P256;
    const crypto = std.crypto;

    // 临时私钥（32 字节大端标量）
    var sk: [32]u8 = undefined;
    crypto.random.bytes(&sk);
    const skScalar = P256.scalar.Scalar.fromBytes(sk, .big) catch {
        // 极小概率越界，重取一次
        crypto.random.bytes(&sk);
        return eciesSeal(a, plain);
    };
    const skBytes = skScalar.toBytes(.big);

    // 临时公钥 = sk * G
    const pubPoint = try P256.basePoint.mul(skBytes, .big);
    const epk = pubPoint.toUncompressedSec1();

    // 共享密钥 = sk * serverPub
    const srv_pub = serverPub();
    const serverPoint = try P256.fromSec1(&srv_pub);
    const sharedPoint = try serverPoint.mul(skBytes, .big);
    const shared = sharedPoint.affineCoordinates().x.toBytes(.big);

    // HKDF-SHA256(shared, salt, info) 取 32 字节
    var salt: [16]u8 = undefined;
    crypto.random.bytes(&salt);
    var session_key: [32]u8 = undefined;
    hkdfSha256(&shared, &salt, &session_key);

    // AES-256-GCM
    var iv: [12]u8 = undefined;
    crypto.random.bytes(&iv);
    const ct = try a.alloc(u8, plain.len);
    var tag: [16]u8 = undefined;
    const AesGcm = crypto.aead.aes_gcm.Aes256Gcm;
    AesGcm.encrypt(ct, &tag, plain, "", iv, session_key);

    return Sealed{ .epk = epk, .salt = salt, .iv = iv, .ct = ct, .tag = tag, .session_key = session_key };
}

fn eciesOpen(a: std.mem.Allocator, ivB64: []const u8, ctB64: []const u8, tagB64: []const u8, key: [32]u8) ![]u8 {
    const iv_raw = try b64UrlDecode(a, ivB64);
    defer a.free(iv_raw);
    const ct_raw = try b64UrlDecode(a, ctB64);
    defer a.free(ct_raw);
    const tag_raw = try b64UrlDecode(a, tagB64);
    defer a.free(tag_raw);

    if (iv_raw.len != 12 or tag_raw.len != 16) return error.BadEnvelope;

    var iv: [12]u8 = undefined;
    @memcpy(&iv, iv_raw);
    var tag: [16]u8 = undefined;
    @memcpy(&tag, tag_raw);

    const out = try a.alloc(u8, ct_raw.len);
    const AesGcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    AesGcm.decrypt(out, ct_raw, tag, "", iv, key) catch {
        a.free(out);
        return error.BadMac;
    };
    return out;
}

/// HKDF-SHA256（RFC 5869），单块输出 32 字节
fn hkdfSha256(ikm: []const u8, salt: []const u8, out: *[32]u8) void {
    var prk: [32]u8 = undefined;
    var hm = std.crypto.auth.hmac.sha2.HmacSha256.init(salt);
    hm.update(ikm);
    hm.final(&prk);

    var hm2 = std.crypto.auth.hmac.sha2.HmacSha256.init(&prk);
    hm2.update(HKDF_INFO);
    hm2.update(&[_]u8{1});
    hm2.final(out);
}

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// 挑战解出的 cookie，同一次运行内复用
var g_cookie: ?[16]u8 = null;
var g_cookie_set = false;

// Zig 0.13 的 std 只提供 SetConsoleOutputCP，这两个自行声明
extern "kernel32" fn SetConsoleCP(wCodePageID: std.os.windows.UINT) callconv(std.os.windows.WINAPI) std.os.windows.BOOL;
extern "kernel32" fn GetConsoleWindow() callconv(std.os.windows.WINAPI) ?std.os.windows.HWND;

/// 控制台输出全部为 UTF-8，而 Windows 控制台默认是 GBK(936)，
/// 不切代码页中文必然乱码。同时记录是否为双击启动（控制台由系统分配）。
fn platformInit() bool {
    if (@import("builtin").os.tag != .windows) return false;

    const w = std.os.windows;
    // 65001 = UTF-8
    _ = w.kernel32.SetConsoleOutputCP(65001);
    _ = SetConsoleCP(65001);

    // 双击运行时进程没有附着到已有控制台，结束后窗口会立刻关闭
    const hwnd = GetConsoleWindow();
    return hwnd == null;
}

fn pauseAtEnd() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("\n  按回车键退出...", .{}) catch return;
    var b: [8]u8 = undefined;
    var r = std.io.getStdIn().reader();
    _ = r.readUntilDelimiterOrEof(&b, '\n') catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const wasLaunchedByDoubleClick = platformInit();

    const stdout = std.io.getStdOut().writer();
    try stdout.print("\n  卡密工具\n", .{});
    try stdout.print("  ------------------------\n\n", .{});

    const device_id = try deviceIdFromKey(a);
    defer a.free(device_id);
    try stdout.print("  设备标识  {s}\n\n", .{device_id});

    if (readSaved(a) catch null) |code| {
        defer a.free(code);
        try stdout.print("  正在校验已保存的卡密...\n", .{});
        if (try request(a, "verify", code, device_id)) |res| {
            defer res.deinit(a);
            try showUnlocked(stdout, res);
            if (wasLaunchedByDoubleClick) pauseAtEnd();
            return;
        }
        try stdout.print("  校验未通过，请重新输入。\n\n", .{});
    }

    var buf: [64]u8 = undefined;
    try stdout.print("  请输入卡密 (XXXX-XXXX-XXXX-XXXX): ", .{});
    var stdin_reader = std.io.getStdIn().reader();
    const raw = try stdin_reader.readUntilDelimiterOrEof(&buf, '\n') orelse return;
    const code = try normalize(a, raw);
    defer a.free(code);

    try stdout.print("\n  正在激活...\n", .{});
    const res = (try request(a, "activate", code, device_id)) orelse {
        try stdout.print("\n  激活失败，请检查卡密是否正确。\n", .{});
        if (wasLaunchedByDoubleClick) pauseAtEnd();
        std.process.exit(1);
    };
    defer res.deinit(a);

    saveCode(a, code) catch {};
    try showUnlocked(stdout, res);
    if (wasLaunchedByDoubleClick) pauseAtEnd();
}

// ---------------------------------------------------------------- 展示

const Result = struct {
    plan: []u8,
    features: [][]u8,
    expire_at: i64,
    /// 解密后的功能数据。拿不到它就无法使用付费功能。
    data: ?[]u8,
    /// 功能数据密钥（来自服务端下发），用于下次校验
    data_key: [32]u8,

    fn deinit(self: Result, a: std.mem.Allocator) void {
        a.free(self.plan);
        for (self.features) |f| a.free(f);
        a.free(self.features);
        if (self.data) |d| a.free(d);
    }
};

fn showUnlocked(w: anytype, r: Result) !void {
    try w.print("\n  [OK] 卡密解锁成功\n\n  ", .{});
    try remainText(w, r.expire_at);
    try w.print("\n\n", .{});

    try w.print("  套餐      {s}\n", .{planLabel(r.plan)});
    if (r.expire_at > 0) {
        const days = @divTrunc(r.expire_at, 86400);
        const today = @divTrunc(std.time.timestamp(), 86400);
        try w.print("  到期      约 {d} 天后\n", .{days - today});
    } else {
        try w.print("  到期      永久\n", .{});
    }
    try w.print("  已解锁    ", .{});
    for (r.features, 0..) |f, i| {
        if (i > 0) try w.print("、", .{});
        try w.print("{s}", .{featureLabel(f)});
    }
    try w.print("\n", .{});
    if (r.data) |d| {
        try w.print("  数据      {d} 字节（已解密）\n", .{d.len});
    }
    try w.print("\n", .{});
}

fn remainText(w: anytype, expire_at: i64) !void {
    if (expire_at <= 0) {
        try w.print("永久有效", .{});
        return;
    }
    const left = expire_at - std.time.timestamp();
    if (left <= 0) {
        try w.print("已过期", .{});
        return;
    }
    const days = @divTrunc(left, 86400);
    if (days > 0) {
        try w.print("剩余 {d} 天", .{days});
    } else {
        try w.print("剩余 {d} 小时", .{@divTrunc(left, 3600)});
    }
}

fn planLabel(p: []const u8) []const u8 {
    if (std.mem.eql(u8, p, "basic")) return "基础版";
    if (std.mem.eql(u8, p, "pro")) return "专业版";
    if (std.mem.eql(u8, p, "trial7")) return "7 天试用";
    if (std.mem.eql(u8, p, "team")) return "团队版";
    return p;
}

fn featureLabel(f: []const u8) []const u8 {
    if (std.mem.eql(u8, f, "core")) return "基础功能";
    if (std.mem.eql(u8, f, "export")) return "数据导出";
    if (std.mem.eql(u8, f, "batch")) return "批量处理";
    if (std.mem.eql(u8, f, "api")) return "开放接口";
    return f;
}

// ---------------------------------------------------------------- 请求

fn request(a: std.mem.Allocator, action: []const u8, code: []const u8, device_id: []const u8) !?Result {
    // 密钥必须长期固定：服务端在首次注册后只认这一把公钥
    const kp = try loadOrCreateKey(a);
    const ts = std.time.timestamp();
    const nonce = try hexRandom(a, 16);
    defer a.free(nonce);

    const base = try std.fmt.allocPrint(a, "{s}\n{s}\n{d}\n{s}", .{ action, device_id, ts, nonce });
    defer a.free(base);
    const sig = try kp.sign(base, null);
    var der_buf: [72]u8 = undefined;
    const der = sig.toDer(&der_buf);

    const pub_sec1 = kp.public_key.toUncompressedSec1();
    const pub_b64 = try spkiB64(a, &pub_sec1);
    defer a.free(pub_b64);
    const sig_b64 = try b64UrlEncode(a, der);
    defer a.free(sig_b64);

    const inner = try std.fmt.allocPrint(a,
        "{{\"action\":\"{s}\",\"code\":\"{s}\",\"device\":\"{s}\",\"device_id\":\"{s}\"," ++
            "\"device_name\":\"Windows PC\",\"app_version\":\"1.0.0\"," ++
            "\"nonce\":\"{s}\",\"ts\":{d},\"pubkey\":\"{s}\",\"sig\":\"{s}\"}}",
        .{ action, code, device_id, device_id, nonce, ts, pub_b64, sig_b64 });
    defer a.free(inner);

    const sealed = try eciesSeal(a, inner);
    defer sealed.deinit(a);
    const body = try std.fmt.allocPrint(a,
        "{{\"epk\":\"{s}\",\"salt\":\"{s}\",\"iv\":\"{s}\",\"ct\":\"{s}\",\"tag\":\"{s}\"}}",
        .{ try b64UrlEncode(a, &sealed.epk), try b64UrlEncode(a, &sealed.salt),
           try b64UrlEncode(a, &sealed.iv), try b64UrlEncode(a, sealed.ct),
           try b64UrlEncode(a, &sealed.tag) });
    defer a.free(body);

    const resp = httpPost(a, action, body) catch {
        std.debug.print("  无法连接服务器\n", .{});
        return null;
    };
    defer a.free(resp);

    var final = resp;
    var retried: ?[]u8 = null;
    defer if (retried) |r| a.free(r);

    if (std.mem.indexOf(u8, resp, "slowAES.decrypt") != null) {
        if (!(try solveChallenge(a, resp))) {
            std.debug.print("  主机挑战未通过，请重试\n", .{});
            return null;
        }
        const retry = httpPost(a, action, body) catch {
            std.debug.print("  无法连接服务器\n", .{});
            return null;
        };
        retried = retry;
        final = retry;
        if (std.mem.indexOf(u8, retry, "slowAES.decrypt") != null) {
            std.debug.print("  主机挑战仍未通过\n", .{});
            return null;
        }
    }

    // GCM 认证失败即说明响应被篡改或来自错误的服务端
    const plain = openResponse(a, final, sealed.session_key) catch |err| {
        std.debug.print("  响应校验失败：{s}\n", .{@errorName(err)});
        return null;
    };
    defer a.free(plain);
    return parseResponse(a, plain);
}

/// 先验服务端 ECDSA 签名，再解密。伪造服务器没有私钥，过不了这一步。
fn openResponse(a: std.mem.Allocator, raw: []const u8, session_key: [32]u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, a, raw, .{}) catch return error.BadResponse;
    defer parsed.deinit();
    const obj = parsed.value.object;

    const ivS = if (obj.get("iv")) |v| v.string else return error.NoEnvelope;
    const ctS = if (obj.get("ct")) |v| v.string else return error.NoEnvelope;
    const tagS = if (obj.get("tag")) |v| v.string else return error.NoEnvelope;
    const sS = if (obj.get("s")) |v| v.string else return error.NoSignature;

    // 先验签再解密：签名覆盖 iv||ct||tag 的原始字节，
    // 因此即使会话密钥泄漏，攻击者也造不出合法响应。
    const iv_raw = try b64UrlDecode(a, ivS);
    defer a.free(iv_raw);
    const ct_raw = try b64UrlDecode(a, ctS);
    defer a.free(ct_raw);
    const tag_raw = try b64UrlDecode(a, tagS);
    defer a.free(tag_raw);
    const sig_der = try b64UrlDecode(a, sS);
    defer a.free(sig_der);

    const signed = try a.alloc(u8, iv_raw.len + ct_raw.len + tag_raw.len);
    defer a.free(signed);
    @memcpy(signed[0..iv_raw.len], iv_raw);
    @memcpy(signed[iv_raw.len..][0..ct_raw.len], ct_raw);
    @memcpy(signed[iv_raw.len + ct_raw.len ..][0..tag_raw.len], tag_raw);

    if (!(try verifyServerBytes(signed, sig_der))) {
        return error.UntrustedServer;
    }

    return eciesOpen(a, ivS, ctS, tagS, session_key);
}

fn httpPost(a: std.mem.Allocator, action: []const u8, body: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = a };
    defer client.deinit();

    var base_buf: [64]u8 = undefined;
    const base = decodeBase(&base_buf);
    const url = try std.fmt.allocPrint(a, "{s}/api.php?action={s}", .{ base, action });
    defer a.free(url);
    const uri = try std.Uri.parse(url);

    var hdr_buf: [16 * 1024]u8 = undefined;
    var headers: [3]std.http.Header = undefined;
    headers[0] = .{ .name = "user-agent", .value = UA };
    headers[1] = .{ .name = "content-type", .value = "application/json; charset=utf-8" };
    var hcount: usize = 2;

    // cookie 值为解密结果的 hex（16 字节 -> 32 字符）
    var cookie_buf: [64]u8 = undefined;
    if (g_cookie_set) {
        const c = g_cookie.?;
        var hexbuf: [32]u8 = undefined;
        for (c, 0..) |b, i| {
            _ = std.fmt.bufPrint(hexbuf[i * 2 .. i * 2 + 2], "{x:0>2}", .{b}) catch {};
        }
        const prefix = "__test=";
        @memcpy(cookie_buf[0..prefix.len], prefix);
        @memcpy(cookie_buf[prefix.len..][0..32], &hexbuf);
        headers[2] = .{ .name = "cookie", .value = cookie_buf[0 .. prefix.len + 32] };
        hcount = 3;
    }

    var req = try client.open(.POST, uri, .{
        .server_header_buffer = &hdr_buf,
        .extra_headers = headers[0..hcount],
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = body.len };
    try req.send();
    try req.writeAll(body);
    try req.finish();
    try req.wait();

    return req.reader().readAllAlloc(a, 256 * 1024);
}

// ---------------------------------------------------------------- 主机挑战

/// 从挑战页取 key/iv/ciphertext，AES-128-CBC 解密得出 __test cookie
fn solveChallenge(a: std.mem.Allocator, html: []const u8) !bool {
    _ = a;
    var parts: [3][]const u8 = undefined;
    var found: usize = 0;
    var idx: usize = 0;
    const marker = "toNumbers(\"";
    while (found < 3) {
        const p = std.mem.indexOfPos(u8, html, idx, marker) orelse break;
        const start = p + marker.len;
        const end = std.mem.indexOfPos(u8, html, start, "\"") orelse break;
        parts[found] = html[start..end];
        found += 1;
        idx = end;
    }

    var key: [16]u8 = undefined;
    var iv: [16]u8 = undefined;
    var ct: [64]u8 = undefined;
    const key_n = try hexToBytes(parts[0], &key);
    const iv_n = try hexToBytes(parts[1], &iv);
    const ct_n = try hexToBytes(parts[2], &ct);
    if (key_n != 16 or iv_n != 16 or ct_n == 0 or ct_n % 16 != 0) return false;

    const ctx = std.crypto.core.aes.Aes128.initDec(key);
    var prev: [16]u8 = iv;
    var cookie: [16]u8 = undefined;
    var written: usize = 0;
    var i: usize = 0;
    while (i < ct_n and written < 16) : (i += 16) {
        const cblock = ct[i..][0..16].*;
        var dec: [16]u8 = undefined;
        ctx.decrypt(&dec, &cblock);
        var plain: [16]u8 = undefined;
        for (0..16) |j| plain[j] = dec[j] ^ prev[j];
        const take = @min(16, 16 - written);
        @memcpy(cookie[written..][0..take], plain[0..take]);
        written += take;
        prev = cblock;
    }
    if (written < 16) return false;
    g_cookie = cookie;
    g_cookie_set = true;
    return true;
}

fn hexToBytes(hex: []const u8, out: []u8) !usize {
    if (hex.len % 2 != 0) return 0;
    const n = hex.len / 2;
    if (n > out.len) return 0;
    for (0..n) |i| {
        out[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }
    return n;
}

// ---------------------------------------------------------------- 解析

fn parseResponse(a: std.mem.Allocator, json_text: []const u8) !?Result {
    const parsed = std.json.parseFromSlice(std.json.Value, a, json_text, .{}) catch {
        std.debug.print("  响应格式异常\n", .{});
        return null;
    };
    defer parsed.deinit();
    const obj = parsed.value.object;

    const ok = if (obj.get("ok")) |v| switch (v) {
        .bool => |b| b,
        else => false,
    } else false;

    if (!ok) {
        if (obj.get("msg")) |m| switch (m) {
            .string => |s| std.debug.print("  服务端：{s}\n", .{s}),
            else => {},
        };
        return null;
    }

    const lic_s = obj.get("license").?.string;
    const sig_s = obj.get("sig").?.string;

    const payload = try b64UrlDecode(a, lic_s);
    defer a.free(payload);
    const sig_bytes = try b64UrlDecode(a, sig_s);
    defer a.free(sig_bytes);

    if (!(try verifyServerSignature(lic_s, sig_bytes))) {
        std.debug.print("  响应签名校验失败\n", .{});
        return null;
    }

    const pj = std.json.parseFromSlice(std.json.Value, a, payload, .{}) catch return null;
    defer pj.deinit();
    const pobj = pj.value.object;

    const plan_s = if (pobj.get("plan")) |v| v.string else "unknown";
    const expire_at: i64 = if (pobj.get("expire_at")) |v| switch (v) {
        .integer => |i| i,
        else => -1,
    } else -1;

    const arr = (pobj.get("features") orelse return null).array;
    const feats = try a.alloc([]u8, arr.items.len);
    for (arr.items, 0..) |item, i| {
        feats[i] = try a.dupe(u8, item.string);
    }

    // 功能数据必须解密成功，否则视为未授权
    var decoded: ?[]u8 = null;
    var dkey: [32]u8 = undefined;
    @memset(&dkey, 0);
    if (obj.get("data")) |dv| {
        const d = dv.object;
        const div = if (d.get("iv")) |v| v.string else "";
        const dct = if (d.get("ct")) |v| v.string else "";
        const dtg = if (d.get("tag")) |v| v.string else "";
        if (div.len > 0 and dct.len > 0 and dtg.len > 0) {
            // 密钥由服务端随数据一起下发；缺了它数据就是一串不可读的字节
            const ksrc = if (d.get("key")) |v| v.string else "";
            if (ksrc.len == 64) {
                for (0..32) |i| {
                    dkey[i] = std.fmt.parseInt(u8, ksrc[i * 2 .. i * 2 + 2], 16) catch 0;
                }
                decoded = eciesOpen(a, div, dct, dtg, dkey) catch null;
            }
        }
    }
    if (decoded == null) {
        std.debug.print("  功能数据缺失或无法解密\n", .{});
        return null;
    }

    return Result{
        .plan = try a.dupe(u8, plan_s),
        .features = feats,
        .expire_at = expire_at,
        .data = decoded,
        .data_key = dkey,
    };
}

/// 对任意字节用内置公钥验签
fn verifyServerBytes(msg: []const u8, sig_der: []const u8) !bool {
    const n = try std.base64.standard.Decoder.calcSizeForSlice(SERVER_PUBKEY_B64);
    var buf: [256]u8 = undefined;
    try std.base64.standard.Decoder.decode(buf[0..n], SERVER_PUBKEY_B64);

    const point = extractSpkiPoint(buf[0..n]) orelse return false;
    const pk = Ecdsa.PublicKey.fromSec1(point) catch return false;
    const sig = Ecdsa.Signature.fromDer(sig_der) catch return false;
    sig.verify(msg, pk) catch return false;
    return true;
}

fn verifyServerSignature(license_b64: []const u8, sig_der: []const u8) !bool {
    const n = try std.base64.standard.Decoder.calcSizeForSlice(SERVER_PUBKEY_B64);
    var buf: [256]u8 = undefined;
    try std.base64.standard.Decoder.decode(buf[0..n], SERVER_PUBKEY_B64);

    const point = extractSpkiPoint(buf[0..n]) orelse return false;
    const pk = Ecdsa.PublicKey.fromSec1(point) catch return false;
    const sig = Ecdsa.Signature.fromDer(sig_der) catch return false;
    sig.verify(license_b64, pk) catch return false;
    return true;
}

/// 从 X.509 SPKI 中取出 SEC-1 公钥点（BIT STRING 内 65 字节，0x04 开头）
fn extractSpkiPoint(der: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 2 < der.len) : (i += 1) {
        if (der[i] == 0x03 and der[i + 1] == 0x42 and i + 3 + 65 <= der.len) {
            return der[i + 3 .. i + 3 + 65];
        }
    }
    return null;
}

// ---------------------------------------------------------------- 编码

fn spkiB64(a: std.mem.Allocator, sec1: []const u8) ![]u8 {
    const prefix = [_]u8{
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    };
    const der = try a.alloc(u8, prefix.len + sec1.len);
    defer a.free(der);
    @memcpy(der[0..prefix.len], &prefix);
    @memcpy(der[prefix.len..], sec1);

    const out = try a.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
    _ = std.base64.standard.Encoder.encode(out, der);
    return out;
}

fn b64UrlEncode(a: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try a.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

fn b64UrlDecode(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = try dec.calcSizeForSlice(s);
    const out = try a.alloc(u8, n);
    try dec.decode(out, s);
    return out;
}

fn hexRandom(a: std.mem.Allocator, n: usize) ![]u8 {
    const raw = try a.alloc(u8, n);
    defer a.free(raw);
    std.crypto.random.bytes(raw);
    const out = try a.alloc(u8, n * 2);
    for (raw, 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 .. i * 2 + 2], "{x:0>2}", .{b}) catch {};
    }
    return out;
}

fn normalize(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    const out = try a.alloc(u8, raw.len);
    var n: usize = 0;
    for (raw) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            out[n] = std.ascii.toUpper(c);
            n += 1;
        }
    }
    return out[0..n];
}

// ---------------------------------------------------------------- 设备与持久化

/// 设备标识由本机长期密钥的公钥派生：密钥不变则标识不变，换密钥即为新设备。
/// 这样「服务端只认首次注册的公钥」与「同一台机器稳定复用」两者不冲突。
fn deviceIdFromKey(a: std.mem.Allocator) ![]u8 {
    const kp = try loadOrCreateKey(a);
    const pubkey = kp.public_key.toUncompressedSec1();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&pubkey);
    var digest: [32]u8 = undefined;
    h.final(&digest);

    var out: [21]u8 = undefined;
    for (digest[0..8], 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 .. i * 2 + 2], "{x:0>2}", .{b}) catch {};
    }
    out[16] = '-';
    for (digest[8..11], 0..) |b, i| {
        _ = std.fmt.bufPrint(out[17 + i * 2 .. 17 + i * 2 + 2], "{x:0>2}", .{b}) catch {};
    }
    return a.dupe(u8, &out);
}

fn configPath(a: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(a, "APPDATA")) |dir| {
        defer a.free(dir);
        return std.fmt.allocPrint(a, "{s}/kami-tool/code.txt", .{dir});
    } else |_| {
        return a.dupe(u8, "kami-code.txt");
    }
}

fn keyPath(a: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(a, "APPDATA")) |dir| {
        defer a.free(dir);
        return std.fmt.allocPrint(a, "{s}/kami-tool/device.key", .{dir});
    } else |_| {
        return a.dupe(u8, "kami-device.key");
    }
}

/// 读取本地长期密钥；不存在则生成 32 字节私钥并落盘。
fn loadOrCreateKey(a: std.mem.Allocator) !Ecdsa.KeyPair {
    const p = try keyPath(a);
    defer a.free(p);

    if (std.fs.cwd().openFile(p, .{})) |f| {
        defer f.close();
        var raw: [Ecdsa.SecretKey.encoded_length]u8 = undefined;
        const n = f.readAll(&raw) catch 0;
        if (n == raw.len) {
            const sk = Ecdsa.SecretKey.fromBytes(raw) catch return Ecdsa.KeyPair.create(null);
            return Ecdsa.KeyPair.fromSecretKey(sk) catch Ecdsa.KeyPair.create(null);
        }
    } else |_| {}

    const kp = try Ecdsa.KeyPair.create(null);
    if (std.fs.path.dirname(p)) |d| {
        std.fs.cwd().makePath(d) catch {};
    }
    if (std.fs.cwd().createFile(p, .{})) |f| {
        defer f.close();
        const sk_bytes = kp.secret_key.toBytes();
        f.writeAll(&sk_bytes) catch {};
    } else |_| {}
    return kp;
}

fn saveCode(a: std.mem.Allocator, code: []const u8) !void {
    const p = try configPath(a);
    defer a.free(p);
    if (std.fs.path.dirname(p)) |d| {
        std.fs.cwd().makePath(d) catch {};
    }
    const f = try std.fs.cwd().createFile(p, .{});
    defer f.close();
    try f.writeAll(code);
}

fn readSaved(a: std.mem.Allocator) !?[]u8 {
    const p = try configPath(a);
    defer a.free(p);
    const f = std.fs.cwd().openFile(p, .{}) catch return null;
    defer f.close();
    const data = try f.readToEndAlloc(a, 4096);
    defer a.free(data);
    return try a.dupe(u8, std.mem.trim(u8, data, " \r\n\t"));
}
