# kami-exe

Windows 卡密客户端（Zig 交叉编译，单文件 EXE，含 TLS）。

与 `kami-license` 服务端配套，与 `kami-app`（Android）共用同一套协议：
每设备 ECDSA P-256 专属密钥 + 请求签名，APK/EXE 内均无共享对称密钥。

## 构建

```sh
zig build-exe src/main.zig -target x86_64-windows-gnu -O ReleaseSmall \
  -femit-bin=kami-tool.exe
```

容器内已装 `zig`（Alpine 包）。产物约 1.1 MB，自带 Windows libc 与 TLS 实现，无需额外依赖。

## 行为

1. 首次运行：读取或生成本机 ECDSA 密钥，设备标识 = 公钥 SHA-256 前 8 字节
2. 输入卡密 → 激活 → 打印套餐、剩余天数、已解锁功能
3. 卡密与对称加密的私钥存于 `%APPDATA%/kami-tool/`
4. 再次运行：自动用本地密钥复验，无需重输卡密

## 该主机的坑

主机前置 AES 挑战会拦截非 Googlebot UA。程序用普通 Chrome UA 发起请求，
收到挑战页后自行用 AES-128-CBC 解出 `__test` cookie 再重试（`solveChallenge`）。

## Windows 控制台编码

Windows 控制台默认代码页是 GBK(936)，而程序输出全部是 UTF-8，直接打印中文必然乱码。
程序启动时调用 `SetConsoleOutputCP(65001)` 与 `SetConsoleCP(65001)` 切换为 UTF-8。

另外两处容易踩：

- **不要输出 ANSI 转义序列**（`\x1b[32m` 之类）。Windows 10 以下 cmd 不支持，
  会原样显示成 `←[32m`，看起来也像乱码。已全部移除，改用纯文本标记。
- **双击运行时结束时暂停**。若进程没有附着到已有控制台（`GetConsoleWindow()` 返回空），
  说明是双击启动，结束前提示「按回车键退出」，否则窗口一闪而过看不到结果。

## 未验证

容器无法运行 Windows 程序，EXE 仅验证了：
- PE 头与结构有效（`MZ` / `PE\0\0`）
- 同源码的 Linux 构建跑通了完整流程（激活、验签、重启复用）

Windows 上的实际运行（控制台编码、TLS 证书链）**未实测**。
