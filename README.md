# 移动云电脑 (Ecloud CloudPC) 协议级保活工具

> 基于对移动云电脑 Windows V3.8.2 客户端的完全逆向分析，用纯 Python（仅依赖 `requests` + `pycryptodome`）实现协议级保活。

## ⚡ 核心结论

**桌面会话保活不需要 SPICE 协议，不需要 uSmartView 二进制，纯 HTTP 就够了。**

这个结论是通过抓包证伪了源码分析得出的初始判断——详见后文的"关键反转"章节。

## 🎯 项目背景

移动云电脑断开连接一段时间后会自动关机，对挂机和长时间任务很不友好。市面上常见的保活方案要么是「套娃」（Docker 里跑 Linux 客户端 + Xvfb + 模拟点击，内存占用高、容易失效），要么依赖官方客户端进程常驻。

本项目将移动云电脑 Windows V3.8.2 客户端**完全逆向**，最终用纯 Python 实现协议级保活。

## 📋 功能特性

- ✅ **协议级登录**：密码登录 → accessTicket → accessToken，完整登录流程
- ✅ **RSA-1024 加解密**：请求体加密、响应体解密
- ✅ **HmacSHA1 签名**：V2.0 签名方案，完全复刻客户端
- ✅ **桌面会话保活**：通过 `/resource/desktopUptime` 和 `/session/machineConnect` 接口保持在线
- ✅ **全自动配置**：首次登录只需输入账号密码，后续全部自动化
- ✅ **极简依赖**：仅需 `requests` + `pycryptodome`

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 首次登录

```bash
python main.py login
```

按提示输入账号密码，工具会自动：
1. 登录获取 `accessToken`
2. 列出所有桌面实例
3. 选择要保活的桌面
4. 保存凭证和设备指纹到 `data/` 目录

### 保活

```bash
# 单次保活
python main.py desktop-keepalive

# 无限循环保活（每5分钟一次）
python main.py desktop-keepalive --loop --interval 300

# 指定轮数
python main.py desktop-keepalive --rounds 10 --interval 300
```

### 定时任务（crontab）

```bash
# 每5分钟保活一次
*/5 * * * * cd ~/ecloud-cloudpc-keepalive && python main.py desktop-keepalive --rounds 1
```

## 🔧 技术原理

### 协议流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                      完整请求构造过程                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 构造业务参数 + commonParams + accessToken                    │
│  2. JSON 序列化 → RSA-1024 PKCS1 分块加密(117字节/块) → base64  │
│  3. HTTP body = {"params": "<base64>"}                          │
│  4. URL 查询串: AccessKey + SignatureMethod + ...               │
│  5. stringToSign = "POST\n" + quote(apiPath+endpoint) + "\n"    │
│     + sha256(querystring)                                       │
│  6. Signature = HmacSHA1(stringToSign, "BC_SIGNATURE&" + secretKey) │
│  7. POST <baseUrl><apiPath>/<endpoint>?<签名查询串>              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 登录流程

```
密码 ──/login/verify──▶ accessTicket ──/login/verifyAccessTicket──▶ accessToken
                              │
                              ├─ 30002009 (未授信设备) → 短信 + /login/trustDevice
                              ├─ 30002060 (二次验证)   → 短信 + /login/verifyTwoFactorAuthSms
                              ├─ 30002063 (增强策略)   → 短信 + /login/verifyLoginEnhanceSms
                              └─ userId 字段           → 4A MFA（未实现）
                              │
                              ▼
                    /resource/desktopUptime
                    /session/machineConnect
                              │
                              ▼
                         桌面保活 ✓
```

### 关键接口

| 接口 | 作用 | 频率 | 说明 |
|------|------|------|------|
| `/user/getSysTime` | 获取服务器时间 | 验证用 | 不需要登录，用于验证签名是否正确 |
| `/login/verify` | 密码登录 | 首次 | 返回 accessTicket |
| `/login/verifyAccessTicket` | 兑换 accessToken | 首次 | 返回 accessToken |
| `/user/getDeviceInfo` | 获取桌面列表 | 首次 | 返回 machineList |
| `/resource/desktopUptime` | 查询桌面运行时长 | **周期性** | ⭐ **保活核心接口** |
| `/session/machineConnect` | 桌面会话登记 | 连接时 + 定期 | 保活辅助接口 |

### 签名算法详解 (V2.0)

```python
# 1. 构建查询参数
query = {
    "AccessKey": "53bb79015a3f47c4be166d9371f68f14",
    "SignatureMethod": "HmacSHA1",
    "SignatureNonce": uuid4.hex,          # 随机 UUID（去横线）
    "SignatureVersion": "V2.0",
    "Timestamp": utc8_timestamp(),         # UTC+8, YYYY-MM-DDTHH:MM:SSZ
}

# 2. 生成规范字符串
canonical = urlencode(sorted(query.items()))

# 3. 计算哈希
hash_step = sha256(canonical.encode()).hexdigest()

# 4. 构建待签名字符串
api_endpoint = quote(API_PATH + endpoint, safe="")
string_to_sign = f"POST\n{api_endpoint}\n{hash_step}"

# 5. 计算签名
signing_key = "BC_SIGNATURE&" + secret_key  # 注意前缀！
signature = hmac.new(signing_key.encode(), string_to_sign.encode(), sha1).hexdigest()
```

**关键点：**
- `BC_SIGNATURE&` 是固定的 salt 前缀，不可省略
- 时间戳必须是 UTC+8 格式
- SignatureNonce 使用 uuid4.hex（去掉横杠）

### 请求体加密 (RSA-1024)

```python
# 合并参数
merged = {**业务参数, **commonParams, "accessToken": token}
data = json.dumps(merged).encode('utf-8')

# RSA-1024 PKCS1 分块加密（每块 117 字节）
chunk_size = 117  # 1024/8 - 11
out = b''
for i in range(0, len(data), chunk_size):
    out += cipher.encrypt(data[i:i+chunk_size])

# Base64 编码
params_b64 = base64.b64encode(out).decode()
http_body = {"params": params_b64}
```

**响应解密：** 同样的格式，用私钥分块（128字节）解密。

### 关键常量

| 常量 | 值 | 来源 |
|------|-----|------|
| `baseUrl` | `https://cloudpc.ecloud.10086.cn` | 客户端配置 |
| `apiPath` | `/api/cem/gateway/outer/cem-webapi` | 客户端配置 |
| `accessKey` | `53bb79015a3f47c4be166d9371f68f14` | settingValue.js 解密 |
| `secretKey` | `6b0d3b93f3aa4c7ea076c841bead1ddd` | settingValue.js 解密 |
| HMAC 前缀 | `BC_SIGNATURE&` | 固定值 |
| RSA | 1024-bit, PKCS1 | 客户端公钥 |
| companyCode | `ECloud` | 业务参数 |
| clientVersion | `3.8.2` | 客户端版本 |

## 🔍 逆向分析过程

### 第一步：确认是 Electron 应用

用 7-Zip 打开安装包 `Ecloud_CloudComputer_x64_V3.8.2_setup.exe`，发现是 NSIS 安装器，里面套了一个 `app.7z`（574MB）。解开后目录结构：

```
LICENSE.electron.txt          ← Electron 官方版权
resources\app.asar             ← Electron 标志性打包文件
icudtl.dat                     ← Chromium 国际化数据
chrome_100_percent.pak         ← Chromium 资源
ffmpeg.dll / libGLESV2.dll     ← Chromium 媒体/图形栈
```

确认是 Electron 应用，业务代码全在 `app.asar` 里。

### 第二步：解包 app.asar

asar 格式很简单：一个 JSON 头（记录文件列表 + 偏移量）+ 拼接的文件数据。解出来 10,467 个文件。

但打开 `service/user.js` 一看，字符串全被 javascript-obfuscator 混淆了：

```javascript
const _0x350a6f = _0x456a;
async ["loginWithPassword"](_0x5a082a, _0x1d6aaa) {
    const _0x2b9a6d = await EcloudHttpUtil.post(
        EcloudServerUrl.LOGIN_CHECK_USER_PASSWORD, {
            'username': _0x5a082a,
            'password': _0x1d6aaa,
            ...
```

### 第三步：反混淆

写了个 AST 遍历脚本，递归替换所有 `_0xXXXXXX` 别名，解码字符串数组。踩了几个坑：

- 字符串数组函数在文件**底部**（函数声明提升，执行时要收集全部机制语句）
- 方法体内部有局部别名 `const _0x2b9e33 = _0x350a6f`，要递归解析
- 解码器内部有 base64 + URI 编码的延迟初始化，必须真正调用一次才生效

最终 125 个文件全部还原，解码 15,931 个字符串。反混淆后的代码完全可读。

### 第四步：还原协议（签名 + 加密）

这是最关键的一步。从 `ecloudHttpUtil.js` 的 `getFullurl` 和 `post` 方法里，完整还原了请求的两层加密。

#### 4.1 URL 签名（HmacSHA1）

复刻 `ecloudHttpUtil.js:189-204`：

```javascript
query = {
    "AccessKey": "53bb79015a3f47c4be166d9371f68f14",
    "SignatureMethod": "HmacSHA1",
    "SignatureNonce": uuid.uuid4().hex,
    "SignatureVersion": "V2.0",
    "Timestamp": utc8_timestamp,
}
canonical = urllib.parse.urlencode(query)
hash_step = hashlib.sha256(canonical.encode()).hexdigest()
string_to_sign = f"POST\n{quote(api_path + endpoint)}\n{hash_step}"
signing_key = "BC_SIGNATURE&" + secret_key  # 注意前缀！
signature = hmac.new(signing_key.encode(), string_to_sign.encode(), hashlib.sha1).hexdigest()
```

这是中国移动 Ecloud 平台标准的 V2.0 签名方案，`BC_SIGNATURE&` 前缀是它的固定 salt。

#### 4.2 请求体加密（RSA-1024）

整个 JSON body 用 RSA 公钥加密后放在 `{"params": "<base64>"}` 里：

```python
# RSA-1024, PKCS1 padding, 分块加密（每块 117 字节）
merged = {**业务参数, **commonParams, "accessToken": token}
data = json.dumps(merged).encode('utf-8')
chunk_size = 117  # 1024/8 - 11
out = b''
for i in range(0, len(data), chunk_size):
    out += cipher.encrypt(data[i:i+chunk_size])
params_b64 = base64.b64encode(out).decode()
http_body = {"params": params_b64}
```

响应也是同样的格式，用私钥分块（128字节）解密。

#### 4.3 提取密钥

密钥不在源码里明文存储，而是用 AES-256-CBC 加密放在 `config/settingValue.js`：

```
密钥派生: key = SHA256("Ecloud-Computer-" + platform)  # platform = "win32"
iv  = key[:16]
```

解密后拿到 `accessKey`、`secretKey`、RSA 公钥。私钥还套了一层——用硬编码的 `kk`/`vv`（AES-256-CBC）再加密了一次。完整的解密链：

```
settingValue.js (hex blob)
  → AES-256-CBC(SHA256("Ecloud-Computer-win32")) → JSON 配置
  → privateKey 字段还是 AES-256-CBC(kk, vv) 加密的 PEM
  → 解密后才是真正的 RSA 私钥
```

#### 4.4 验证协议正确性

写完后第一件事是验证签名能不能被服务端接受。调一个不需要登录的接口 `/user/getSysTime`：

```python
resp = http.post("/user/getSysTime")
# RESPONSE: {'systime': '2026-06-14 12:28:11'}
# === server accepted signature + encryption ===
```

服务端返回了真实时间——证明 HmacSHA1 签名、RSA 加密、设备指纹全部正确。这是整个项目的第一个里程碑。

### 第五步：抓包突破（关键反转）

到这一步，登录和账号保活都实现了。但**桌面会话保活**卡住了。

从源码分析得出的结论是：真正的桌面连接由 `uSmartView_VDI_Client.exe` 维持，SCG 网关认证 + 穿云 Trunk + SPICE 握手协议全在这个二进制内部，Electron 源码里 `grep -r "SCG\|spice\|穿云\|10800"` 零匹配。

我当时判断「Python 无法纯协议保活桌面会话」。

**直到抓包。**

用 Reqable 抓了一次「连接桌面后」的流量，导出 HAR。关键是我能用自己的 RSA 私钥**解密 HAR 里的所有密文**。解密后发现了三个源码里没有的接口：

| 接口 | 作用 | 频率 |
|------|------|------|
| `/resource/desktopUptime` | 查询桌面运行时长 | 周期性 ⭐ |
| `/session/machineConnect` | 桌面会话登记 | 连接时 1 次 |
| `/machine/pushConnectEventData` | 连接事件上报 | 连接时 1 次 |

`/resource/desktopUptime` 的请求体极其简单：

```json
{"instanceId": "CCA-2b44466f2dd04fbcb73477d637c9108f"}
```

响应：

```json
{"body": "13小时38分54秒"}
```

**就是这个接口。** 它不需要 SPICE，不需要 uSmartView，只需要 `accessToken` + `instanceId`。

#### 验证保活有效性

用抓包的真实凭证调用 `desktopUptime`，运行时长持续增长：

```
12:47:46 启动保活，间隔 5s
12:47:47 运行时长: 11小时8分7秒    ← 第1轮
12:47:52 运行时长: 11小时8分12秒   ← 第2轮 (+5秒)
12:47:57 运行时长: 11小时8分17秒   ← 第3轮 (+5秒)
```

运行时的增长和实际经过时间完全吻合，证明服务端在为这个会话累计在线时长。

**纯 HTTP 保活真实有效**，之前的判断被证伪了。

这个反转很有意思：源码分析告诉你「复杂协议在二进制里，Python 做不到」，但抓包告诉你「服务端其实只看一个简单的 HTTP 心跳」。两个证据冲突时，**抓包（实际行为）永远优先于源码（设计意图）**。

### 第六步：全自动实现

最后一步是让保活真正「全自动」——用户只填账号密码，剩下全自动。

#### 6.1 自动获取桌面列表

从渲染层 bundle (`index-53f3f1a5.js`) 里找到桌面列表接口：

```javascript
// POST /user/getDeviceInfo
// 参数: {accessToken, companyCode:"ECloud", allCompany:true, version:"1.0.0"}
// 响应: body.machineList[]  每项含 {instanceId, machineId, machineName, ...}
```

#### 6.2 字段必要性实测

有个意外发现：通过逐字段删除测试，发现服务端**完全不校验设备指纹字段**：

```
[完整 18 字段]  OK → 13小时51分29秒
[只保留 6 个]   OK → 13小时51分29秒
[只保留 4 个]   OK → 13小时51分30秒
[空 commonParams] OK → 13小时51分33秒  ← 连空都行！
```

这意味着用户只需提供**账号密码**，`access_token`（登录获取）、`device_uid`（首次自动生成并固化）、`instance_id`（拉桌面列表获取）全部自动。

#### 6.3 最终用法

```bash
# 首次登录（交互式）
python main.py login
# account: <账号>
# password: <密码>

# 全自动桌面保活（自动拉桌面列表 + 选桌面 + 保活）
python main.py desktop-keepalive

# 配 crontab 每 5 分钟保活
*/5 * * * * cd ~/cloudpc-keepalive && python main.py desktop-keepalive --rounds 1
```

## 📁 项目结构

```
ecloud-cloudpc-keepalive/
├── main.py                  # 入口，命令行交互
├── protocol.py              # 协议实现层（签名、加密、HTTP 客户端）
├── requirements.txt         # 依赖列表
├── README.md                # 本文件
└── data/                    # 自动生成的配置目录
    ├── credentials.json         # accessToken 凭证
    ├── device.json              # 设备指纹
    └── selected_instance.json   # 选中的桌面实例
```

## ⚠️ 踩过的坑

1. **业务参数顺序**：服务端对 JSON 字段顺序不敏感（JSON 标准特性），但必须包含 `accessToken`。

2. **commonParams 可以为空**：实测服务端完全不校验设备指纹字段，空 `commonParams` 也能保活成功（最长 13 小时+）。这意味着用户只需提供账号密码，其余全部自动。

3. **RSA 分块大小**：1024-bit RSA PKCS1 padding 最大分块 117 字节，解密侧 128 字节。写反了会导致解密失败。

4. **HMAC 前缀**：`BC_SIGNATURE&` 是固定的 salt，不可省略。漏掉前缀会导致签名验证失败。

5. **时间戳格式**：必须是 UTC+8 的 `YYYY-MM-DDTHH:MM:SSZ` 格式。用 UTC+0 或其他格式会被服务端拒绝。

6. **SignatureNonce**：必须使用 uuid4.hex（去掉横杠），不能用随机字符串。

7. **登录分支处理**：密码登录可能返回多种错误码（30002009 未授信设备、30002060 二次验证等），需要分别处理短信验证流程。

8. **抓包 vs 源码**：源码分析可能误导判断，实际行为（抓包）才是真理。不要轻信源码中的注释和设计意图。

## 🛡️ 免责声明

本项目仅供学习和研究使用。请确保你有权对目标系统进行逆向分析和测试。作者不对任何滥用此工具的行为负责。

## 📖 参考

- 原始逆向分析文章: https://hansiy.net/p/86b7133e/
- 移动云电脑客户端: `Ecloud_CloudComputer_x64_V3.8.2_setup.exe`
- 中国移动 Ecloud 平台 API 文档（公开部分）

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License
