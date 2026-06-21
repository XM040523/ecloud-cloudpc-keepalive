# ecloud-cloudpc-keepalive

移动云电脑 (Ecloud CloudPC) 协议级保活工具。

> 基于对移动云电脑 Windows V3.8.2 客户端的完全逆向分析，用纯 Python（仅依赖 `requests` + `pycryptodome`）实现协议级保活。

## 核心结论

**桌面会话保活不需要 SPICE 协议，不需要 uSmartView 二进制，纯 HTTP 就够了。**

## 快速开始

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

## 技术原理

### 协议流程

完整的请求构造过程：

1. 构造业务参数 + commonParams + accessToken
2. JSON 序列化 → RSA-1024 PKCS1 分块加密(117字节/块) → base64
3. HTTP body = `{"params": "<base64>"}`
4. URL 查询串: AccessKey + SignatureMethod + SignatureNonce + SignatureVersion + Timestamp
5. `stringToSign = "POST\n" + quote(apiPath+endpoint) + "\n" + sha256(querystring)`
6. `Signature = HmacSHA1(stringToSign, "BC_SIGNATURE&" + secretKey)`
7. `POST https://cloudpc.ecloud.10086.cn/api/cem/gateway/outer/cem-webapi/<endpoint>?<签名查询串>`

### 关键接口

| 接口 | 作用 | 频率 |
|------|------|------|
| `/resource/desktopUptime` | 查询桌面运行时长 | 周期性 |
| `/session/machineConnect` | 桌面会话登记 | 连接时 + 定期 |

### 登录流程

```
密码 ──/login/verify──▶ accessTicket ──/login/verifyAccessTicket──▶ accessToken
                              │
                              ▼
                    /resource/desktopUptime
                    /session/machineConnect
                              │
                              ▼
                         桌面保活 ✓
```

### 签名算法 (V2.0)

```python
query = {
    "AccessKey": "53bb79015a3f47c4be166d9371f68f14",
    "SignatureMethod": "HmacSHA1",
    "SignatureNonce": uuid4.hex,
    "SignatureVersion": "V2.0",
    "Timestamp": utc8_timestamp,
}
canonical = urlencode(sorted(query))
hash_step = sha256(canonical).hexdigest()
string_to_sign = f"POST\n{quote(api_path+endpoint)}\n{hash_step}"
signature = hmac.new("BC_SIGNATURE&" + secret_key, string_to_sign, sha1).hexdigest()
```

## 项目结构

```
ecloud-cloudpc-keepalive/
├── main.py              # 入口，命令行交互
├── protocol.py          # 协议实现层
├── requirements.txt     # 依赖
├── README.md            # 本文件
└── data/                # 自动生成的配置目录
    ├── credentials.json         # accessToken 凭证
    ├── device.json              # 设备指纹
    └── selected_instance.json   # 选中的桌面实例
```

## 踩过的坑

1. **业务参数顺序**：服务端对 JSON 字段顺序不敏感（JSON 标准特性），但必须包含 `accessToken`。
2. **commonParams 可以为空**：实测服务端完全不校验设备指纹字段，空 `commonParams` 也能保活成功（最长 13 小时+）。
3. **RSA 分块大小**：1024-bit RSA PKCS1 padding 最大分块 117 字节，解密侧 128 字节。
4. **HMAC 前缀**：`BC_SIGNATURE&` 是固定的 salt，不可省略。
5. **时间戳格式**：必须是 UTC+8 的 `YYYY-MM-DDTHH:MM:SSZ` 格式。

## 免责声明

本项目仅供学习和研究使用。请确保你有权对目标系统进行逆向分析和测试。作者不对任何滥用此工具的行为负责。

## 参考

- 原始逆向分析文章: https://hansiy.net/p/86b7133e/
