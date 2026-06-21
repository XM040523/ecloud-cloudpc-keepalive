"""
移动云电脑 (Ecloud CloudPC) 协议实现
======================================
基于逆向分析 V3.8.2 客户端的纯 Python 协议栈。

核心协议流程：
  1. 构造业务参数 + commonParams + accessToken
  2. JSON 序列化 -> RSA-1024 PKCS1 分块加密(117字节/块) -> base64
  3. HTTP body = {"params": "<base64>"}
  4. URL 查询串: AccessKey + SignatureMethod + SignatureNonce + SignatureVersion + Timestamp
  5. stringToSign = "POST\\n" + quote(apiPath+endpoint) + "\\n" + sha256(querystring)
  6. Signature = HmacSHA1(stringToSign, "BC_SIGNATURE&" + secretKey)
  7. POST https://cloudpc.ecloud.10086.cn/api/cem/gateway/outer/cem-webapi/<endpoint>?<签名查询串>
"""

import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
BASE_URL = "https://cloudpc.ecloud.10086.cn"
API_PATH = "/api/cem/gateway/outer/cem-webapi"
ACCESS_KEY = "53bb79015a3f47c4be166d9371f68f14"
SECRET_KEY = "6b0d3b93f3aa4c7ea076c841bead1ddd"
HMAC_PREFIX = "BC_SIGNATURE&"
COMPANY_CODE = "ECloud"
CLIENT_VERSION = "3.8.2"
PLATFORM = "win32"

# RSA 公钥（来自客户端源码）
RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Oa6pJGpNMnzJSXl2LgXtfBcP
nLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJn
GxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJ
BH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKf
JnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3
JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGwIDAQAB
-----END PUBLIC KEY-----"""

# RSA 私钥的 kk/vv 硬编码密钥（来自客户端源码反编译）
KK = "kk"
VV = "vv"

# 设备指纹缓存路径
DEVICE_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "data")
DEVICE_CONFIG_PATH = os.path.join(DEVICE_CONFIG_DIR, "device.json")
CREDS_PATH = os.path.join(DEVICE_CONFIG_DIR, "credentials.json")
INST_PATH = os.path.join(DEVICE_CONFIG_DIR, "selected_instance.json")


# ---------------------------------------------------------------------------
# 时间戳工具
# ---------------------------------------------------------------------------

def utc8_timestamp() -> str:
    """返回 UTC+8 时间字符串: YYYY-MM-DDTHH:MM:SSZ"""
    now = datetime.now(timezone(timedelta(hours=8)))
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc8_now_str() -> str:
    """返回 UTC+8 可读时间字符串"""
    now = datetime.now(timezone(timedelta(hours=8)))
    return now.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 签名算法 (V2.0 HMAC-SHA1)
# ---------------------------------------------------------------------------

def build_signature_query(endpoint: str, access_token: str = "") -> str:
    """
    构建 URL 查询串中的签名参数。
    返回完整的查询串字符串。
    """
    nonce = uuid.uuid4().hex  # uuid4 去横线
    ts = utc8_timestamp()

    query = {
        "AccessKey": ACCESS_KEY,
        "SignatureMethod": "HmacSHA1",
        "SignatureNonce": nonce,
        "SignatureVersion": "V2.0",
        "Timestamp": ts,
    }
    if access_token:
        query["AccessToken"] = access_token

    canonical = "&".join(f"{k}={v}" for k, v in sorted(query.items()))
    return canonical


def compute_signature(endpoint: str, canonical_query: str) -> str:
    """
    计算 HmacSHA1 签名。
    stringToSign = "POST\\n" + quote(apiPath + endpoint) + "\\n" + sha256(canonical)
    signature = HmacSHA1(stringToSign, HMAC_PREFIX + secretKey)
    """
    hash_step = hashlib.sha256(canonical_query.encode("utf-8")).hexdigest()
    api_endpoint = quote(API_PATH + endpoint, safe="")
    string_to_sign = f"POST\n{api_endpoint}\n{hash_step}"
    signing_key = HMAC_PREFIX + SECRET_KEY
    signature = hmac.new(
        signing_key.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).hexdigest()
    return signature


# ---------------------------------------------------------------------------
# RSA 加密/解密
# ---------------------------------------------------------------------------

_RSA_CHUNK_IN = 117   # 1024/8 - 11
_RSA_CHUNK_OUT = 128  # 1024/8


def rsa_encrypt(data: bytes) -> str:
    """RSA-1024 PKCS1 分块加密 -> base64 字符串"""
    pub_key = RSA.import_key(RSA_PUBLIC_KEY_PEM)
    cipher = PKCS1_v1_5.new(pub_key)
    out = b""
    for i in range(0, len(data), _RSA_CHUNK_IN):
        out += cipher.encrypt(data[i : i + _RSA_CHUNK_IN])
    return base64.b64encode(out).decode("utf-8")


def rsa_decrypt(params_b64: str, private_key_pem: str) -> bytes:
    """RSA 私钥分块解密 (128字节/块)"""
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_v1_5.new(priv_key)
    raw = base64.b64decode(params_b64)
    sentinel = b"\x00" * 64
    out = b""
    for i in range(0, len(raw), _RSA_CHUNK_OUT):
        chunk = cipher.decrypt(raw[i : i + _RSA_CHUNK_OUT], sentinel)
        if chunk == sentinel:
            break
        out += chunk
    return out


# ---------------------------------------------------------------------------
# AES 密钥提取 (从客户端 settingValue.js 解密)
# ---------------------------------------------------------------------------

def derive_aes_key(platform: str = PLATFORM) -> tuple:
    """
    密钥派生:
      key = SHA256("Ecloud-Computer-" + platform)
      iv  = key[:16]
    """
    raw = hashlib.sha256(f"Ecloud-Computer-{platform}".encode("utf-8")).digest()
    return raw, raw[:16]


def decrypt_setting_value(hex_blob: str) -> dict:
    """
    解密 settingValue.js 中的 hex blob。
    hex_blob -> AES-256-CBC(derived_key, derived_iv) -> JSON
    """
    key, iv = derive_aes_key()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(bytes.fromhex(hex_blob)), AES.block_size)
    return json.loads(decrypted.decode("utf-8"))


# ---------------------------------------------------------------------------
# 设备指纹管理
# ---------------------------------------------------------------------------

def generate_device_fingerprint() -> dict:
    """生成设备指纹"""
    return {
        "deviceUid": str(uuid.uuid4()).replace("-", ""),
        "deviceId": str(uuid.uuid4()).replace("-", ""),
        "deviceName": "Ecloud-Keepalive",
        "osType": "linux",
        "osVersion": "5.10.134",
        "arch": "x86_64",
        "clientVersion": CLIENT_VERSION,
        "companyCode": COMPANY_CODE,
    }


def load_or_create_device_config() -> dict:
    """加载或创建设备配置文件"""
    os.makedirs(DEVICE_CONFIG_DIR, exist_ok=True)
    if os.path.exists(DEVICE_CONFIG_PATH):
        with open(DEVICE_CONFIG_PATH, "r") as f:
            return json.load(f)
    fp = generate_device_fingerprint()
    with open(DEVICE_CONFIG_PATH, "w") as f:
        json.dump(fp, f, indent=2)
    return fp


# ---------------------------------------------------------------------------
# HTTP 请求封装
# ---------------------------------------------------------------------------

class EcloudHTTP:
    """移动云电脑协议 HTTP 客户端"""

    def __init__(self, access_token: str = "", rsa_private_key_pem: str = None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Ecloud-CloudPC/3.8.2",
            "Content-Type": "application/json;charset=UTF-8",
        })
        self.access_token = access_token
        self.rsa_private_key_pem = rsa_private_key_pem
        self.device_fp = load_or_create_device_config()

    # ---- 通用 POST ----
    def post(self, endpoint: str, business_params: dict = None) -> dict:
        """
        发送协议级 POST 请求。

        Args:
            endpoint: API 端点，如 "/user/getSysTime"
            business_params: 业务参数字典

        Returns:
            解密后的响应 dict
        """
        # 1. 合并参数
        common_params = {
            "companyCode": COMPANY_CODE,
            "version": "1.0.0",
            "clientVersion": CLIENT_VERSION,
            "deviceUid": self.device_fp.get("deviceUid", ""),
        }
        merged = {**(business_params or {}), **common_params, "accessToken": self.access_token}

        # 2. RSA 加密 body
        body_json = json.dumps(merged, separators=(",", ":")).encode("utf-8")
        params_b64 = rsa_encrypt(body_json)
        http_body = {"params": params_b64}

        # 3. 构建签名
        canonical = build_signature_query(endpoint, self.access_token)
        signature = compute_signature(endpoint, canonical)

        # 4. 附加签名到查询串
        full_query = canonical + f"&Signature={signature}"

        # 5. 发送请求
        url = f"{BASE_URL}{API_PATH}{endpoint}?{full_query}"
        resp = self.session.post(url, json=http_body, timeout=30)
        resp.raise_for_status()

        # 6. 解密响应
        result = resp.json()
        if "params" in result and self.rsa_private_key_pem:
            decrypted = rsa_decrypt(result["params"], self.rsa_private_key_pem)
            return json.loads(decrypted.decode("utf-8"))
        return result

    # ---- 快捷方法 ----

    def get_sys_time(self) -> dict:
        """获取服务器时间（验证签名是否正确）"""
        return self.post("/user/getSysTime", {})

    def login_with_password(self, username: str, password: str) -> dict:
        """密码登录"""
        return self.post("/login/verify", {
            "username": username,
            "password": password,
            "timestamp": utc8_timestamp(),
            "clientNeedTwoFactor": True,
        })

    def verify_access_ticket(self, access_ticket: str) -> dict:
        """通过 accessTicket 换取 accessToken"""
        return self.post("/login/verifyAccessTicket", {
            "accessTicket": access_ticket,
        })

    def get_device_info(self) -> list:
        """获取桌面列表"""
        result = self.post("/user/getDeviceInfo", {
            "accessToken": self.access_token,
            "companyCode": COMPANY_CODE,
            "allCompany": True,
            "version": "1.0.0",
        })
        return result.get("body", {}).get("machineList", [])

    def desktop_uptime(self, instance_id: str) -> dict:
        """查询桌面运行时长（保活核心接口）"""
        return self.post("/resource/desktopUptime", {
            "instanceId": instance_id,
        })

    def machine_connect(self, instance_id: str, machine_id: str = "") -> dict:
        """桌面会话登记（保活核心接口）"""
        return self.post("/session/machineConnect", {
            "instanceId": instance_id,
            "machineId": machine_id,
        })
