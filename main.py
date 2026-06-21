#!/usr/bin/env python3
"""
移动云电脑 (Ecloud CloudPC) 协议级保活工具
============================================
用法:
    python main.py login              # 首次登录，获取 accessToken
    python main.py desktop-keepalive  # 全自动桌面保活
    python main.py desktop-keepalive --rounds 1  # 单次保活
"""

import argparse
import json
import os
import sys
import time

from protocol import (
    EcloudHTTP,
    CREDS_PATH,
    INST_PATH,
    DEVICE_CONFIG_DIR,
    utc8_now_str,
)


def print_banner():
    print("=" * 60)
    print("  移动云电脑 (Ecloud CloudPC) 协议级保活工具")
    print("  基于逆向分析 V3.8.2 客户端")
    print("  仅依赖 requests + pycryptodome")
    print("=" * 60)
    print()


def cmd_login(args):
    """交互式登录流程"""
    print("[*] 请输入账号密码:")
    username = input("  账号: ").strip()
    password = input("  密码: ").strip()

    if not username or not password:
        print("[!] 账号或密码不能为空")
        sys.exit(1)

    http = EcloudHTTP()

    # Step 1: 密码登录获取 accessTicket
    print(f"[*] 正在登录... ({username})")
    try:
        ticket_resp = http.login_with_password(username, password)
    except Exception as e:
        print(f"[!] 登录请求失败: {e}")
        sys.exit(1)

    # 检查是否成功
    if "body" in ticket_resp and "accessTicket" in ticket_resp["body"]:
        access_ticket = ticket_resp["body"]["accessTicket"]
        print("[+] 获取到 accessTicket")
    elif "errorCode" in ticket_resp:
        err_code = ticket_resp["errorCode"]
        err_msg = ticket_resp.get("errorMsg", "未知错误")
        print(f"[!] 登录失败: 错误码={err_code}, 信息={err_msg}")
        if err_code == "30002009":
            print("    提示: 未授信设备，需要短信验证")
        elif err_code == "30002060":
            print("    提示: 需要二次验证，请检查手机短信")
        else:
            print("    提示: 请检查账号密码是否正确")
        sys.exit(1)
    else:
        print(f"[!] 登录响应异常: {json.dumps(ticket_resp, ensure_ascii=False)}")
        sys.exit(1)

    # Step 2: accessTicket -> accessToken
    print("[*] 正在兑换 accessToken...")
    try:
        token_resp = http.verify_access_ticket(access_ticket)
    except Exception as e:
        print(f"[!] 兑换 accessToken 失败: {e}")
        sys.exit(1)

    if "body" in token_resp and "accessToken" in token_resp["body"]:
        access_token = token_resp["body"]["accessToken"]
        print("[+] 获取到 accessToken")
    else:
        print(f"[!] 兑换失败: {json.dumps(token_resp, ensure_ascii=False)}")
        sys.exit(1)

    # Step 3: 保存凭证
    os.makedirs(DEVICE_CONFIG_DIR, exist_ok=True)
    creds = {
        "username": username,
        "accessToken": access_token,
        "savedAt": utc8_now_str(),
    }
    with open(CREDS_PATH, "w") as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    print(f"[+] 凭证已保存到: {CREDS_PATH}")

    # Step 4: 获取桌面列表
    print("[*] 正在获取桌面列表...")
    http.access_token = access_token
    machines = http.get_device_info()
    if not machines:
        print("[!] 未找到任何桌面实例")
        sys.exit(1)

    print(f"\n[+] 找到 {len(machines)} 个桌面实例:")
    print("-" * 60)
    for i, m in enumerate(machines):
        iid = m.get("instanceId", "?")
        mid = m.get("machineId", "?")
        name = m.get("machineName", "Unknown")
        status = m.get("status", "?")
        print(f"  [{i}] {name:30s}  instanceId={iid}  status={status}")
    print("-" * 60)

    # Step 5: 选择桌面
    if len(machines) == 1:
        selected = machines[0]
    else:
        idx = int(input("\n[*] 选择要保活的桌面序号 (默认 0): ").strip() or "0")
        selected = machines[idx]

    selected_info = {
        "instanceId": selected.get("instanceId", ""),
        "machineId": selected.get("machineId", ""),
        "machineName": selected.get("machineName", ""),
    }
    with open(INST_PATH, "w") as f:
        json.dump(selected_info, f, indent=2, ensure_ascii=False)
    print(f"[+] 已选择桌面: {selected_info['machineName']} (instanceId={selected_info['instanceId']})")
    print(f"[+] 保活配置已保存到: {INST_PATH}")

    # Step 6: 验证
    print("[*] 验证连接...")
    try:
        sys_time = http.get_sys_time()
        print(f"[+] 连接成功! 服务器时间: {sys_time.get('systime', '?')}")
    except Exception as e:
        print(f"[!] 验证失败: {e}")


def cmd_desktop_keepalive(args):
    """桌面会话保活"""
    # 加载凭证
    if not os.path.exists(CREDS_PATH):
        print("[!] 未找到凭证文件，请先运行: python main.py login")
        sys.exit(1)

    with open(CREDS_PATH, "r") as f:
        creds = json.load(f)

    access_token = creds.get("accessToken", "")
    if not access_token:
        print("[!] 凭证中缺少 accessToken")
        sys.exit(1)

    # 加载选中的桌面
    if os.path.exists(INST_PATH):
        with open(INST_PATH, "r") as f:
            inst = json.load(f)
        instance_id = inst.get("instanceId", "")
        machine_id = inst.get("machineId", "")
        machine_name = inst.get("machineName", "Unknown")
    else:
        # 尝试自动获取
        print("[!] 未找到选中的桌面配置，正在自动获取...")
        http = EcloudHTTP(access_token=access_token)
        machines = http.get_device_info()
        if not machines:
            print("[!] 未找到任何桌面实例")
            sys.exit(1)
        instance_id = machines[0].get("instanceId", "")
        machine_id = machines[0].get("machineId", "")
        machine_name = machines[0].get("machineName", "Unknown")

    print(f"[*] 保活目标: {machine_name} (instanceId={instance_id})")

    rounds = getattr(args, "rounds", 0)
    interval = getattr(args, "interval", 300)  # 默认 5 分钟
    loop = getattr(args, "loop", False)

    round_count = 0
    while True:
        round_count += 1
        http = EcloudHTTP(access_token=access_token)

        try:
            # 1. 查询桌面运行时长
            uptime_result = http.desktop_uptime(instance_id)
            uptime_seconds = uptime_result.get("body", {}).get("uptimeSeconds", 0)
            uptime_human = format_uptime(uptime_seconds)

            # 2. 会话登记
            connect_result = http.machine_connect(instance_id, machine_id)
            connect_status = connect_result.get("errorCode", "unknown")

            now = utc8_now_str()
            print(f"[{now}] Round #{round_count} | Uptime: {uptime_human} | Connect: {connect_status}")

            # 3. 验证 token 是否过期
            if connect_status != 0 and connect_status != "0":
                err_msg = connect_result.get("errorMsg", "")
                if "token" in err_msg.lower() or "expire" in err_msg.lower() or "expired" in err_msg.lower():
                    print("[!] accessToken 已过期，请重新登录!")
                    print(f"    凭证过期时间: {creds.get('savedAt', '?')}")
                    sys.exit(1)

        except Exception as e:
            print(f"[!] 保活请求失败: {e}")

        if loop:
            time.sleep(interval)
        else:
            if round_count >= rounds and rounds > 0:
                print(f"\n[+] 完成 {rounds} 轮保活")
                break
            else:
                print(f"[+] 完成 1 轮保活")
                break


def format_uptime(seconds: int) -> str:
    """格式化运行时长"""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    parts = []
    if days:
        parts.append(f"{days}天")
    if hours:
        parts.append(f"{hours}小时")
    if minutes:
        parts.append(f"{minutes}分钟")
    parts.append(f"{secs}秒")
    return "".join(parts)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="移动云电脑 (Ecloud CloudPC) 协议级保活工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # login
    subparsers.add_parser("login", help="首次登录，获取 accessToken")

    # desktop-keepalive
    ka_parser = subparsers.add_parser("desktop-keepalive", help="桌面会话保活")
    ka_parser.add_argument("--rounds", "-r", type=int, default=0,
                           help="保活轮数，0=无限循环")
    ka_parser.add_argument("--interval", "-i", type=int, default=300,
                           help="保活间隔(秒)，默认300")
    ka_parser.add_argument("--loop", "-l", action="store_true",
                           help="循环模式")

    args = parser.parse_args()

    if args.command == "login":
        cmd_login(args)
    elif args.command == "desktop-keepalive":
        cmd_desktop_keepalive(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
