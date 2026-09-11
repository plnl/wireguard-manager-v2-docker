#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— DDNS 端点自动更新模块。

用于 Site-to-Site 场景中对端使用动态公网 IP + DDNS 域名的情况。
WireGuard 本身只在 wg-quick 启动时解析一次域名，之后不会动态更新。
本模块在每个采集周期内：
  1. 读取所有已启用站点的 REMOTE_ENDPOINT
  2. 判断是否为域名（非纯 IP），若是则解析当前 IP
  3. 与 WireGuard peer 当前实际 endpoint 对比
  4. IP 变化时通过 `wg set` 热更新 peer endpoint（无需重启 wg0）
  5. 将变更记录写入 state/ddns.json
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path


def _is_ip(host: str) -> bool:
    """判断字符串是否为合法 IP 地址。"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_endpoint(endpoint: str) -> tuple[str, str] | None:
    """解析 'host:port' 格式，返回 (host, port) 或 None。"""
    if not endpoint:
        return None
    # 处理 IPv6 地址 [::1]:51820 的情况
    if endpoint.startswith("["):
        idx = endpoint.find("]")
        if idx == -1:
            return None
        host = endpoint[1:idx]
        port = endpoint[idx + 1:].lstrip(":")
        return (host, port) if port else None
    # 普通 host:port
    parts = endpoint.rsplit(":", 1)
    if len(parts) != 2:
        return None
    host, port = parts
    if not port.isdigit():
        return None
    return (host, port)


def _resolve(hostname: str) -> str | None:
    """解析域名为 IP 地址，失败返回 None。"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _get_peer_endpoints(interface: str) -> dict[str, str]:
    """通过 `wg show <interface> endpoints` 获取所有 peer 的当前 endpoint。
    返回 {public_key: "ip:port"} 字典。"""
    try:
        result = subprocess.run(
            ["wg", "show", interface, "endpoints"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return {}
        peers = {}
        for line in result.stdout.strip().split("\n"):
            if "\t" in line:
                pubkey, endpoint = line.split("\t", 1)
                if endpoint.strip():
                    peers[pubkey.strip()] = endpoint.strip()
        return peers
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


def _update_peer_endpoint(interface: str, pubkey: str, endpoint: str) -> bool:
    """通过 `wg set` 热更新单个 peer 的 endpoint，无需重启接口。"""
    try:
        subprocess.run(
            ["wg", "set", interface, "peer", pubkey,
             "endpoint", endpoint],
            capture_output=True, text=True, timeout=10,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        return False


def _read_meta(meta_path: str) -> dict[str, str]:
    """读取 meta.conf 键值对。"""
    meta = {}
    try:
        with open(meta_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    meta[key.strip()] = val.strip()
    except FileNotFoundError:
        pass
    return meta


def check_ddns(sites_dir: str, interface: str, state_dir: str,
               log_fn=print) -> list[dict]:
    """检查所有启用站点的 DDNS 域名，IP 变化时更新 WireGuard peer endpoint。

    返回本次发生变更的列表。
    """
    changes = []
    peer_endpoints = _get_peer_endpoints(interface)

    sites_path = Path(sites_dir)
    if not sites_path.is_dir():
        return changes

    for site_dir in sorted(sites_path.iterdir()):
        if not site_dir.is_dir():
            continue
        meta_path = site_dir / "meta.conf"
        if not meta_path.exists():
            continue

        meta = _read_meta(str(meta_path))
        if meta.get("ENABLED") != "yes":
            continue

        name = meta.get("NAME", site_dir.name)
        endpoint = meta.get("REMOTE_ENDPOINT", "")
        pubkey = meta.get("REMOTE_PUBLIC_KEY", "")

        if not endpoint or not pubkey:
            continue

        parsed = _parse_endpoint(endpoint)
        if not parsed:
            continue
        host, port = parsed

        # 纯 IP 地址，不需要 DDNS 解析
        if _is_ip(host):
            continue

        # 解析域名
        new_ip = _resolve(host)
        if not new_ip:
            log_fn(f"[DDNS] {name}: 无法解析 {host}，跳过")
            continue

        # 构造新 endpoint
        new_endpoint = f"{new_ip}:{port}"

        # 获取当前 peer endpoint
        current = peer_endpoints.get(pubkey, "")
        current_ip = current.rsplit(":", 1)[0] if ":" in current else ""

        if current_ip == new_ip:
            continue  # IP 未变化

        # IP 变化，热更新
        log_fn(f"[DDNS] {name}: {host} IP 变化 "
               f"{current_ip or '未知'} -> {new_ip}，更新中...")
        if _update_peer_endpoint(interface, pubkey, new_endpoint):
            change = {
                "site": name,
                "hostname": host,
                "old_ip": current_ip or "",
                "new_ip": new_ip,
                "old_endpoint": current,
                "new_endpoint": new_endpoint,
                "timestamp": datetime.now().isoformat(),
                "status": "updated",
            }
            changes.append(change)
            log_fn(f"[DDNS] {name}: 已更新 endpoint -> {new_endpoint}")
        else:
            changes.append({
                "site": name,
                "hostname": host,
                "old_ip": current_ip or "",
                "new_ip": new_ip,
                "timestamp": datetime.now().isoformat(),
                "status": "failed",
            })
            log_fn(f"[DDNS] {name}: 更新失败，wg set 出错")

    # 将变更记录写入 state/ddns.json
    if changes:
        state_path = Path(state_dir) / "ddns.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        # 保留历史记录（追加模式，最多 200 条）
        history = []
        if state_path.exists():
            try:
                with open(state_path, "r") as f:
                    history = json.load(f)
            except (json.JSONDecodeError, IOError):
                history = []
        history.extend(changes)
        if len(history) > 200:
            history = history[-200:]
        with open(state_path, "w") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

    return changes


def get_ddns_status(sites_dir: str, interface: str) -> list[dict]:
    """返回所有 DDNS 站点的当前状态（不执行更新）。"""
    status = []
    peer_endpoints = _get_peer_endpoints(interface)
    sites_path = Path(sites_dir)

    if not sites_path.is_dir():
        return status

    for site_dir in sorted(sites_path.iterdir()):
        if not site_dir.is_dir():
            continue
        meta_path = site_dir / "meta.conf"
        if not meta_path.exists():
            continue

        meta = _read_meta(str(meta_path))
        if meta.get("ENABLED") != "yes":
            continue

        endpoint = meta.get("REMOTE_ENDPOINT", "")
        pubkey = meta.get("REMOTE_PUBLIC_KEY", "")
        name = meta.get("NAME", site_dir.name)

        parsed = _parse_endpoint(endpoint)
        if not parsed:
            continue
        host, port = parsed

        if _is_ip(host):
            continue  # 静态 IP，不列入

        resolved = _resolve(host)
        current = peer_endpoints.get(pubkey, "")
        current_ip = current.rsplit(":", 1)[0] if ":" in current else ""

        status.append({
            "site": name,
            "hostname": host,
            "configured_endpoint": endpoint,
            "resolved_ip": resolved or "解析失败",
            "active_endpoint": current or "未连接",
            "active_ip": current_ip or "",
            "needs_update": bool(resolved and current_ip != resolved),
        })

    return status


if __name__ == "__main__":
    import sys
    import wgm_common as C
    conf = C.manager_conf()
    iface = conf.get("WG_INTERFACE", C.INTERFACE)
    mgr_dir = conf.get("MANAGER_DIR", C.MANAGER_DIR)
    sites = os.path.join(mgr_dir, "sites")
    state = os.path.join(mgr_dir, "state")

    mode = "all"
    if "--check" in sys.argv:
        mode = "check"
    elif "--status" in sys.argv:
        mode = "status"

    if mode in ("status", "all"):
        print("=== DDNS 端点状态 ===")
        for s in get_ddns_status(sites, iface):
            flag = " !! 需更新" if s["needs_update"] else " OK"
            print(f"  {s['site']}: {s['hostname']} -> "
                  f"{s['resolved_ip']} (当前: {s['active_ip']}){flag}")

    if mode in ("check", "all"):
        if mode == "all":
            print()
        print("=== 执行 DDNS 检查 ===")
        changes = check_ddns(sites, iface, state, log_fn=print)
        if not changes:
            print("无变更。")
        else:
            for c in changes:
                print(f"  {c['site']}: {c['old_ip']} -> {c['new_ip']} "
                      f"[{c['status']}]")
