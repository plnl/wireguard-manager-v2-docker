#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— 告警引擎。

建议文档里的流程是：某个 Peer 离线 → 连续检测 N 次 → 确认离线 → 推送。
那个"连续 N 次"不是形式主义：WireGuard 的握手时间在 NAT 后面本来就会抖，
一次采集正好撞上对端切网络，如果立刻推送，一周下来你会收到几十条
"其实已经自己恢复了"的告警，然后开始无视这个渠道——那比没有告警更糟。

去抖的具体做法：
  * 只有 status 已经是 offline（>15 分钟没握手）的 Peer 才开始计数，
    所以"连续 N 次"是在 offline 之上再叠一层，不是从 idle 就开始算。
  * 计数达到 ALERT_THRESHOLD 且还没推过，才推送并打上 alerted 标记。
  * 恢复到 online/idle 时清零计数，并按配置推一条恢复通知。
  * 接口整体 down 的时候，所有 Peer 都会变 offline —— 这时候只推一条
    "接口挂了"，把逐 Peer 的告警全部抑制掉，否则一次重启就是几十条推送。

只用标准库：urllib + hmac + hashlib，钉钉加签也是手算的。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import wgm_common as C

_HTTP_TIMEOUT = 10
_MAX_EVENTS = 200

_TELEGRAM_API = "https://api.telegram.org/bot%s/sendMessage"
_WECOM_API = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=%s"
_DINGTALK_API = "https://oapi.dingtalk.com/robot/send?access_token=%s"


# --------------------------------------------------------------------------
# 状态存储
# --------------------------------------------------------------------------

def _load_state() -> dict:
    data = C.load_json(C.ALERTS_JSON, {}) or {}
    data.setdefault("track", {})
    data.setdefault("events", [])
    return data


def _save_state(state: dict) -> None:
    state["updated_at"] = int(time.time())
    state["updated_at_str"] = C.ts_str(state["updated_at"])
    state["events"] = state["events"][-_MAX_EVENTS:]
    C.atomic_write_json(C.ALERTS_JSON, state)


def _record_event(state: dict, peer: str, kind: str, channels, ok: bool,
                  detail: str = "", errors=None) -> dict:
    event = {
        "t": int(time.time()),
        "t_str": C.ts_str(int(time.time())),
        "peer": peer,
        "kind": kind,
        "channels": list(channels),
        "ok": bool(ok),
        "detail": detail,
        "errors": list(errors or []),
    }
    state["events"].append(event)
    return event


# --------------------------------------------------------------------------
# 监控范围
# --------------------------------------------------------------------------

def _watch_match(watch: str, peer: dict) -> bool:
    watch = (watch or "all").strip().lower()
    if not watch or watch == "all":
        return True
    if watch == "sites":
        return peer.get("kind") == "site"
    if watch == "clients":
        return peer.get("kind") == "client"
    names = {item.strip().lower() for item in watch.split(",") if item.strip()}
    return (peer.get("name") or "").lower() in names


# --------------------------------------------------------------------------
# 消息渲染
# --------------------------------------------------------------------------

def _render_offline(peer: dict, status: dict, miss: int) -> tuple:
    iface = status.get("interface") or {}
    name = peer.get("name") or "?"
    kind = "站点" if peer.get("kind") == "site" else "客户端"
    ago = C.human_duration(peer.get("handshake_ago_sec"))

    title = "WireGuard 告警：%s 离线" % name
    body = "\n".join([
        "⚠️ WireGuard %s离线" % kind,
        "",
        "主机：%s" % (status.get("hostname") or "-"),
        "名称：%s" % name,
        "类型：%s" % kind,
        "状态：OFFLINE（连续 %d 次确认）" % miss,
        "",
        "最后握手：%s前" % ago,
        "VPN IP：%s" % (peer.get("vpn_ip4") or "-"),
        "Endpoint：%s" % (peer.get("endpoint") or "尚未连接"),
        "监听端口：UDP/%s" % iface.get("listen_port", "-"),
        "",
        "建议检查：",
        "1. 对端 WireGuard 进程是否还在运行",
        "2. 对端 Endpoint 是否指向 %s" % (iface.get("endpoint") or "本机公网地址"),
        "3. 上游/云厂商安全组是否放行 UDP/%s" % iface.get("listen_port", "-"),
        "4. 对端 PersistentKeepalive 是否设置（当前 %s）" % peer.get("keepalive", "off"),
    ])
    return title, body


def _render_recovery(peer: dict, status: dict, down_for: int) -> tuple:
    name = peer.get("name") or "?"
    kind = "站点" if peer.get("kind") == "site" else "客户端"
    title = "WireGuard 恢复：%s 已上线" % name
    body = "\n".join([
        "✅ WireGuard %s已恢复" % kind,
        "",
        "主机：%s" % (status.get("hostname") or "-"),
        "名称：%s" % name,
        "状态：ONLINE",
        "离线时长：%s" % C.human_duration(down_for),
        "Endpoint：%s" % (peer.get("endpoint") or "-"),
    ])
    return title, body


def _render_interface_down(status: dict) -> tuple:
    iface = status.get("interface") or {}
    title = "WireGuard 告警：接口 %s 已停止" % iface.get("name", "wg0")
    body = "\n".join([
        "🔴 WireGuard 接口已停止",
        "",
        "主机：%s" % (status.get("hostname") or "-"),
        "接口：%s" % iface.get("name", "wg0"),
        "配置文件：%s" % iface.get("config_path", "-"),
        "",
        "所有 Peer 现在都连不上。本次不再逐个推送 Peer 离线告警。",
        "",
        "建议检查：",
        "1. wgmgr server up 尝试拉起",
        "2. journalctl -u wg-quick@%s -n 50" % iface.get("name", "wg0"),
        "3. 是否刚做过配置变更 —— 主菜单 11 -> 3 从快照回滚",
    ])
    return title, body


def _render_interface_up(status: dict, down_for: int) -> tuple:
    iface = status.get("interface") or {}
    title = "WireGuard 恢复：接口 %s 已启动" % iface.get("name", "wg0")
    body = "\n".join([
        "✅ WireGuard 接口已恢复",
        "",
        "主机：%s" % (status.get("hostname") or "-"),
        "接口：%s" % iface.get("name", "wg0"),
        "停止时长：%s" % C.human_duration(down_for),
    ])
    return title, body


def _render_test(status: dict) -> tuple:
    summary = status.get("summary") or {}
    title = "WireGuard Manager 测试告警"
    body = "\n".join([
        "🔔 这是一条测试告警",
        "",
        "主机：%s" % (status.get("hostname") or "-"),
        "接口：%s（%s）" % (
            (status.get("interface") or {}).get("name", "wg0"),
            "RUNNING" if (status.get("interface") or {}).get("running") else "STOPPED"),
        "Peer：%s 个，在线 %s" % (
            summary.get("peers_total", 0), summary.get("online", 0)),
        "时间：%s" % C.ts_str(int(time.time())),
        "",
        "收到这条说明渠道配置正确。",
    ])
    return title, body


# --------------------------------------------------------------------------
# 渠道投递
# --------------------------------------------------------------------------

def _post_json(url: str, payload: dict, headers=None) -> str:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    hdrs = {"Content-Type": "application/json; charset=utf-8",
            "User-Agent": "WireGuardManager/2.0"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        return resp.read(2048).decode("utf-8", "replace")


def _post_form(url: str, fields: dict) -> str:
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "WireGuardManager/2.0"},
        method="POST")
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        return resp.read(2048).decode("utf-8", "replace")


def _send_telegram(conf: dict, title: str, body: str) -> None:
    token = (conf.get("ALERT_TELEGRAM_TOKEN") or "").strip()
    chat = (conf.get("ALERT_TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat:
        raise ValueError("Telegram token / chat_id 未配置")
    _post_json(_TELEGRAM_API % token, {
        "chat_id": chat,
        "text": body,
        "disable_web_page_preview": True,
    })


def _send_bark(conf: dict, title: str, body: str) -> None:
    url = (conf.get("ALERT_BARK_URL") or "").strip()
    if not url:
        raise ValueError("Bark URL 未配置")
    if not url.startswith(("http://", "https://")):
        raise ValueError("Bark URL 必须以 http(s):// 开头")
    _post_json(url, {
        "title": title,
        "body": body,
        "group": "WireGuardManager",
        "sound": "alarm",
        "level": "timeSensitive",
    })


def _send_wecom(conf: dict, title: str, body: str) -> None:
    key = (conf.get("ALERT_WECOM_KEY") or "").strip()
    if not key:
        raise ValueError("企业微信 webhook key 未配置")
    _post_json(_WECOM_API % urllib.parse.quote(key, safe=""), {
        "msgtype": "text",
        "text": {"content": body},
    })


def _send_dingtalk(conf: dict, title: str, body: str) -> None:
    token = (conf.get("ALERT_DINGTALK_TOKEN") or "").strip()
    if not token:
        raise ValueError("钉钉 access_token 未配置")

    url = _DINGTALK_API % urllib.parse.quote(token, safe="")
    secret = (conf.get("ALERT_DINGTALK_SECRET") or "").strip()
    if secret:
        # 钉钉"加签"模式：sign = urlEncode(base64(hmacSHA256(timestamp\nsecret, secret)))
        # 注意被签的字符串是 "时间戳\n密钥"，而 HMAC 的 key 是密钥本身，
        # 这两个位置很容易写反，写反了钉钉会一直回 310000。
        ts = str(round(time.time() * 1000))
        digest = hmac.new(
            secret.encode("utf-8"),
            ("%s\n%s" % (ts, secret)).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(digest).decode("ascii"))
        url += "&timestamp=%s&sign=%s" % (ts, sign)

    _post_json(url, {"msgtype": "text", "text": {"content": body}})


def _send_webhook(conf: dict, title: str, body: str) -> None:
    url = (conf.get("ALERT_WEBHOOK_URL") or "").strip()
    if not url:
        raise ValueError("Webhook URL 未配置")
    if not url.startswith(("http://", "https://")):
        raise ValueError("Webhook URL 必须以 http(s):// 开头")
    _post_json(url, {
        "source": "wireguard-manager",
        "version": "2.0",
        "title": title,
        "text": body,
        "timestamp": int(time.time()),
    })


_SENDERS = {
    "telegram": _send_telegram,
    "bark": _send_bark,
    "wecom": _send_wecom,
    "dingtalk": _send_dingtalk,
    "webhook": _send_webhook,
}


def send_all(conf: dict, title: str, body: str):
    """按 ALERT_CHANNELS 投递，返回 (成功渠道, [错误描述])。

    一个渠道挂了不影响其他渠道：逐个 try，把失败原因收集起来，
    最后一起写进告警历史——不然某天 Telegram 被封了，你会以为
    "没有告警 = 一切正常"。
    """
    channels = [
        item.strip().lower()
        for item in (conf.get("ALERT_CHANNELS") or "").split(",")
        if item.strip()
    ]
    ok, errors = [], []
    for channel in channels:
        sender = _SENDERS.get(channel)
        if sender is None:
            errors.append("%s：未知渠道" % channel)
            continue
        try:
            sender(conf, title, body)
            ok.append(channel)
        except urllib.error.HTTPError as exc:
            errors.append("%s：HTTP %d %s" % (channel, exc.code, exc.reason))
        except urllib.error.URLError as exc:
            errors.append("%s：网络错误 %s" % (channel, exc.reason))
        except Exception as exc:      # 配置缺失、超时、DNS……都不该让采集循环崩掉
            errors.append("%s：%s" % (channel, exc))
    return ok, errors


# --------------------------------------------------------------------------
# 评估
# --------------------------------------------------------------------------

def evaluate(status: dict = None, conf: dict = None, dry_run: bool = False) -> dict:
    """跑一轮告警评估，更新 state/alerts.json，返回本轮摘要。"""
    status = status if status is not None else C.load_status()
    conf = conf if conf is not None else C.manager_conf()
    state = _load_state()

    now = int(time.time())
    enabled = C.conf_bool(conf, "ALERT_ENABLED", False)
    threshold = max(1, C.conf_int(conf, "ALERT_THRESHOLD", 3))
    watch = conf.get("ALERT_WATCH") or "all"
    want_recovery = C.conf_bool(conf, "ALERT_RECOVERY", True)

    fired = []
    result = {"enabled": enabled, "fired": fired, "skipped": 0}

    if not status:
        state["last_error"] = "status.json 读不到，跳过本轮告警评估"
        _save_state(state)
        return result

    track = state["track"]
    iface = status.get("interface") or {}
    iface_running = bool(iface.get("running"))
    iface_configured = bool(iface.get("configured"))

    # ---- 接口级别 ----
    iface_key = "@interface"
    iface_track = track.setdefault(iface_key, {})
    if iface_configured and not iface_running:
        if not iface_track.get("alerted"):
            iface_track.update({"alerted": True, "since": now})
            if enabled and not dry_run:
                title, body = _render_interface_down(status)
                ok, errors = send_all(conf, title, body)
                _record_event(state, iface.get("name", "wg0"), "interface_down",
                              ok, not errors, body.splitlines()[0], errors)
            fired.append("interface_down")
    elif iface_running and iface_track.get("alerted"):
        down_for = now - int(iface_track.get("since") or now)
        iface_track.clear()
        if enabled and want_recovery and not dry_run:
            title, body = _render_interface_up(status, down_for)
            ok, errors = send_all(conf, title, body)
            _record_event(state, iface.get("name", "wg0"), "interface_up",
                          ok, not errors, body.splitlines()[0], errors)
        fired.append("interface_up")

    # 接口都没起来的时候，逐个 Peer 推离线是纯粹的噪音
    suppress_peers = iface_configured and not iface_running

    # ---- Peer 级别 ----
    seen = set()
    for peer in status.get("peers") or []:
        name = peer.get("name") or peer.get("id")
        if not name:
            continue
        seen.add(name)

        entry = track.setdefault(name, {})
        entry["kind"] = peer.get("kind", "client")
        entry["status"] = peer.get("status", "never")
        entry["seen_at"] = now

        if not peer.get("enabled") or not _watch_match(watch, peer):
            # 主动禁用的 Peer 不该告警；不在监控范围内的直接清零，
            # 否则等你把它加回监控范围时，历史计数会立刻触发一次误报。
            entry["miss"] = 0
            entry.pop("alerted", None)
            entry.pop("since", None)
            continue

        if suppress_peers:
            result["skipped"] += 1
            entry["miss"] = 0
            continue

        if peer.get("status") == "offline":
            entry["miss"] = int(entry.get("miss") or 0) + 1
            if entry["miss"] == 1:
                entry["since"] = now

            if entry["miss"] >= threshold and not entry.get("alerted"):
                entry["alerted"] = True
                entry["alerted_at"] = now
                if enabled and not dry_run:
                    title, body = _render_offline(peer, status, entry["miss"])
                    ok, errors = send_all(conf, title, body)
                    _record_event(state, name, "offline", ok, not errors,
                                  "连续 %d 次确认离线" % entry["miss"], errors)
                fired.append(name)
        else:
            was_alerted = bool(entry.get("alerted"))
            down_for = now - int(entry.get("since") or now)
            entry["miss"] = 0
            entry.pop("alerted", None)
            entry.pop("since", None)

            if was_alerted and peer.get("status") in ("online", "idle"):
                if enabled and want_recovery and not dry_run:
                    title, body = _render_recovery(peer, status, down_for)
                    ok, errors = send_all(conf, title, body)
                    _record_event(state, name, "recovery", ok, not errors,
                                  "离线 %s 后恢复" % C.human_duration(down_for),
                                  errors)
                fired.append("%s(recovered)" % name)

    # 已经被删掉的 Peer 不该永远留在 track 里
    for stale in [k for k in track if k not in seen and k != iface_key]:
        track.pop(stale, None)

    state.pop("last_error", None)
    _save_state(state)
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_test() -> int:
    conf = C.manager_conf()
    status = C.load_status()
    channels = [c.strip() for c in (conf.get("ALERT_CHANNELS") or "").split(",") if c.strip()]

    print("=" * 62)
    print("  告警渠道测试")
    print("=" * 62)
    print()
    print("  总开关   ：%s" % ("已开启" if C.conf_bool(conf, "ALERT_ENABLED") else "关闭"))
    print("  监控范围 ：%s" % (conf.get("ALERT_WATCH") or "all"))
    print("  确认次数 ：%s" % (conf.get("ALERT_THRESHOLD") or "3"))
    print("  已配置渠道：%s" % (", ".join(channels) if channels else "（无）"))
    print()

    if not channels:
        print("  没有配置任何渠道，先去 主菜单 10 -> 告警设置 里配一个。")
        return 1

    title, body = _render_test(status)
    ok, errors = send_all(conf, title, body)

    for channel in channels:
        if channel in ok:
            print("  ✓ %s 投递成功" % channel)
        else:
            reason = next((e for e in errors if e.startswith(channel + "：")), "未知原因")
            print("  ✗ %s 投递失败 —— %s" % (channel, reason))
    print()

    state = _load_state()
    _record_event(state, "-", "test", ok, not errors, "手动测试告警", errors)
    _save_state(state)
    return 0 if ok and not errors else 1


def cmd_history(limit: int = 20) -> int:
    state = _load_state()
    events = state.get("events") or []

    print("=" * 74)
    print("  最近告警记录（共 %d 条，显示最近 %d 条）" % (len(events), min(limit, len(events))))
    print("  状态文件：%s（%s）" % (
        C.ALERTS_JSON,
        C.ts_str(state.get("updated_at")) if state.get("updated_at") else "从未评估"))
    print("=" * 74)
    print()

    if not events:
        print("  还没有任何告警记录。")
        print()
        print("  可能的原因：")
        print("    · 告警总开关没打开（主菜单 10 -> 告警设置 -> 1）")
        print("    · 没有配置任何渠道")
        print("    · 采集服务没在跑（wgmgr web status）")
        print("    · 确实一直没出过问题")
        return 0

    for event in events[-limit:][::-1]:
        mark = "✓" if event.get("ok") else "✗"
        print("  %s  %s  %-22s %-16s %s" % (
            mark,
            event.get("t_str", "-"),
            event.get("peer", "-"),
            event.get("kind", "-"),
            ",".join(event.get("channels") or []) or "-",
        ))
        if event.get("detail"):
            print("       %s" % event["detail"])
        for err in event.get("errors") or []:
            print("       ⚠ %s" % err)
    print()

    track = state.get("track") or {}
    watching = {k: v for k, v in track.items()
                if not k.startswith("@") and (v.get("miss") or v.get("alerted"))}
    if watching:
        print("  当前处于计数/已告警状态的 Peer：")
        for name, entry in sorted(watching.items()):
            print("    %-20s status=%-8s miss=%s alerted=%s" % (
                name, entry.get("status", "-"),
                entry.get("miss", 0), "yes" if entry.get("alerted") else "no"))
        print()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="WireGuard 告警")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("test", help="给所有已配置渠道发一条测试告警")

    hist = sub.add_parser("history", help="查看最近告警记录")
    hist.add_argument("--limit", type=int, default=20)

    ev = sub.add_parser("evaluate", help="跑一轮评估（采集服务内部调用）")
    ev.add_argument("--dry-run", action="store_true", help="只更新计数，不真的推送")
    ev.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "test":
        return cmd_test()
    if args.cmd == "history":
        return cmd_history(args.limit)
    if args.cmd == "evaluate":
        result = evaluate(dry_run=args.dry_run)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif result["fired"]:
            C.log_line("告警触发：%s" % ", ".join(result["fired"]))
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
