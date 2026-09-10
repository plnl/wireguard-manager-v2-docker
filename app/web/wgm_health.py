#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— Health Check 引擎。

和 `wgmgr diagnose` 的区别：diagnose 是给人看的 ✓/✗ 清单，这里是**结构化
结论**——每一条都带 id、级别、以及"下一步该查什么"的具体动作。同一份
health.json 同时喂给 Web 面板、CLI `wgmgr health` 和告警引擎，所以三处
永远不会给出互相矛盾的判断。

设计原则沿用 Bash 侧那一套：**采集层只报事实，判断放在这里**。
status.json 里的 `ipv4_forward`、`port_listening` 是布尔事实，
"这算不算问题"由本文件的规则决定——规则要改就改一处。
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import wgm_common as C

PASS, INFO, WARN, ERROR = "pass", "info", "warn", "error"

_LEVEL_ORDER = {PASS: 0, INFO: 1, WARN: 2, ERROR: 3}

# 状态数据超过这个秒数就认为采集停了。默认采集间隔 30 秒，
# 给 10 倍余量：偶尔一次采集卡住（比如 wg show 撞上接口重建）不该告警。
_STALE_FACTOR = 10

_DISK_WARN_KB = 512 * 1024      # 512MB
_DISK_ERROR_KB = 100 * 1024     # 100MB
_NEVER_CONNECTED_DAYS = 7


def _check(check_id, level, title, detail="", hints=None):
    return {
        "id": check_id,
        "level": level,
        "title": title,
        "detail": detail,
        "hints": hints or [],
    }


def _created_epoch(value):
    """meta.conf 里的 CREATED 是 `date '+%Y-%m-%d %H:%M:%S'`。"""
    if not value:
        return None
    try:
        return int(time.mktime(time.strptime(str(value), "%Y-%m-%d %H:%M:%S")))
    except (ValueError, OverflowError):
        return None


# --------------------------------------------------------------------------
# 系统级规则
# --------------------------------------------------------------------------

def check_system(status: dict, conf: dict) -> list:
    checks = []
    iface = status.get("interface") or {}
    system = status.get("system") or {}
    web = status.get("web") or {}
    collector = status.get("collector") or {}
    peers = status.get("peers") or []

    configured = bool(iface.get("configured"))
    running = bool(iface.get("running"))
    port = iface.get("listen_port") or 0

    if not system.get("wg_installed", False):
        checks.append(_check(
            "wg_missing", ERROR, "系统里没有 wg 命令",
            "wireguard-tools 未安装，本脚本无法生成或校验任何配置。",
            ["apt-get install -y wireguard", "运行交互式菜单 wgmgr，它会自动检测并安装依赖"],
        ))
        return checks    # 后面所有检查都没有意义了

    if not configured:
        checks.append(_check(
            "not_configured", WARN, "服务端尚未初始化",
            "找不到 %s。" % iface.get("config_path", "/etc/wireguard/wg0.conf"),
            ["主菜单 2 -> 1 初始化 / 重新配置服务端", "或 wgmgr server info 查看当前状态"],
        ))
        return checks

    checks.append(_check("configured", PASS, "服务端已配置",
                         "接口 %s，UDP/%s" % (iface.get("name"), port)))

    if not running:
        checks.append(_check(
            "iface_down", ERROR, "WireGuard 接口没有运行",
            "配置文件存在，但 %s 当前不在 up 状态，所有 Peer 都连不上。"
            % iface.get("name"),
            ["wgmgr server up", "journalctl -u wg-quick@%s -n 50 --no-pager"
             % iface.get("name"),
             "如果刚改过配置，主菜单 11 -> 3 从自动快照回滚"],
        ))
        # 接口都没起来，端口监听/NAT 这些检查全是噪音
        return checks

    checks.append(_check("iface_up", PASS, "接口运行中",
                         "%s UP，MTU %s" % (iface.get("name"), iface.get("mtu"))))

    if not system.get("port_listening", False):
        checks.append(_check(
            "port_not_listening", ERROR, "UDP/%s 没有在监听" % port,
            "接口是 up 的，但内核里看不到这个端口的 UDP socket。"
            "通常是 wg0.conf 里 ListenPort 和实际不一致，或者接口正在重建。",
            ["ss -lunp | grep %s" % port, "wg show %s listen-port" % iface.get("name"),
             "主菜单 2 -> 7 从元数据重新生成配置"],
        ))
    else:
        checks.append(_check("port_listening", PASS, "UDP/%s 正在监听" % port))

    sites_enabled = [p for p in peers if p.get("kind") == "site" and p.get("enabled")]
    need_forward = bool(iface.get("internet_nat")) or bool(sites_enabled)

    if need_forward and not system.get("ipv4_forward", False):
        checks.append(_check(
            "no_ipv4_forward", ERROR, "IPv4 转发没有打开",
            "客户端能握手，但流量到了这台机器就断了——它不肯替别人转发。",
            ["sysctl -w net.ipv4.ip_forward=1",
             "确认 /etc/sysctl.d/99-wireguard.conf 存在",
             "主菜单 2 -> 7 重新生成配置（会一并写 sysctl）"],
        ))
    elif need_forward:
        checks.append(_check("ipv4_forward", PASS, "IPv4 转发已开启"))

    if iface.get("internet_nat") and running:
        if not system.get("nat_rule_present", False):
            checks.append(_check(
                "nat_missing", WARN, "没有找到出网 NAT 规则",
                "Internet NAT 是开启的，但 %s 上找不到针对 %s 的 MASQUERADE。"
                "客户端访问公网会失败。"
                % (iface.get("wan_interface"), iface.get("vpn_network4")),
                ["主菜单 7 -> 3 重新同步防火墙",
                 "wgmgr fw show 看带 wg-manager 标签的规则",
                 "如果这台机器在云厂商那里，检查控制台的安全组（脚本管不到那一层）"],
            ))
        else:
            checks.append(_check("nat_present", PASS, "出网 NAT 规则存在"))

    if iface.get("use_ipv6"):
        if system.get("ipv6_forward") and not iface.get("ipv6_forward_harden"):
            checks.append(_check(
                "ipv6_open_forward", WARN, "IPv6 全局转发已开启且没有加固",
                "net.ipv6.conf.all.forwarding=1 是全局开关。如果这台机器本身有"
                "可路由的 IPv6 网段，它现在会替任何人转发 IPv6 包，等于一台开放路由器。",
                ["主菜单 14 -> 4 打开 IPv6 转发加固（只放行经过 %s 的转发）"
                 % iface.get("name"),
                 "如果不需要 IPv6，主菜单 2 -> 1 重新配置时关掉它"],
            ))
        elif not system.get("ipv6_forward"):
            checks.append(_check(
                "ipv6_forward_off", WARN, "启用了 IPv6 但内核没开 IPv6 转发",
                "客户端拿到的 IPv6 地址不会被转发出去。",
                ["主菜单 2 -> 7 重新生成配置"],
            ))
        else:
            checks.append(_check("ipv6_forward", PASS, "IPv6 转发已开启且已加固"))

    backend = iface.get("fw_backend") or "none"
    if backend == "none":
        checks.append(_check(
            "fw_backend_none", WARN, "没有检测到可用的防火墙后端",
            "UFW / nftables / iptables 都没找到。端口放行和 NAT 规则无法下发，"
            "只能依赖云厂商的安全组。",
            ["apt-get install -y nftables", "wgmgr fw backend 确认探测结果"],
        ))
    else:
        checks.append(_check("fw_backend", PASS, "防火墙后端：%s" % backend))

    disk_kb = system.get("disk_avail_kb_root") or 0
    if disk_kb and disk_kb < _DISK_ERROR_KB:
        checks.append(_check(
            "disk_critical", ERROR, "根分区剩余空间不足 100MB",
            "剩余 %s。备份和流量采样都写不下去，配置变更随时可能失败。"
            % C.human_bytes(disk_kb * 1024),
            ["清理 %s/backups 下的旧快照" % C.MANAGER_DIR,
             "df -h / 看是谁占满了"],
        ))
    elif disk_kb and disk_kb < _DISK_WARN_KB:
        checks.append(_check(
            "disk_low", WARN, "根分区剩余空间不足 512MB",
            "剩余 %s。" % C.human_bytes(disk_kb * 1024),
            ["清理 %s/backups 下的旧快照" % C.MANAGER_DIR],
        ))

    mem_total = system.get("mem_total_kb") or 0
    mem_avail = system.get("mem_avail_kb") or 0
    if mem_total and mem_avail * 100 // mem_total < 10:
        checks.append(_check(
            "mem_low", WARN, "可用内存低于 10%",
            "可用 %s / 共 %s。WireGuard 本身很省内存，这通常说明这台机器上"
            "还有别的东西在吃内存，握手延迟会明显变大。"
            % (C.human_bytes(mem_avail * 1024), C.human_bytes(mem_total * 1024)),
        ))

    if system.get("in_container"):
        checks.append(_check(
            "in_container", INFO, "本进程运行在容器里",
            "容器里 wg-quick@ 的 systemd 服务通常不可用，接口生命周期需要"
            "由容器启动脚本自己管。",
            ["确认容器有 NET_ADMIN 能力和 /dev/net/tun 设备",
             "改用 wg-quick up %s 而不是 systemctl" % iface.get("name")],
        ))

    # ---- 状态层自身 ----
    interval = C.conf_int(conf, "COLLECT_INTERVAL", 30) or 30
    age = C.file_age_sec(C.STATUS_JSON)
    if age is None:
        checks.append(_check(
            "state_missing", WARN, "state/status.json 不存在",
            "面板和 health check 都依赖这份文件。",
            ["wgmgr collect 手动采集一次", "wgmgr web install 安装采集服务"],
        ))
    elif age > interval * _STALE_FACTOR:
        checks.append(_check(
            "state_stale", WARN, "状态数据已经 %s 没刷新" % C.human_duration(age),
            "采集间隔是 %d 秒，超过 %d 倍说明采集服务没在正常工作。"
            "面板上看到的在线状态是旧的，不要拿它做判断。"
            % (interval, _STALE_FACTOR),
            ["wgmgr web status",
             "systemctl status %s" % "wireguard-manager-collector",
             "journalctl -u wireguard-manager-collector -n 50 --no-pager"],
        ))
    else:
        checks.append(_check("state_fresh", PASS, "状态数据 %s前刷新" % C.human_duration(age)))

    if web.get("installed") and not web.get("running"):
        checks.append(_check(
            "web_down", WARN, "Web 面板已安装但没有在运行",
            "监听地址 %s。" % web.get("listen", "-"),
            ["wgmgr web start", "journalctl -u wireguard-manager-web -n 50 --no-pager"],
        ))
    elif web.get("installed") and not collector.get("running"):
        checks.append(_check(
            "collector_down", WARN, "采集服务没有在运行",
            "面板还开着，但没人给它喂数据，页面上的状态会一直停在最后一次采集。",
            ["systemctl start wireguard-manager-collector",
             "wgmgr web status 看两个服务的状态"],
        ))
    elif web.get("installed"):
        checks.append(_check("web_up", PASS, "Web 面板运行中", "%s" % web.get("listen")))

    return checks


# --------------------------------------------------------------------------
# Peer 级规则
# --------------------------------------------------------------------------

_OFFLINE_HINTS = [
    "对端的 WireGuard 进程还在跑吗（手机客户端经常被系统杀掉后台）",
    "对端配置的 Endpoint 是不是这台机器真实的公网 IP:端口",
    "上游/云厂商安全组有没有放行 UDP（脚本管不到云控制台那一层）",
    "对端的 PersistentKeepalive 有没有设（NAT 后面不设就会静默断）",
]


def check_peer(peer: dict, status: dict, now: int) -> list:
    checks = []
    name = peer.get("name") or peer.get("id") or "?"
    kind = peer.get("kind", "client")
    state = peer.get("status", "never")
    iface_running = bool((status.get("interface") or {}).get("running"))

    if not peer.get("enabled"):
        checks.append(_check(
            "disabled", INFO, "已禁用",
            "这个 Peer 没有出现在 wg0.conf 里，WireGuard 根本不认它的公钥。"
            "这是主动禁用的结果，不是故障。",
        ))
        return checks

    if iface_running and not peer.get("loaded"):
        # 元数据说启用、接口也在跑，但 wg show dump 里没有这个公钥。
        # 只可能是有人手改过 wg0.conf，或者上一次 syncconf 失败了。
        checks.append(_check(
            "not_loaded", ERROR, "元数据标记为启用，但接口里没有这个 Peer",
            "wg0.conf 和 %s/*/meta.conf 已经不一致了。这种情况下面板显示"
            "「启用」，实际却连不上。" % ("clients" if kind == "client" else "sites"),
            ["主菜单 2 -> 7 重新生成配置（从元数据重建 wg0.conf）",
             "wg show %s dump 核对公钥" % (status.get("interface") or {}).get("name")],
        ))
        return checks

    if state == "online":
        checks.append(_check(
            "online", PASS, "在线",
            "最近一次握手 %s前。" % C.human_duration(peer.get("handshake_ago_sec")),
        ))
    elif state == "idle":
        checks.append(_check(
            "idle", INFO, "空闲",
            "已经 %s 没有握手，超过在线阈值（180 秒）但还没到离线（15 分钟）。"
            "多数情况是这台设备暂时没流量，不是故障。"
            % C.human_duration(peer.get("handshake_ago_sec")),
        ))
    elif state == "offline":
        checks.append(_check(
            "offline", ERROR, "离线",
            "最后握手 %s前，已经超过 15 分钟。"
            % C.human_duration(peer.get("handshake_ago_sec")),
            list(_OFFLINE_HINTS),
        ))
    elif state == "never":
        created = _created_epoch(peer.get("created"))
        age_days = (now - created) / 86400.0 if created else None
        if age_days is not None and age_days > _NEVER_CONNECTED_DAYS:
            checks.append(_check(
                "never_connected", WARN, "创建 %d 天，从未握手成功过一次" % int(age_days),
                "配置生成过，但对端一次都没连上来。通常是配置发出去以后没导入，"
                "或者 Endpoint / 端口填错了。",
                ["wgmgr %s conf %s --qrcode 重新扫码导入"
                 % ("client" if kind == "client" else "site", name),
                 "核对 Endpoint：%s" % (status.get("interface") or {}).get("endpoint"),
                 ] + _OFFLINE_HINTS[1:],
            ))
        else:
            checks.append(_check(
                "never_connected_new", INFO, "从未握手",
                "还没连上过。如果配置刚生成，等对端导入即可。",
            ))
    elif state == "pending":
        checks.append(_check("pending", INFO, "尚未采集到状态"))

    # ---- keepalive ----
    if str(peer.get("keepalive", "off")) in ("off", "0", ""):
        if kind == "site":
            checks.append(_check(
                "site_no_keepalive", WARN, "Site-to-Site 没有设置 PersistentKeepalive",
                "站点隧道两端通常都在 NAT 后面，不发保活包的话 NAT 映射几分钟就过期，"
                "隧道会静默断掉，直到有一端主动发包才恢复。",
                ["重建站点时指定 --keepalive 25",
                 "或在 %s/sites/%s/meta.conf 里设置 KEEPALIVE=25 后重新生成配置"
                 % (C.MANAGER_DIR, name)],
            ))
        elif state in ("never", "offline"):
            checks.append(_check(
                "no_keepalive", INFO, "没有设置 PersistentKeepalive",
                "如果这个客户端在 NAT/4G 后面，不设保活包会导致 NAT 映射过期后"
                "需要等下次发包才恢复连接。",
            ))

    # ---- Site-to-Site 专项 ----
    if kind == "site":
        mode = peer.get("mode", "routing")
        if mode == "conflict":
            checks.append(_check(
                "site_conflict_mode", WARN, "这条站点是「网段冲突」降级模式",
                "两端 LAN 网段重叠，只能访问对端 WireGuard 机器本身，"
                "访问不了它背后的内网设备。",
                ["改掉其中一端路由器的 LAN 网段（治本）",
                 "wgmgr site delete %s 之后用新网段重建" % name],
            ))
        elif mode == "nat":
            checks.append(_check(
                "site_nat_mode", INFO, "这条站点走 NAT 模式",
                "对端看到的源 IP 是这台机器的 VPN IP，不是真实的 LAN IP。"
                "管不了对端路由器时这是合理的妥协，但排障时不如纯路由直观。",
                ["如果两端路由器都能加静态路由，建议改成 routing 模式："
                 "站点之间不做 MASQUERADE 是 WireGuard 官方推荐做法"],
            ))
        else:
            checks.append(_check("site_routing_mode", PASS, "纯路由模式（推荐）"))

        if not peer.get("remote_endpoint"):
            checks.append(_check(
                "site_no_endpoint", INFO, "没有配置对端 Endpoint",
                "这条隧道只能被动等对端来握手。如果两端都在 NAT 后面且都没有"
                "公网入口，隧道永远建立不起来。",
            ))

        if peer.get("local_lan") == peer.get("remote_lan") and peer.get("local_lan"):
            checks.append(_check(
                "site_lan_identical", WARN, "两端 LAN 网段完全相同",
                "%s —— 三层路由无法区分两边的主机。" % peer.get("local_lan"),
            ))

    return checks


# --------------------------------------------------------------------------
# 汇总
# --------------------------------------------------------------------------

def build_health(status: dict = None, conf: dict = None) -> dict:
    status = status if status is not None else C.load_status()
    conf = conf if conf is not None else C.manager_conf()
    now = int(time.time())

    system_checks = check_system(status, conf)

    peer_reports = []
    for peer in status.get("peers") or []:
        peer_checks = check_peer(peer, status, now)
        worst = PASS
        for item in peer_checks:
            if _LEVEL_ORDER[item["level"]] > _LEVEL_ORDER[worst]:
                worst = item["level"]
        peer_reports.append({
            "name": peer.get("name") or peer.get("id"),
            "kind": peer.get("kind", "client"),
            "status": peer.get("status", "never"),
            "level": worst,
            "checks": peer_checks,
        })

    counts = {PASS: 0, INFO: 0, WARN: 0, ERROR: 0}
    for item in system_checks:
        counts[item["level"]] = counts.get(item["level"], 0) + 1
    for report in peer_reports:
        for item in report["checks"]:
            counts[item["level"]] = counts.get(item["level"], 0) + 1

    ok = counts[ERROR] == 0

    if not ok:
        headline = "发现 %d 个必须处理的问题" % counts[ERROR]
    elif counts[WARN]:
        headline = "能跑，但有 %d 项需要注意" % counts[WARN]
    else:
        headline = "一切正常"

    return {
        "schema": 1,
        "generated_at": now,
        "generated_at_str": C.ts_str(now),
        "ok": ok,
        "headline": headline,
        "counts": counts,
        "system": system_checks,
        "peers": peer_reports,
    }


def write_health(health: dict) -> None:
    C.atomic_write_json(C.HEALTH_JSON, health)


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------

_GLYPH = {PASS: "✓", INFO: "·", WARN: "⚠", ERROR: "✗"}
_COLOR = {PASS: "\033[32m", INFO: "\033[90m", WARN: "\033[33m",
          ERROR: "\033[31m"}
_RESET = "\033[0m"


def _print_check(item, indent="  ", color=True):
    glyph = _GLYPH.get(item["level"], "?")
    prefix = _COLOR.get(item["level"], "") if color else ""
    suffix = _RESET if color else ""
    print("%s%s%s %s%s" % (indent, prefix, glyph, item["title"], suffix))
    if item.get("detail"):
        print("%s    %s" % (indent, item["detail"]))
    for hint in item.get("hints") or []:
        print("%s    → %s" % (indent, hint))


def print_health(health: dict, color: bool = True) -> None:
    counts = health["counts"]
    print("=" * 62)
    print("  Health Check   %s" % health["generated_at_str"])
    print("  结论：%s" % health["headline"])
    print("  ✗ %d   ⚠ %d   · %d   ✓ %d" % (
        counts.get(ERROR, 0), counts.get(WARN, 0),
        counts.get(INFO, 0), counts.get(PASS, 0)))
    print("=" * 62)
    print()
    print("  ── 系统 ──")
    shown = False
    for item in health["system"]:
        if item["level"] == PASS:
            continue
        shown = True
        _print_check(item, color=color)
    if not shown:
        print("  ✓ 系统层面没有发现问题（%d 项检查全部通过）"
              % len(health["system"]))
    else:
        passed = sum(1 for i in health["system"] if i["level"] == PASS)
        print("  （另有 %d 项检查通过，已折叠）" % passed)
    print()

    problem_peers = [p for p in health["peers"] if p["level"] in (WARN, ERROR)]
    print("  ── Peer ──")
    if not problem_peers:
        print("  ✓ 全部 %d 个 Peer 状态正常" % len(health["peers"]))
    else:
        for report in problem_peers:
            print("  %s %s  [%s / %s]" % (
                _GLYPH.get(report["level"], "?"), report["name"],
                report["kind"], report["status"]))
            for item in report["checks"]:
                if item["level"] == PASS:
                    continue
                _print_check(item, indent="      ", color=color)
        print()
        print("  （其余 %d 个 Peer 正常）"
              % (len(health["peers"]) - len(problem_peers)))
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="WireGuard Health Check")
    sub = parser.add_subparsers(dest="cmd")

    chk = sub.add_parser("check", help="执行一次检查")
    chk.add_argument("--json", action="store_true")
    chk.add_argument("--pretty", action="store_true")
    chk.add_argument("--no-write", action="store_true",
                     help="只输出，不更新 state/health.json")
    chk.add_argument("--no-color", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd != "check":
        parser.print_help()
        return 2

    health = build_health()
    if not args.no_write:
        try:
            write_health(health)
        except OSError as exc:
            C.log_line("写 health.json 失败：%s" % exc)

    if args.json:
        print(json.dumps(health, ensure_ascii=False, indent=2))
    else:
        print_health(health, color=not args.no_color)

    # 有 error 时返回 1，方便挂到 cron / 监控里当探针用
    return 0 if health["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
