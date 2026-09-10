#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— Web API / Dashboard 服务。

建议文档里最硬的一条约束是：

    「Web 面板不能直接让浏览器执行 Bash。」
    「Web API 只允许白名单操作。」
    「而不是让 Web 用户传 command=rm -rf ...」

本文件的实现方式：

  * 所有读操作都来自 state/*.json —— 由 root 权限的采集进程写好，
    本进程以非特权的 wgmgr-web 用户读取。面板自己一行 wg / nft 都不执行。
  * 所有写操作都映射到 wgm_common.ALLOWED_CLI 里的一条**固定 argv**，
    HTTP 请求体只提供参数值，参数值先过正则校验，再由 subprocess 以
    shell=False 的列表形式交给 Bash 核心。请求里没有任何一个字段会被
    当成命令名或命令片段。
  * 认证是用户名/口令 + Session Cookie（HttpOnly / SameSite=Strict），
    不是 ?token=xxx —— 后者会留在浏览器历史、访问日志和 Referer 里。

只依赖标准库。Debian 10 / Ubuntu 20.04 自带的 Python 3.7+ 即可运行
（类型注解用了 `from __future__ import annotations`）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import wgm_alert
import wgm_common as C
import wgm_health
import wgm_traffic

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# 本进程是否自己在跑 TLS。main() 成功包装后才会置 True。
# 反向代理终结 TLS 的场景下它一直是 False，那种情况要用 WEB_COOKIE_SECURE=yes
# 显式打开 Cookie 的 Secure 标志。
TLS_ENABLED = False

_MAX_BODY = 64 * 1024          # 请求体上限。这个 API 没有任何一个端点需要更多。
_SESSION_TTL_SEC = 12 * 3600
_LOGIN_MAX_FAILS = 5
_LOGIN_LOCK_SEC = 900

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}

# 面板自己不发任何外站请求、不加载 CDN 资源，所以 CSP 可以收得很紧。
# 一旦哪天想引入图表库，正确做法是把文件放进 static/ 走 'self'，
# 而不是往这里加一个 https://cdn.xxx 的白名单。
_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "connect-src 'self'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)

# --------------------------------------------------------------------------
# 参数校验
#
# 这一层是白名单之外的第二道防线。就算某个端点忘了校验，
# wgm_common.run_cli 还会拒绝含 shell 元字符的参数。
# --------------------------------------------------------------------------

_RE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_RE_IPV4 = re.compile(r"^(\d{1,3})(\.(\d{1,3})){3}$")
_RE_CIDR4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$")
_RE_WGKEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_RE_ENDPOINT = re.compile(r"^[A-Za-z0-9._-]{1,253}:[0-9]{1,5}$")
_RE_ALLOWED_LIST = re.compile(r"^[A-Za-z0-9.:,/_ \-]{1,512}$")


class BadRequest(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _need_name(value, field="name"):
    value = (value or "").strip()
    if not _RE_NAME.match(value) or value.startswith("."):
        raise BadRequest(
            "%s 只能包含字母、数字、下划线、点和连字符，长度 1-64，且不能以点开头" % field)
    return value


def _need_cidr4(value, field):
    value = (value or "").strip()
    match = _RE_CIDR4.match(value)
    if not match:
        raise BadRequest("%s 必须是 IPv4 CIDR，例如 192.168.20.0/24" % field)
    address, _, prefix = value.partition("/")
    for part in address.split("."):
        if int(part) > 255:
            raise BadRequest("%s 含非法的 IP 段：%s" % (field, part))
    if int(prefix) > 32:
        raise BadRequest("%s 的掩码长度必须在 0-32 之间" % field)
    return value


def _need_ipv4(value, field):
    value = (value or "").strip()
    if not _RE_IPV4.match(value):
        raise BadRequest("%s 必须是 IPv4 地址" % field)
    for part in value.split("."):
        if int(part) > 255:
            raise BadRequest("%s 含非法的 IP 段：%s" % (field, part))
    return value


def _need_wgkey(value, field):
    value = (value or "").strip()
    if not _RE_WGKEY.match(value):
        raise BadRequest("%s 必须是 44 字符的 WireGuard Base64 公钥" % field)
    return value


def _need_endpoint(value, field):
    value = (value or "").strip()
    if not _RE_ENDPOINT.match(value):
        raise BadRequest("%s 必须是 host:port 形式，例如 2.2.2.2:51820" % field)
    host, _, port = value.rpartition(":")
    if not 1 <= int(port) <= 65535:
        raise BadRequest("%s 的端口必须在 1-65535 之间" % field)
    return value


def _need_allowed(value, field="allowed"):
    """客户端 AllowedIPs：逗号分隔的 CIDR 列表，或 0.0.0.0/0。"""
    value = (value or "").strip()
    if not value:
        return ""
    if not _RE_ALLOWED_LIST.match(value):
        raise BadRequest("%s 含非法字符" % field)
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise BadRequest("%s 里有空项" % field)
        if ":" in item:
            continue    # IPv6 CIDR，交给 Bash 侧做最终校验
        _need_cidr4(item, field)
    return value


def _need_int(value, field, low, high):
    try:
        num = int(str(value).strip())
    except (TypeError, ValueError):
        raise BadRequest("%s 必须是整数" % field)
    if not low <= num <= high:
        raise BadRequest("%s 必须在 %d-%d 之间" % (field, low, high))
    return num


# --------------------------------------------------------------------------
# 口令
# --------------------------------------------------------------------------

def verify_password(stored: str, candidate: str) -> bool:
    """校验 Bash 侧 _web_hash_password 生成的 scrypt$N$r$p$salt$hash。

    参数（N/r/p）从存储串里读出来，不写死在这里——这样以后 Bash 侧
    调高 cost 参数，老的哈希仍然能校验，改口令时自动升级成新参数。
    """
    if not stored or not stored.startswith("scrypt$"):
        return False
    parts = stored.split("$")
    if len(parts) != 6:
        return False
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        expected = base64.b64decode(parts[5], validate=True)
    except (ValueError, TypeError):
        return False

    # n 必须是 2 的幂且不能大得离谱，否则一个畸形的 web.conf 就能让
    # 登录请求把内存吃光（scrypt 的内存开销约 128*N*r 字节）。
    if n < 1024 or n > 1 << 20 or (n & (n - 1)) != 0 or r < 1 or r > 32 or p < 1 or p > 8:
        return False

    try:
        actual = hashlib.scrypt(
            candidate.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected),
            maxmem=128 * n * r * p * 2,
        )
    except (ValueError, OSError):
        return False

    return hmac.compare_digest(actual, expected)


# --------------------------------------------------------------------------
# 会话 / 登录限速
# --------------------------------------------------------------------------

class SessionStore:
    """内存会话表。

    刻意不落盘：面板重启后要求重新登录，比在磁盘上留一个能被偷走的
    长期凭据更安全，代价只是偶尔重新输一次口令。
    """

    def __init__(self, ttl: int = _SESSION_TTL_SEC):
        self.ttl = ttl
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, user: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sweep(now)
            self._sessions[token] = {"user": user, "created": now, "expires": now + self.ttl}
        return token

    def get(self, token: str):
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None
            if session["expires"] < now:
                self._sessions.pop(token, None)
                return None
            return dict(session)

    def drop(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def _sweep(self, now: float) -> None:
        for token in [t for t, s in self._sessions.items() if s["expires"] < now]:
            self._sessions.pop(token, None)


class LoginThrottle:
    """按来源 IP 限制失败次数。

    没有这个，一个公网可达的面板就是一台口令爆破机。scrypt 本身已经把
    单次校验成本抬到几十毫秒，但攻击者要的不是快，是次数。
    """

    def __init__(self):
        self._fails = {}
        self._lock = threading.Lock()

    def blocked(self, ip: str):
        with self._lock:
            entry = self._fails.get(ip)
            if not entry:
                return 0
            if entry["count"] < _LOGIN_MAX_FAILS:
                return 0
            remaining = int(entry["until"] - time.time())
            if remaining <= 0:
                self._fails.pop(ip, None)
                return 0
            return remaining

    def fail(self, ip: str) -> None:
        with self._lock:
            entry = self._fails.setdefault(ip, {"count": 0, "until": 0})
            entry["count"] += 1
            if entry["count"] >= _LOGIN_MAX_FAILS:
                entry["until"] = time.time() + _LOGIN_LOCK_SEC

    def reset(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)


SESSIONS = SessionStore()
THROTTLE = LoginThrottle()


# --------------------------------------------------------------------------
# 运行时配置
# --------------------------------------------------------------------------

class RuntimeConfig:
    """每次请求重新读一次 web.conf / manager.conf。

    这两个文件都是几十字节，读一次的开销可以忽略；换来的是
    `wgmgr web passwd` 改完口令立刻生效，不需要重启面板。
    """

    def __init__(self):
        self.web = C.web_conf()
        self.manager = C.manager_conf()

    @property
    def user(self) -> str:
        return self.web.get("WEB_USER") or "admin"

    @property
    def pass_hash(self) -> str:
        return self.web.get("WEB_PASS_HASH") or ""

    @property
    def readonly(self) -> bool:
        return C.conf_bool(self.web, "WEB_READONLY", False)

    @property
    def cookie_secure(self) -> bool:
        return C.conf_bool(self.web, "WEB_COOKIE_SECURE", False)

    @property
    def bind_scope(self) -> str:
        return (self.web.get("WEB_BIND_SCOPE") or "local").strip().lower()

    def allow_key_export(self) -> bool:
        """客户端配置里含私钥，能不能从面板下载取决于面板暴露得多宽。

        scope=vpn / local 时默认允许：这两种情况下能打开面板的人本来就能
        SSH 上来 cat 这个文件，风险等级是一样的。
        scope=public 时默认**禁止**，必须显式写 WEB_ALLOW_KEY_EXPORT=yes
        才放行——公网可达的面板一旦被爆破，第一个被拿走的就应该是私钥，
        所以这里要求你自己明确表过态。
        """
        raw = (self.web.get("WEB_ALLOW_KEY_EXPORT") or "").strip().lower()
        if raw in ("yes", "true", "1", "on"):
            return True
        if raw in ("no", "false", "0", "off"):
            return False
        return self.bind_scope in ("vpn", "local")


# --------------------------------------------------------------------------
# Peer 查找
# --------------------------------------------------------------------------

def _find_peer(name: str):
    status = C.load_status()
    for peer in status.get("peers") or []:
        if (peer.get("name") or peer.get("id")) == name:
            return status, peer
    return status, None


def _peer_kind(name: str) -> str:
    """按名字解析出这是 client 还是 site。

    必须从状态里查、不能让浏览器自己传 kind：如果传进来的 kind 和实际
    不符，写操作就会落到另一个同名对象上（客户端和站点是两套目录，
    名字空间不互通，撞名是完全可能的）。
    """
    _, peer = _find_peer(name)
    if peer is None:
        raise BadRequest("找不到 Peer：%s" % name)
    return "site" if peer.get("kind") == "site" else "client"


# --------------------------------------------------------------------------
# 端点实现
#
# 统一签名：handler(ctx, match, query, body) -> dict | bytes
# ctx 里有 config / client_ip / secure
# --------------------------------------------------------------------------

def ep_ping(ctx, match, query, body):
    return {
        "ok": True,
        "service": "wireguard-manager-web",
        "auth_required": True,
        "time": int(time.time()),
    }


def ep_login(ctx, match, query, body):
    ip = ctx["client_ip"]
    blocked = THROTTLE.blocked(ip)
    if blocked:
        raise PermissionError(
            "失败次数过多，请 %s后再试" % C.human_duration(blocked))

    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    config = ctx["config"]

    # 用户名用 compare_digest 比，避免通过响应时间猜出有效用户名。
    # 口令这一侧 scrypt 本身已经是恒定成本，但用户名先短路会泄露长度信息。
    name_ok = hmac.compare_digest(username.encode("utf-8"), config.user.encode("utf-8"))
    pass_ok = verify_password(config.pass_hash, password) if password else False

    if not (name_ok and pass_ok):
        THROTTLE.fail(ip)
        raise PermissionError("用户名或口令错误")

    THROTTLE.reset(ip)
    token = SESSIONS.create(username)
    ctx["set_session"] = token
    return {"ok": True, "user": username, "expires_in": SESSIONS.ttl}


def ep_logout(ctx, match, query, body):
    token = ctx.get("session_token")
    if token:
        SESSIONS.drop(token)
    ctx["clear_session"] = True
    return {"ok": True}


def _status_payload():
    status = C.load_status()
    age = C.file_age_sec(C.STATUS_JSON)
    status["_state_age_sec"] = age
    status["_state_stale"] = bool(age is None or age > 300)
    return status


def ep_status(ctx, match, query, body):
    payload = _status_payload()
    # Cookie 是 HttpOnly 的，前端自己读不到，所以由服务端告诉它当前登录的是谁。
    payload["who"] = ctx.get("user") or ""
    return payload


def ep_interface(ctx, match, query, body):
    status = _status_payload()
    return {
        "interface": status.get("interface") or {},
        "summary": status.get("summary") or {},
        "generated_at": status.get("generated_at"),
        "state_age_sec": status.get("_state_age_sec"),
    }


def ep_system(ctx, match, query, body):
    status = _status_payload()
    return {
        "system": status.get("system") or {},
        "web": status.get("web") or {},
        "collector": status.get("collector") or {},
        "hostname": status.get("hostname"),
        "version": status.get("version"),
    }


def ep_peers(ctx, match, query, body):
    status = _status_payload()
    peers = status.get("peers") or []

    kind = (query.get("kind") or [""])[0]
    state = (query.get("status") or [""])[0]
    if kind:
        peers = [p for p in peers if p.get("kind") == kind]
    if state:
        peers = [p for p in peers if p.get("status") == state]

    return {
        "peers": peers,
        "count": len(peers),
        "summary": status.get("summary") or {},
        "generated_at": status.get("generated_at"),
        "state_age_sec": status.get("_state_age_sec"),
    }


def ep_peer_detail(ctx, match, query, body):
    name = urllib.parse.unquote(match.group("name"))
    status = _status_payload()
    peer = None
    for item in status.get("peers") or []:
        if (item.get("name") or item.get("id")) == name:
            peer = item
            break
    if peer is None:
        raise LookupError("找不到 Peer：%s" % name)

    health = C.load_json(C.HEALTH_JSON, {}) or {}
    checks = []
    for report in health.get("peers") or []:
        if report.get("name") == name:
            checks = report.get("checks") or []
            break

    return {
        "peer": peer,
        "checks": checks,
        "generated_at": status.get("generated_at"),
        "state_age_sec": status.get("_state_age_sec"),
    }


def ep_sites(ctx, match, query, body):
    status = _status_payload()
    sites = [p for p in (status.get("peers") or []) if p.get("kind") == "site"]
    # 拓扑视图：以本机为中心，站点是叶子。建议文档里画的那棵树就是靠这个结构渲染的。
    interface = status.get("interface") or {}
    return {
        "hub": {
            "name": status.get("hostname") or interface.get("name", "wg0"),
            "vpn_ip4": interface.get("server_ip4"),
            "vpn_network4": interface.get("vpn_network4"),
            "local_lans": sorted({s.get("local_lan") for s in sites if s.get("local_lan")}),
            "running": bool(interface.get("running")),
        },
        "sites": sites,
        "count": len(sites),
        "generated_at": status.get("generated_at"),
    }


def ep_routes(ctx, match, query, body):
    status = _status_payload()
    return {
        "routes": status.get("routes") or [],
        "kernel_routes": status.get("kernel_routes") or [],
    }


def ep_firewall(ctx, match, query, body):
    data = C.load_json(C.FIREWALL_JSON, None)
    if data is None:
        status = C.load_status()
        return {
            "available": False,
            "reason": "还没有防火墙快照。它由采集进程每 %d 轮生成一次，"
                      "或者手动跑一次 wgmgr collect。" % 10,
            "backend": (status.get("interface") or {}).get("fw_backend", "none"),
        }
    data["available"] = True
    return data


def ep_traffic(ctx, match, query, body):
    range_key = (query.get("range") or ["24h"])[0]
    if range_key not in wgm_traffic.RANGES:
        raise BadRequest("range 只能是 %s 之一" % "/".join(wgm_traffic.RANGES))
    by_peer = (query.get("by_peer") or ["0"])[0] in ("1", "true", "yes")
    return wgm_traffic.build_report(range_key, by_peer=by_peer)


def ep_logs(ctx, match, query, body):
    limit = 100
    raw = (query.get("n") or ["100"])[0]
    try:
        limit = max(1, min(500, int(raw)))
    except ValueError:
        pass
    data = C.load_json(C.MANAGER_LOG_JSON, None)
    if data is None:
        return {"available": False, "lines": [],
                "reason": "还没有日志快照，等采集进程跑一轮。"}
    lines = data.get("lines") or []
    return {
        "available": True,
        "digest": data.get("digest"),
        "generated_at": data.get("generated_at"),
        "count": len(lines[-limit:]),
        "lines": lines[-limit:],
    }


def ep_health(ctx, match, query, body):
    health = C.load_json(C.HEALTH_JSON, None)
    if health is None:
        # 面板刚装好、采集还没跑第一轮时，直接现算一份，
        # 而不是让首屏显示"暂无数据"。
        health = wgm_health.build_health()
    health["state_age_sec"] = C.file_age_sec(C.HEALTH_JSON)
    return health


def ep_alerts(ctx, match, query, body):
    data = C.load_json(C.ALERTS_JSON, {}) or {}
    conf = ctx["config"].manager
    return {
        "config": {
            "enabled": C.conf_bool(conf, "ALERT_ENABLED", False),
            "watch": conf.get("ALERT_WATCH") or "all",
            "threshold": C.conf_int(conf, "ALERT_THRESHOLD", 3),
            "channels": [c.strip() for c in (conf.get("ALERT_CHANNELS") or "").split(",") if c.strip()],
            # 只报"配了没有"，绝不把 token / webhook 内容回给浏览器
            "configured": {
                key: bool(conf.get(env_key))
                for key, env_key in (
                    ("telegram", "ALERT_TELEGRAM_TOKEN"),
                    ("bark", "ALERT_BARK_URL"),
                    ("wecom", "ALERT_WECOM_KEY"),
                    ("dingtalk", "ALERT_DINGTALK_TOKEN"),
                    ("webhook", "ALERT_WEBHOOK_URL"),
                )
            },
        },
        "updated_at": data.get("updated_at"),
        "updated_at_str": data.get("updated_at_str"),
        "track": data.get("track") or {},
        "events": (data.get("events") or [])[-100:][::-1],
    }


# ---- 写操作 ----

def _guard_write(ctx):
    if ctx["config"].readonly:
        raise PermissionError("面板处于只读模式（WEB_READONLY=yes），拒绝任何写操作")


def ep_collect(ctx, match, query, body):
    _guard_write(ctx)
    code, out, err = C.run_cli(["collect"], timeout=90)
    if code != 0:
        raise RuntimeError((err or out).strip()[:300] or "采集失败")
    return {"ok": True, "state": _status_payload().get("generated_at_str")}


def ep_client_add(ctx, match, query, body):
    _guard_write(ctx)
    name = _need_name(body.get("name"))
    argv = ["client", "add", name]

    ip4 = (body.get("ip4") or "").strip()
    if ip4:
        argv += ["--ip4", _need_ipv4(ip4, "ip4")]
    allowed = (body.get("allowed_ips") or "").strip()
    if allowed:
        argv += ["--allowed", _need_allowed(allowed)]

    code, out, err = C.run_cli(argv, timeout=120)
    if code != 0:
        raise RuntimeError((err or out).strip()[:400] or "创建客户端失败")

    _, peer = _find_peer(name)
    return {"ok": True, "name": name, "peer": peer, "detail": out.strip()[:2000]}


def ep_peer_toggle(ctx, match, query, body, target: str):
    _guard_write(ctx)
    name = _need_name(urllib.parse.unquote(match.group("name")), "peer")
    kind = _peer_kind(name)
    argv = [kind, target, name]
    code, out, err = C.run_cli(argv, timeout=120)
    if code != 0:
        raise RuntimeError((err or out).strip()[:400] or "%s 失败" % target)
    return {"ok": True, "name": name, "kind": kind, "state": target}


def ep_peer_enable(ctx, match, query, body):
    return ep_peer_toggle(ctx, match, query, body, "enable")


def ep_peer_disable(ctx, match, query, body):
    return ep_peer_toggle(ctx, match, query, body, "disable")


def ep_peer_delete(ctx, match, query, body):
    _guard_write(ctx)
    name = _need_name(urllib.parse.unquote(match.group("name")), "peer")
    # 删除是不可逆的（密钥会一起没掉），所以要求请求体里显式带上名字再确认一次。
    # 这不是防误触的花架子：DELETE 请求在浏览器里往往是一次滑动或一次回车，
    # 而删掉一个正在用的站点，恢复手段只有重新对端配置。
    if str(body.get("confirm") or "") != name:
        raise BadRequest("删除需要在请求体里带 confirm=\"%s\" 二次确认" % name)
    kind = _peer_kind(name)
    code, out, err = C.run_cli([kind, "delete", name], timeout=120)
    if code != 0:
        raise RuntimeError((err or out).strip()[:400] or "删除失败")
    return {"ok": True, "name": name, "kind": kind, "deleted": True}


def ep_peer_rotate_key(ctx, match, query, body):
    _guard_write(ctx)
    name = _need_name(urllib.parse.unquote(match.group("name")), "peer")
    if _peer_kind(name) != "client":
        # 站点的私钥在对端机器上，这边只能换它的公钥记录，
        # 那属于"重新对接"而不是"轮换密钥"，必须两边一起改，不该由面板代劳。
        raise BadRequest("站点密钥不在本机，无法从面板轮换")
    # 轮换之后这个客户端会立刻掉线，直到重新导入新配置。所以要求二次确认，
    # 和删除同一个理由：这是"点一下就会生效"的操作，而不是"点一下弹个窗"。
    if str(body.get("confirm") or "") != name:
        raise BadRequest("轮换密钥会让 %s 立刻掉线，需要在请求体里带 confirm=\"%s\"" % (name, name))

    code, out, err = C.run_cli(["client", "rotate-key", name], timeout=120)
    if code != 0:
        raise RuntimeError((err or out).strip()[:400] or "轮换密钥失败")
    ctx["log_line"] = "轮换客户端密钥 %s by %s" % (name, ctx["user"])
    _, peer = _find_peer(name)
    return {"ok": True, "name": name, "peer": peer, "detail": out.strip()[:2000]}


def ep_peer_config(ctx, match, query, body):
    name = _need_name(urllib.parse.unquote(match.group("name")), "peer")
    if _peer_kind(name) != "client":
        raise BadRequest("站点没有可下载的客户端配置")
    if not ctx["config"].allow_key_export():
        raise PermissionError(
            "当前绑定范围（%s）下默认禁止从面板导出含私钥的配置。"
            "确有需要请在 web.conf 里设置 WEB_ALLOW_KEY_EXPORT=yes"
            % ctx["config"].bind_scope)
    code, out, err = C.run_cli(["client", "conf", name], timeout=30)
    if code != 0:
        raise RuntimeError((err or out).strip()[:200] or "读取配置失败")
    ctx["log_line"] = "导出客户端配置 %s（含私钥）by %s" % (name, ctx["user"])
    return ("text/plain; charset=utf-8",
            out.encode("utf-8"),
            'attachment; filename="%s.conf"' % name)


def ep_peer_qrcode(ctx, match, query, body):
    name = _need_name(urllib.parse.unquote(match.group("name")), "peer")
    if _peer_kind(name) != "client":
        raise BadRequest("站点没有二维码")
    if not ctx["config"].allow_key_export():
        raise PermissionError("当前绑定范围下默认禁止导出含私钥的配置")
    png = C.run_cli_bytes(["client", "conf", name, "--png"], timeout=30)
    ctx["log_line"] = "导出客户端二维码 %s by %s" % (name, ctx["user"])
    return ("image/png", png, None)


def ep_site_create(ctx, match, query, body):
    _guard_write(ctx)
    name = _need_name(body.get("name"))
    argv = ["site", "create", name,
            "--remote-lan", _need_cidr4(body.get("remote_lan"), "remote_lan"),
            "--remote-wg-ip", _need_ipv4(body.get("remote_wg_ip"), "remote_wg_ip"),
            "--remote-pubkey", _need_wgkey(body.get("remote_pubkey"), "remote_pubkey")]

    local_lan = (body.get("local_lan") or "").strip()
    if local_lan:
        argv += ["--local-lan", _need_cidr4(local_lan, "local_lan")]
    endpoint = (body.get("remote_endpoint") or "").strip()
    if endpoint:
        argv += ["--remote-endpoint", _need_endpoint(endpoint, "remote_endpoint")]

    mode = (body.get("mode") or "routing").strip().lower()
    if mode not in ("routing", "nat"):
        # 刻意不接受 conflict：那是网段冲突时的降级结果，由 Bash 侧自己判定，
        # 不应该让面板主动请求一个"只能通 VPN IP"的站点。
        raise BadRequest("mode 只能是 routing（推荐）或 nat")
    argv += ["--mode", mode]

    if body.get("keepalive"):
        argv += ["--keepalive", str(_need_int(body.get("keepalive"), "keepalive", 0, 600))]

    code, out, err = C.run_cli(argv, timeout=120)
    if code != 0:
        raise RuntimeError((err or out).strip()[:500] or "创建站点失败")
    return {"ok": True, "name": name, "mode": mode, "detail": out.strip()[:3000]}


def ep_site_test(ctx, match, query, body):
    _guard_write(ctx)
    name = _need_name(urllib.parse.unquote(match.group("name")), "site")
    if _peer_kind(name) != "site":
        raise BadRequest("%s 不是站点" % name)
    code, out, err = C.run_cli(["site", "test", name], timeout=60)
    return {"ok": code == 0, "name": name,
            "output": (out or err).strip()[:3000]}


def ep_fw_sync(ctx, match, query, body):
    _guard_write(ctx)
    code, out, err = C.run_cli(["fw", "sync"], timeout=120)
    if code != 0:
        raise RuntimeError((err or out).strip()[:300] or "防火墙同步失败")
    return {"ok": True, "detail": (out or err).strip()[:1000]}


def ep_backup(ctx, match, query, body):
    _guard_write(ctx)
    code, out, err = C.run_cli(["backup", "create"], timeout=180)
    if code != 0:
        raise RuntimeError((err or out).strip()[:300] or "备份失败")
    return {"ok": True, "detail": (out or err).strip()[:1000]}


def ep_alert_test(ctx, match, query, body):
    _guard_write(ctx)
    conf = ctx["config"].manager
    channels = [c.strip() for c in (conf.get("ALERT_CHANNELS") or "").split(",") if c.strip()]
    if not channels:
        # send_all 在这种情况下返回 ([], [])，ok 是假值而 errors 是空的。
        # 直接把那个结果透出去，面板只能说"发送失败：未知原因"——
        # 而真实原因是"你根本还没配渠道"，这两件事的处置方式完全不同。
        raise BadRequest(
            "还没有配置任何告警渠道。SSH 登录服务器运行 wgmgr → 告警设置，"
            "配好 Telegram / Bark / 企业微信 / 钉钉 / Webhook 中的任意一个再来测试。")

    status = C.load_status()
    title, text = wgm_alert._render_test(status)
    ok, errors = wgm_alert.send_all(conf, title, text)
    state = wgm_alert._load_state()
    wgm_alert._record_event(state, "-", "test", ok, not errors, "面板发起的测试告警", errors)
    wgm_alert._save_state(state)
    return {
        "ok": not errors and bool(ok),
        "sent": ok,
        "errors": errors,
        "enabled": C.conf_bool(conf, "ALERT_ENABLED", False),
    }


# --------------------------------------------------------------------------
# 路由表
# --------------------------------------------------------------------------

_ROUTES = [
    # method, pattern, handler, 需要登录
    ("GET",    r"^/api/v1/ping$",                 ep_ping,         False),
    ("POST",   r"^/api/v1/login$",                ep_login,        False),
    ("POST",   r"^/api/v1/logout$",               ep_logout,       True),

    ("GET",    r"^/api/v1/status$",               ep_status,       True),
    ("GET",    r"^/api/v1/interface$",            ep_interface,    True),
    ("GET",    r"^/api/v1/system$",               ep_system,       True),
    ("GET",    r"^/api/v1/peers$",                ep_peers,        True),
    ("GET",    r"^/api/v1/peers/(?P<name>[^/]+)$", ep_peer_detail, True),
    ("GET",    r"^/api/v1/sites$",                ep_sites,        True),
    ("GET",    r"^/api/v1/routes$",               ep_routes,       True),
    ("GET",    r"^/api/v1/firewall$",             ep_firewall,     True),
    ("GET",    r"^/api/v1/traffic$",              ep_traffic,      True),
    ("GET",    r"^/api/v1/logs$",                 ep_logs,         True),
    ("GET",    r"^/api/v1/health$",               ep_health,       True),
    ("GET",    r"^/api/v1/alerts$",               ep_alerts,       True),

    ("GET",    r"^/api/v1/peers/(?P<name>[^/]+)/config$",    ep_peer_config,  True),
    ("GET",    r"^/api/v1/peers/(?P<name>[^/]+)/qrcode\.png$", ep_peer_qrcode, True),

    ("POST",   r"^/api/v1/collect$",              ep_collect,      True),
    ("POST",   r"^/api/v1/clients$",              ep_client_add,   True),
    ("POST",   r"^/api/v1/sites$",                ep_site_create,  True),
    ("POST",   r"^/api/v1/backup$",               ep_backup,       True),
    ("POST",   r"^/api/v1/firewall/sync$",        ep_fw_sync,      True),
    ("POST",   r"^/api/v1/alerts/test$",          ep_alert_test,   True),
    ("POST",   r"^/api/v1/peers/(?P<name>[^/]+)/enable$",  ep_peer_enable,  True),
    ("POST",   r"^/api/v1/peers/(?P<name>[^/]+)/disable$", ep_peer_disable, True),
    ("POST",   r"^/api/v1/peers/(?P<name>[^/]+)/rotate-key$", ep_peer_rotate_key, True),
    ("POST",   r"^/api/v1/sites/(?P<name>[^/]+)/test$",    ep_site_test,    True),
    ("DELETE", r"^/api/v1/peers/(?P<name>[^/]+)$", ep_peer_delete, True),
]

_COMPILED_ROUTES = [
    (method, re.compile(pattern), handler, need_auth)
    for method, pattern, handler, need_auth in _ROUTES
]


# --------------------------------------------------------------------------
# HTTP Handler
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "WireGuardManager/2.0"
    protocol_version = "HTTP/1.1"

    # ---- 基础设施 ----

    def log_message(self, fmt, *args):
        # 默认实现会往 stderr 打，格式里带完整请求行。这里重写：
        # 去掉 query string（可能带敏感参数），交给 journald 统一收。
        path = self.path.split("?", 1)[0]
        C.log_line("%s %s %s %s" % (self._client_ip(), self.command, path, fmt % args))

    def _client_ip(self) -> str:
        # 反向代理场景下 client_address 是代理自己的地址。
        # 只信任 X-Forwarded-For 的最左一段用于**限速**——它可被伪造，
        # 但伪造只会让攻击者绕过自己的限速，不会获得任何权限；
        # 认证判定完全不看这个头。
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first[:64]
        try:
            return self.client_address[0]
        except (AttributeError, IndexError):
            return "-"

    def _is_secure(self) -> bool:
        # 本进程自己跑 TLS 时为 True。反代终结 TLS 的场景下这里是 False，
        # 需要靠 WEB_COOKIE_SECURE=yes 显式打开 Secure 标志。
        return TLS_ENABLED

    def _security_headers(self, content_type: str):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("Cache-Control", "no-store")
        if content_type.startswith("text/html"):
            # HTML 一律不缓存；静态资源下面单独给短缓存
            self.send_header("Pragma", "no-cache")

    def _send(self, status: int, content_type: str, payload: bytes,
              extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._security_headers(content_type)
        for key, value in (extra_headers or []):
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json(self, status: int, obj, extra_headers=None):
        payload = json.dumps(obj, ensure_ascii=False, indent=None).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", payload, extra_headers)

    def _session_cookie(self, token: str, config) -> tuple:
        parts = ["wgm_session=%s" % token, "Path=/", "HttpOnly", "SameSite=Strict",
                 "Max-Age=%d" % SESSIONS.ttl]
        # Secure 标志一旦设上，纯 HTTP 访问时浏览器就不肯回传 Cookie，
        # 面板会表现为"登录成功但立刻又被踢回登录页"。所以只在明确
        # 配置了 WEB_COOKIE_SECURE=yes 或本进程自己就在跑 TLS 时才加。
        if config.cookie_secure or self._is_secure():
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def _read_body(self):
        raw = self.headers.get("Content-Length")
        if not raw:
            return {}
        try:
            length = int(raw)
        except ValueError:
            raise BadRequest("Content-Length 非法")
        if length < 0:
            raise BadRequest("Content-Length 非法")
        if length > _MAX_BODY:
            raise BadRequest("请求体超过 %d 字节上限" % _MAX_BODY)
        if length == 0:
            return {}

        blob = self.rfile.read(length)
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type not in ("application/json", ""):
            # 拒绝表单编码：SameSite=Strict 已经能挡住跨站表单，
            # 但少支持一种格式就少一种被利用的方式，而且前端全程用 JSON。
            raise BadRequest("只接受 application/json")
        try:
            data = json.loads(blob.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BadRequest("请求体不是合法 JSON")
        if not isinstance(data, dict):
            raise BadRequest("请求体必须是 JSON 对象")
        return data

    def _session_token(self):
        header = self.headers.get("Cookie") or ""
        for chunk in header.split(";"):
            key, _, value = chunk.strip().partition("=")
            if key == "wgm_session" and value:
                return value
        return None

    # ---- 方法入口 ----

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_HEAD(self):
        self._handle("GET")

    def do_PUT(self):
        self._send_json(405, {"error": "方法不允许"})

    def do_PATCH(self):
        self._send_json(405, {"error": "方法不允许"})

    def _handle(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # 清掉重复斜杠和 . / .. 段，避免 //api 或 /static/../web.conf 这类绕过。
        # 刻意**不**在这里 unquote 整条路径：各端点会对匹配到的 name 分组单独
        # 解码一次，整体先解码就成了双重解码，而且 %2F 解出来的斜杠会改变
        # 路由分组的边界。
        segments = [s for s in path.split("/") if s not in ("", ".", "..")]
        path = "/" + "/".join(segments) if segments else "/"

        if path.startswith("/api/"):
            self._handle_api(method, path, query)
        elif method == "GET":
            self._handle_static(path)
        else:
            self._send_json(405, {"error": "方法不允许"})

    def _handle_api(self, method, path, query):
        config = RuntimeConfig()
        token = self._session_token()
        session = SESSIONS.get(token) if token else None

        matched = None
        for route_method, pattern, handler, need_auth in _COMPILED_ROUTES:
            if route_method != method:
                continue
            match = pattern.match(path)
            if match:
                matched = (match, handler, need_auth)
                break

        if matched is None:
            # 405 还是 404：路径对但方法不对时给 405，否则 404。
            # 这个区分对排障有用，也不会泄露额外信息（路由表是固定的）。
            for route_method, pattern, _handler, _auth in _COMPILED_ROUTES:
                if pattern.match(path):
                    self._send_json(405, {"error": "该路径不支持 %s" % method})
                    return
            self._send_json(404, {"error": "未知接口：%s" % path})
            return

        match, handler, need_auth = matched

        if need_auth and session is None:
            self._send_json(401, {"error": "未登录或会话已过期"},
                            [("WWW-Authenticate", "Session")])
            return

        if not config.pass_hash and need_auth:
            self._send_json(503, {
                "error": "面板还没有设置口令，服务拒绝提供任何数据。",
                "hint": "在服务器上执行：wgmgr web passwd",
            })
            return

        ctx = {
            "config": config,
            "client_ip": self._client_ip(),
            "user": (session or {}).get("user"),
            "session_token": token,
            "secure": self._is_secure(),
        }

        try:
            body = self._read_body() if method in ("POST", "DELETE") else {}
        except BadRequest as exc:
            self._send_json(400, {"error": exc.message})
            return

        extra = []
        try:
            result = handler(ctx, match, query, body)
        except BadRequest as exc:
            self._send_json(400, {"error": exc.message})
            return
        except PermissionError as exc:
            self._send_json(403, {"error": str(exc)})
            return
        except LookupError as exc:
            self._send_json(404, {"error": str(exc)})
            return
        except C.CliError as exc:
            self._send_json(502, {"error": "调用管理核心失败：%s" % exc})
            return
        except RuntimeError as exc:
            self._send_json(409, {"error": str(exc)})
            return
        except Exception as exc:      # 兜底：不把 traceback 回给浏览器
            C.log_line("处理 %s %s 时异常：%r" % (method, path, exc))
            self._send_json(500, {"error": "服务器内部错误"})
            return

        if ctx.get("log_line"):
            C.log_line(ctx["log_line"])

        if ctx.get("set_session"):
            extra.append(self._session_cookie(ctx["set_session"], config))
        if ctx.get("clear_session"):
            extra.append(("Set-Cookie",
                          "wgm_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"))

        # handler 返回 (content_type, bytes, disposition) 时按原始字节发，
        # 用于下载 .conf 和二维码 PNG；否则一律当 JSON 对象。
        if isinstance(result, tuple):
            content_type, payload, disposition = result
            if disposition:
                extra.append(("Content-Disposition", disposition))
            self._send(200, content_type, payload, extra)
        else:
            self._send_json(200, result, extra)

    # ---- 静态资源 ----

    def _handle_static(self, path):
        if path == "/":
            path = "/index.html"

        # 只允许 static/ 目录下的普通文件。realpath 之后必须仍在
        # STATIC_DIR 之内，否则就是穿越尝试（符号链接也算）。
        candidate = os.path.realpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        root = os.path.realpath(STATIC_DIR)
        if candidate != root and not candidate.startswith(root + os.sep):
            self._send_json(403, {"error": "禁止访问"})
            return
        if not os.path.isfile(candidate):
            self._send_json(404, {"error": "没有这个资源"})
            return

        ext = os.path.splitext(candidate)[1].lower()
        content_type = _CONTENT_TYPES.get(ext, "application/octet-stream")
        try:
            with open(candidate, "rb") as fh:
                payload = fh.read()
        except OSError:
            self._send_json(500, {"error": "读取失败"})
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", _CSP)
        # index.html 不缓存（改了前端要立刻能看到），带指纹的资源可以长缓存。
        # 这里没有构建步骤、也没有指纹，所以统一 no-cache：每次问一次
        # "变了没有"，代价是一个 304，换来的是不会出现"改了 JS 但页面还是旧的"。
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        # HEAD 要发完整的头和 Content-Length，但不能发响应体
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass


# --------------------------------------------------------------------------
# 服务器
# --------------------------------------------------------------------------

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # 面板可能被扫端口，连接队列不需要很大；但也不能是默认的 5，
    # 否则前端一次并发拉 6 个接口就会开始丢连接。
    request_queue_size = 64

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        # 客户端中途关连接是常态，不该刷屏
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, socket.timeout)):
            return
        C.log_line("处理来自 %s 的请求时出错：%r" % (client_address, exc))


def _wrap_tls(server, cert: str, key: str):
    """给监听 socket 套上 TLS。成功后置位模块级 TLS_ENABLED。"""
    global TLS_ENABLED
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    TLS_ENABLED = True
    return server


def _parse_listen(listen: str):
    """把 web.conf 里的 WEB_LISTEN 拆成 (host, port)。"""
    listen = (listen or "").strip()
    if not listen:
        listen = "127.0.0.1:8443"
    host, _, port = listen.rpartition(":")
    if not host:
        host = "127.0.0.1"
    try:
        port_num = int(port)
    except ValueError:
        raise SystemExit("WEB_LISTEN 里的端口非法：%r" % listen)
    if not 1 <= port_num <= 65535:
        raise SystemExit("WEB_LISTEN 里的端口超出范围：%d" % port_num)
    return host, port_num


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="WireGuard Manager Web 面板")
    parser.add_argument("--listen", default="",
                        help="覆盖 web.conf 里的 WEB_LISTEN（host:port）")
    parser.add_argument("--check", action="store_true",
                        help="只做启动前自检，不真正监听")
    args = parser.parse_args(argv)

    config = RuntimeConfig()

    problems = []
    if not config.pass_hash:
        problems.append("没有设置登录口令 —— 执行：wgmgr web passwd")
    elif not config.pass_hash.startswith("scrypt$"):
        problems.append("WEB_PASS_HASH 格式不对，应该是 scrypt$N$r$p$salt$hash")
    if not os.path.isdir(STATIC_DIR):
        problems.append("找不到前端目录：%s" % STATIC_DIR)
    elif not os.path.isfile(os.path.join(STATIC_DIR, "index.html")):
        problems.append("缺少 %s/index.html" % STATIC_DIR)
    if os.geteuid() == 0 and config.bind_scope == "public":
        # root 跑公网面板本身不是错的，但值得提醒一次：
        # systemd 单元里已经把它降权到 wgmgr-web 了，手动用 root 起会绕过这层保护。
        C.log_line("警告：正在以 root 身份运行 Web 面板。systemd 单元会降权到 wgmgr-web，"
                   "手动启动请自行确认。")

    if args.check:
        if problems:
            for item in problems:
                C.log_line("自检失败：%s" % item)
            return 1
        C.log_line("自检通过：user=%s scope=%s readonly=%s key_export=%s static=%s" % (
            config.user, config.bind_scope, config.readonly,
            config.allow_key_export(), STATIC_DIR))
        return 0

    if problems:
        for item in problems:
            C.log_line("启动失败：%s" % item)
        return 1

    if args.listen:
        host, port = _parse_listen(args.listen)
    else:
        host, port = _parse_listen(config.web.get("WEB_LISTEN"))

    try:
        server = Server((host, port), Handler)
    except PermissionError:
        C.log_line("无法绑定 %s:%d —— 端口 <1024 需要 root，或者端口已被占用" % (host, port))
        return 1
    except OSError as exc:
        C.log_line("无法绑定 %s:%d —— %s" % (host, port, exc))
        return 1

    cert = (config.web.get("WEB_TLS_CERT") or "").strip()
    key = (config.web.get("WEB_TLS_KEY") or "").strip()
    scheme = "http"
    if cert and key:
        if not (os.path.isfile(cert) and os.path.isfile(key)):
            C.log_line("TLS 证书或私钥文件不存在：%s / %s" % (cert, key))
            return 1
        try:
            _wrap_tls(server, cert, key)
            scheme = "https"
        except Exception as exc:
            C.log_line("启用 TLS 失败：%s" % exc)
            return 1
    elif config.bind_scope == "public":
        # 绑 0.0.0.0 又不跑 TLS，登录口令就是明文过公网。
        # 不阻止启动（前面通常挂着反代），但必须说清楚。
        C.log_line("警告：面板绑定在 0.0.0.0 且没有启用 TLS。"
                   "如果前面没有 HTTPS 反向代理，登录口令将以明文传输。"
                   "要么在 web.conf 里配置 WEB_TLS_CERT/WEB_TLS_KEY，"
                   "要么把 WEB_BIND_SCOPE 改成 vpn。")

    C.log_line("面板启动 %s://%s:%d/  scope=%s readonly=%s key_export=%s pid=%d" % (
        scheme, host, port, config.bind_scope, config.readonly,
        config.allow_key_export(), os.getpid()))

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        C.log_line("面板已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
