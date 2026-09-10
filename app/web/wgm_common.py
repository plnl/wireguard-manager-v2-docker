#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— Python 层共享基础。

刻意只用标准库：这台机器上跑的是网络基础设施，面板不能因为
`pip install` 失败、venv 被 apt 升级冲掉、或者某个第三方包改了 API
就跟着一起挂。标准库版本要求 Python 3.8+（Debian 10 / Ubuntu 20.04 自带）。

路径全部来自 Bash 侧通过环境变量传入（见 wireguard-manager-v2.0.sh 的
web_python()），这里只保留一份和 Bash 常量一致的兜底默认值，方便单独调试。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

# --------------------------------------------------------------------------
# 路径
# --------------------------------------------------------------------------

MANAGER_DIR = os.environ.get("WGM_MANAGER_DIR", "/etc/wireguard-manager")
STATE_DIR = os.environ.get("WGM_STATE_DIR", os.path.join(MANAGER_DIR, "state"))
LOG_DIR = os.environ.get("WGM_LOG_DIR", os.path.join(MANAGER_DIR, "logs"))
WEB_CONF = os.environ.get("WGM_WEB_CONF", os.path.join(MANAGER_DIR, "web.conf"))
MANAGER_CONF = os.environ.get(
    "WGM_MANAGER_CONF", os.path.join(MANAGER_DIR, "manager.conf")
)
CLI = os.environ.get("WGM_CLI", "/usr/local/bin/wgmgr")
INTERFACE = os.environ.get("WGM_INTERFACE", "wg0")

TRAFFIC_DIR = os.path.join(STATE_DIR, "traffic")
STATUS_JSON = os.path.join(STATE_DIR, "status.json")
HEALTH_JSON = os.path.join(STATE_DIR, "health.json")
ALERTS_JSON = os.path.join(STATE_DIR, "alerts.json")
TRAFFIC_JSON = os.path.join(STATE_DIR, "traffic.json")
FIREWALL_JSON = os.path.join(STATE_DIR, "firewall.json")
MANAGER_LOG_JSON = os.path.join(STATE_DIR, "manager-log.json")
MANAGER_LOG = os.path.join(LOG_DIR, "manager.log")

# 流量采样保留天数。30 秒一次、20 个 Peer，一天大约 1MB，90 天不到 100MB。
TRAFFIC_RETENTION_DAYS = 90


# --------------------------------------------------------------------------
# key=value 配置读取
#
# 和 Bash 侧 set_kv/get_kv 的语义严格一致：`KEY=VALUE` 一行一条，
# 同一个 KEY 出现多次时**最后一次**生效（Bash 那边是 grep | tail -n 1）。
# --------------------------------------------------------------------------

def read_kv(path: str) -> dict:
    conf = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                conf[key.strip()] = value
    except OSError:
        pass
    return conf


def manager_conf() -> dict:
    return read_kv(MANAGER_CONF)


def web_conf() -> dict:
    return read_kv(WEB_CONF)


def conf_int(conf: dict, key: str, default: int) -> int:
    try:
        return int(str(conf.get(key, "")).strip())
    except (TypeError, ValueError):
        return default


def conf_bool(conf: dict, key: str, default: bool = False) -> bool:
    raw = str(conf.get(key, "")).strip().lower()
    if not raw:
        return default
    return raw in ("yes", "true", "1", "on")


# --------------------------------------------------------------------------
# 原子写
#
# Web 面板和采集进程是两个独立的进程，面板随时可能正在读 state/*.json。
# 直接 open(w) 会让面板读到半截文件、json.loads 抛异常；先写同目录临时文件
# 再 rename，在同一文件系统上是原子的，读方要么看到旧的完整版、要么新的完整版。
# --------------------------------------------------------------------------

def atomic_write_text(path: str, text: str, mode: int = 0o640) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".wgm-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: str, obj, mode: int = 0o640) -> None:
    atomic_write_text(
        path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n", mode
    )


def load_json(path: str, default=None):
    """读 JSON。文件不存在/半截损坏时返回 default，绝不抛异常。

    面板是"只读观测层"，一次采集写入撞上一次读取不应该让整页 500。
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def load_status() -> dict:
    return load_json(STATUS_JSON, {}) or {}


def file_age_sec(path: str):
    try:
        return max(0, int(time.time() - os.path.getmtime(path)))
    except OSError:
        return None


# --------------------------------------------------------------------------
# 展示辅助
# --------------------------------------------------------------------------

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(value) -> str:
    try:
        num = float(value or 0)
    except (TypeError, ValueError):
        num = 0.0
    idx = 0
    while num >= 1024 and idx < len(_UNITS) - 1:
        num /= 1024.0
        idx += 1
    if idx == 0:
        return "%d%s" % (num, _UNITS[idx])
    return "%.2f%s" % (num, _UNITS[idx])


def human_duration(seconds) -> str:
    if seconds is None:
        return "-"
    try:
        sec = int(seconds)
    except (TypeError, ValueError):
        return "-"
    if sec < 0:
        sec = 0
    if sec < 60:
        return "%d 秒" % sec
    if sec < 3600:
        return "%d 分钟" % (sec // 60)
    if sec < 86400:
        return "%d 小时 %d 分钟" % (sec // 3600, (sec % 3600) // 60)
    return "%d 天 %d 小时" % (sec // 86400, (sec % 86400) // 3600)


def ts_str(epoch) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(epoch)))
    except (TypeError, ValueError, OSError):
        return "-"


# --------------------------------------------------------------------------
# 调用 Bash 核心
#
# 这是 Python 侧**唯一**允许执行外部命令的入口，三条硬规矩：
#   1. 只用列表形式的 argv 交给 subprocess，shell=False。永远不拼字符串，
#      永远不经过 /bin/sh —— 否则 HTTP 里传来的一个分号就能变成命令注入。
#   2. argv 的前两段必须命中 ALLOWED_CLI 白名单。新增能力要显式往白名单里
#      加一条，而不是放开校验。
#   3. 任何参数值都要先过各自 endpoint 的校验（名字、CIDR、端口…），
#      校验发生在 wgm_web.py 里；这里再兜一层"值里不许出现 shell 元字符"，
#      纯粹是纵深防御。
# --------------------------------------------------------------------------

ALLOWED_CLI = {
    ("collect", ""),
    ("status", ""),
    ("health", ""),
    ("traffic", ""),
    ("peer", "list"),
    ("peer", "show"),
    ("client", "list"),
    ("client", "add"),
    ("client", "enable"),
    ("client", "disable"),
    ("client", "delete"),
    ("client", "conf"),
    ("client", "rotate-key"),
    ("site", "list"),
    ("site", "create"),
    ("site", "enable"),
    ("site", "disable"),
    ("site", "delete"),
    ("site", "test"),
    ("route", "list"),
    ("server", "info"),
    ("fw", "show"),
    ("fw", "backend"),
    ("fw", "sync"),
    ("backup", "create"),
    ("backup", "list"),
}

# 白名单的边界是"影响范围"，不是"危险程度"：
#   允许 —— 只影响单个 Peer 的操作（增删、启停、导出、轮换它自己的密钥）。
#           最坏情况是那一个设备连不上，重新导入配置即可，而且轮换前
#           Bash 侧自己会先打一次快照。
#   禁止 —— key rotate-server、server up/down/restart/rebuild、fw clean、
#           uninstall、web *。这些会让**所有**正在连接的 Peer 一起掉线，
#           或者干脆不可逆，必须 SSH 上去在交互菜单里由人做。
# 这样即使面板口令被爆破，攻击者能造成的损失上限也是可控的：
# 他能骚扰某一个客户端，但没法把整张网掀掉。

_META_CHARS = re.compile(r"[;&|`$<>(){}\n\r\\]")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class CliError(RuntimeError):
    pass


def valid_name(name: str) -> bool:
    """Peer / 客户端 / 站点 / 路由名。

    这个名字会被 Bash 侧直接当成目录名和 wg0.conf 里的注释用，
    所以限制得比"看起来够用"更严：不许空格、不许斜杠、不许点开头。
    """
    if not name or not _NAME_RE.match(name):
        return False
    return not name.startswith(".")


def _run(argv, timeout: int, json_mode: bool):
    """白名单校验 + 执行，返回 CompletedProcess。run_cli / run_cli_bytes 共用。"""
    if not argv:
        raise CliError("空命令")

    argv = [str(a) for a in argv]
    key = (argv[0], argv[1] if len(argv) > 1 else "")
    if key not in ALLOWED_CLI:
        raise CliError("命令不在白名单内：%s" % " ".join(argv[:2]))

    for arg in argv[2:]:
        if _META_CHARS.search(arg):
            raise CliError("参数含非法字符：%r" % arg)

    full = [CLI] + argv
    if json_mode:
        full.append("--json")

    # 面板进程降权到 wgmgr-web 跑（非 root），但 wgmgr 入口处 require_root，
    # 写操作必须以 root 落地。这里经 sudoers 白名单
    # （/etc/sudoers.d/wireguard-manager-web，只放行 /usr/local/bin/wgmgr）
    # 免密 sudo 调用；-n 确保万一规则没装好也立刻失败，绝不卡在口令提示上。
    # 采集进程本来就是 root，geteuid()==0，不加 sudo，行为完全不变。
    # 上面的白名单校验和非法字符校验都只针对 argv（wgmgr 子命令本身），
    # sudo 前缀只加在最终执行的 full 上，不绕过那两层校验。
    if os.geteuid() != 0:
        full = ["sudo", "-n"] + full

    try:
        return subprocess.run(
            full,
            shell=False,
            stdin=subprocess.DEVNULL,   # 绝不能让子命令卡在等 stdin 上
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise CliError("命令超时（%ds）：%s" % (timeout, " ".join(argv)))
    except OSError as exc:
        raise CliError("无法执行 %s：%s" % (CLI, exc))


def run_cli(argv, timeout: int = 60, json_mode: bool = False):
    """执行一条白名单内的 wgmgr 子命令，返回 (returncode, stdout, stderr)。"""
    proc = _run(argv, timeout, json_mode)
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    return proc.returncode, out, err


def run_cli_bytes(argv, timeout: int = 60):
    """和 run_cli 同一套白名单，但 stdout 保持原始字节。

    给 `client conf --png` 这种输出二进制的子命令用：走 UTF-8 解码会把
    PNG 里的非法字节替换成 U+FFFD，图片直接损坏。
    """
    proc = _run(argv, timeout, json_mode=False)
    if proc.returncode != 0:
        raise CliError(
            proc.stderr.decode("utf-8", "replace").strip()
            or "命令返回 %d" % proc.returncode
        )
    return proc.stdout


def run_cli_json(argv, timeout: int = 60):
    code, out, err = run_cli(argv, timeout=timeout, json_mode=True)
    if code != 0:
        raise CliError(err.strip() or out.strip() or "命令返回 %d" % code)
    try:
        return json.loads(out)
    except ValueError:
        # Bash 侧在 JSON 模式下会把彩色提示全部转到 stderr，
        # 走到这里说明输出被污染了，原样报出来方便定位。
        raise CliError("输出不是合法 JSON：%s" % out[:400])


def log_line(message: str) -> None:
    """采集/面板进程自己的运行日志，走 stderr 交给 journald。

    刻意不写进 manager.log：那个文件是"谁改了配置"的审计记录，
    由 Bash 侧的 log_action 独占写入，混进心跳噪音会把它冲掉。
    """
    print("%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)
