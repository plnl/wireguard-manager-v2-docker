#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— 采集守护进程。

一个周期做五件事：

  1. `wgmgr collect`              刷新 state/status.json（Bash 侧，root）
  2. 追加一个流量采样点            state/traffic/YYYY-MM-DD.jsonl
  3. 跑一遍 Health Check          state/health.json
  4. 跑一遍告警评估               state/alerts.json（+ 实际推送）
  5. 定期快照防火墙规则和日志尾部   state/firewall.json / state/manager-log.json

第 5 步是特意让**采集进程（root）**去做的，而不是让 Web 进程做：
Web 面板以非特权的 wgmgr-web 用户运行，它读不到 nft/iptables，也读不到
root 拥有的 manager.log。把结果落成 state/ 下的 JSON，面板就能在完全不
提权的前提下展示这些信息。这正是建议文档里"状态和配置分离"的落地方式
—— 面板挂了，采集照常；采集挂了，WireGuard 照常。

这个进程**不碰任何配置**，只读 wg show + 写 state/，所以它不参与
Bash 侧的 flock 排它锁：否则你人在菜单里停着不动，采集就全停了。
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import os
import signal
import subprocess
import sys
import time

import wgm_alert
import wgm_common as C
import wgm_health
import wgm_traffic

LOCK_PATH = "/run/wireguard-manager-collector.lock"

# 防火墙规则快照的周期倍数。`nft list` / `iptables -S` 不算贵，
# 但也没必要每 30 秒跑一次——规则只在有人改配置时才变。
_FW_SNAPSHOT_EVERY = 10

_LOG_TAIL_LINES = 200

_shutdown = False


def _on_signal(signum, _frame):
    global _shutdown
    _shutdown = True
    C.log_line("收到信号 %d，本轮结束后退出" % signum)


def _acquire_lock():
    """防止两个采集进程同时跑（systemd 重启竞态、或者手动 --once 撞上服务）。"""
    try:
        fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        # /run 不可写不是致命问题：采集本身是幂等的，两个进程同时写
        # state/ 也只是浪费一点 CPU（写入都是 tmp+rename 原子的）。
        C.log_line("无法创建锁文件 %s（%s），继续但不做互斥" % (LOCK_PATH, exc))
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            os.close(fd)
            raise SystemExit("另一个采集进程已经在运行，退出。")
        os.close(fd)
        return None
    os.write(fd, str(os.getpid()).encode())
    return fd


def _snapshot_firewall() -> None:
    """把 root 才能看到的防火墙规则落到 state/，供非特权的面板展示。"""
    status = C.load_status()
    iface = status.get("interface") or {}
    system = status.get("system") or {}
    try:
        proc = subprocess.run(
            [C.CLI, "fw", "show"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        raw = proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        C.log_line("防火墙快照失败：%s" % exc)
        return

    C.atomic_write_json(C.FIREWALL_JSON, {
        "generated_at": int(time.time()),
        "generated_at_str": C.ts_str(int(time.time())),
        "backend": iface.get("fw_backend", "none"),
        "port_listening": bool(system.get("port_listening")),
        "nat_rule_present": bool(system.get("nat_rule_present")),
        "raw": raw[:65536],
    })


def _snapshot_manager_log() -> None:
    """把 manager.log 的尾部复制到 state/，面板才读得到（原文件是 root 600）。

    只在日志真的变了的时候重写：内容不变时每 30 秒刷一次 mtime，
    会让"最后修改时间"这个信息失去意义。
    """
    try:
        stat = os.stat(C.MANAGER_LOG)
    except OSError:
        return

    marker = "%d:%d" % (stat.st_size, int(stat.st_mtime))
    cache = getattr(_snapshot_manager_log, "_marker", None)
    if cache == marker:
        return
    _snapshot_manager_log._marker = marker

    try:
        with open(C.MANAGER_LOG, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            # 只读最后 256KB，日志很长的时候不要把整个文件拉进内存
            fh.seek(max(0, size - 262144))
            blob = fh.read()
    except OSError as exc:
        C.log_line("读操作日志失败：%s" % exc)
        return

    lines = blob.decode("utf-8", "replace").splitlines()[-_LOG_TAIL_LINES:]
    digest = hashlib.sha256(("\n".join(lines)).encode("utf-8")).hexdigest()[:16]

    C.atomic_write_json(C.MANAGER_LOG_JSON, {
        "generated_at": int(time.time()),
        "digest": digest,
        "lines": lines,
    })


def cycle(seq: int) -> dict:
    """跑一轮完整采集，返回本轮摘要。任何一步失败都不影响后面的步骤。"""
    summary = {"seq": seq, "ok": True, "errors": []}

    # 1. Bash 侧刷新 status.json
    try:
        code, out, err = C.run_cli(["collect"], timeout=90)
        if code != 0:
            summary["ok"] = False
            summary["errors"].append("collect 退出码 %d：%s" % (code, (err or out).strip()[:200]))
    except C.CliError as exc:
        summary["ok"] = False
        summary["errors"].append("collect：%s" % exc)

    status = C.load_status()
    conf = C.manager_conf()

    if not status:
        summary["ok"] = False
        summary["errors"].append("status.json 读不到，本轮跳过后续步骤")
        return summary

    # 2. 流量采样
    try:
        wgm_traffic.append_sample(status)
    except Exception as exc:
        summary["errors"].append("traffic：%s" % exc)

    # 3. Health Check
    try:
        health = wgm_health.build_health(status, conf)
        wgm_health.write_health(health)
        summary["health_ok"] = health["ok"]
        summary["counts"] = health["counts"]
    except Exception as exc:
        summary["ok"] = False
        summary["errors"].append("health：%s" % exc)

    # 4. 告警评估
    try:
        result = wgm_alert.evaluate(status, conf)
        summary["alerts"] = result["fired"]
    except Exception as exc:
        # 告警失败绝不能影响采集：宁可少推一条，也不能让状态层停更
        summary["errors"].append("alert：%s" % exc)

    # 5. 低频快照
    if seq % _FW_SNAPSHOT_EVERY == 0:
        _snapshot_firewall()
    _snapshot_manager_log()

    # 6. 每天清一次过期采样
    if seq % 2880 == 0:
        removed = wgm_traffic.prune()
        if removed:
            C.log_line("清理了 %d 个过期流量采样文件" % removed)

    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="WireGuard Manager 采集守护进程")
    parser.add_argument("--once", action="store_true", help="只跑一轮就退出")
    parser.add_argument("--interval", type=int, default=0,
                        help="覆盖 manager.conf 里的 COLLECT_INTERVAL")
    parser.add_argument("--quiet", action="store_true", help="正常轮次不打印")
    args = parser.parse_args(argv)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    lock_fd = _acquire_lock()

    conf = C.manager_conf()
    interval = args.interval or C.conf_int(conf, "COLLECT_INTERVAL", 30)
    if interval < 5:
        # 采集一轮本身要 fork 几十次，间隔太短会和它自己打架
        C.log_line("采集间隔 %d 秒过小，已提升到 5 秒" % interval)
        interval = 5

    C.log_line("采集启动 pid=%d interval=%ds state=%s" % (os.getpid(), interval, C.STATE_DIR))

    seq = 0
    try:
        while not _shutdown:
            started = time.time()
            seq += 1
            try:
                summary = cycle(seq)
            except Exception as exc:      # 兜底：守护进程绝不能因为一轮异常就退出
                summary = {"seq": seq, "ok": False, "errors": ["cycle：%s" % exc]}

            if not args.quiet and (summary.get("errors") or not summary.get("ok")):
                C.log_line("第 %d 轮异常：%s" % (seq, "; ".join(summary["errors"])))
            elif not args.quiet and seq % 20 == 0:
                # 每 20 轮打一次心跳，方便从 journalctl 确认它还活着
                counts = summary.get("counts") or {}
                C.log_line("心跳 seq=%d ✗%d ⚠%d 告警=%s" % (
                    seq, counts.get("error", 0), counts.get("warn", 0),
                    ",".join(summary.get("alerts") or []) or "-"))

            if args.once:
                if summary.get("errors"):
                    for err in summary["errors"]:
                        C.log_line("  · %s" % err)
                return 0 if summary.get("ok") else 1

            # 从"本轮结束"开始算下一次，而不是从"本轮开始"——
            # 否则一轮跑了 40 秒而间隔是 30 秒时，会变成背靠背连轴转。
            elapsed = time.time() - started
            remaining = interval - elapsed
            deadline = time.time() + max(1.0, remaining)
            while not _shutdown and time.time() < deadline:
                time.sleep(min(1.0, deadline - time.time()))
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass

    C.log_line("采集退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
