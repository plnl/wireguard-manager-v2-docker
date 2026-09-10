#!/usr/bin/env python3
"""WireGuard Manager V2.0 —— 流量历史。

数据来源：`wg show dump` 给出的 rx/tx 是**自接口起来以后的累计值**，
不是速率。所以这里存的是累计快照，报表阶段再相邻两点相减得到区间流量。
存累计值而不是存差值有两个好处：

  1. 采集进程崩过一次、漏了几个点，历史不会因此算错——差值只是拉长到
     下一个存在的点，总量仍然守恒。
  2. 计数器归零（wg-quick down/up、Peer 被删掉重建、机器重启）时，
     当前值会小于上一个值，这时候把上一个值当作 0 处理即可，不会算出
     一个天文数字或者负数。这个判断只有在保留了原始累计值时才做得到。

存储：state/traffic/YYYY-MM-DD.jsonl，一行一个采样点。
选 JSONL 而不是一个大 JSON 数组，是为了让采集进程能 O(1) 追加，
不用每 30 秒把整天的数据读进来再写回去。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

import wgm_common as C

# 每个时间范围对应的趋势图分桶粒度（秒）
_BUCKETS = {
    "24h": 1800,
    "7d": 21600,
    "30d": 86400,
    "today": 3600,
    "yesterday": 3600,
    "week": 43200,
    "month": 86400,
}

_RANGE_SECONDS = {
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
}

# 对外暴露的合法 range 取值。Web 层校验参数时用这个，
# 不去引用 _BUCKETS 这种模块内私有名。
RANGES = tuple(sorted(_BUCKETS))


# --------------------------------------------------------------------------
# 采样
# --------------------------------------------------------------------------

def _day_file(day: str) -> str:
    return os.path.join(C.TRAFFIC_DIR, "%s.jsonl" % day)


def append_sample(status: dict) -> bool:
    """把一次采集结果追加成一个采样点。返回是否真的写了。"""
    if not status:
        return False

    peers = status.get("peers") or []
    summary = status.get("summary") or {}
    now = int(time.time())

    per_peer = {}
    for peer in peers:
        name = peer.get("name") or peer.get("id")
        if not name:
            continue
        per_peer[name] = [
            int(peer.get("rx_bytes") or 0),
            int(peer.get("tx_bytes") or 0),
        ]

    sample = {
        "t": now,
        "rx": int(summary.get("rx_bytes_total") or 0),
        "tx": int(summary.get("tx_bytes_total") or 0),
        "up": bool((status.get("interface") or {}).get("running")),
        "p": per_peer,
    }

    os.makedirs(C.TRAFFIC_DIR, exist_ok=True)
    path = _day_file(time.strftime("%Y-%m-%d", time.localtime(now)))
    try:
        # 追加写不需要临时文件：单行 write 在 O_APPEND 下是原子的，
        # 而且读方（报表）逐行解析，天然会忽略最后可能存在的半行。
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(sample, ensure_ascii=False, separators=(",", ":")))
            fh.write("\n")
        os.chmod(path, 0o640)
    except OSError as exc:
        C.log_line("流量采样写入失败：%s" % exc)
        return False
    return True


def prune() -> int:
    """删掉超过保留期的采样文件，返回删除个数。"""
    cutoff = time.time() - C.TRAFFIC_RETENTION_DAYS * 86400
    removed = 0
    for path in glob.glob(os.path.join(C.TRAFFIC_DIR, "*.jsonl")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.unlink(path)
                removed += 1
        except OSError:
            pass
    return removed


def _iter_raw(since: float, until: float):
    """按时间顺序产出 [since, until] 内的采样点。

    只打开日期上可能相交的那几个文件，不扫整个目录。
    """
    files = sorted(glob.glob(os.path.join(C.TRAFFIC_DIR, "*.jsonl")))
    if not files:
        return

    day = time.strftime("%Y-%m-%d", time.localtime(since))
    for path in files:
        name = os.path.basename(path)[:10]
        if name < day:
            continue
        if name > time.strftime("%Y-%m-%d", time.localtime(until)):
            break
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        sample = json.loads(line)
                    except ValueError:
                        continue    # 最后一行可能正被写，跳过
                    ts = sample.get("t")
                    if not isinstance(ts, int):
                        continue
                    if since <= ts <= until:
                        yield sample
        except OSError:
            continue


# --------------------------------------------------------------------------
# 区间统计
# --------------------------------------------------------------------------

def _window_delta(samples):
    """把一段累计快照折算成 (rx_delta, tx_delta)。

    首尾相减即可，中间点不参与总量计算——这样即使中间某次采集正好撞上
    计数器归零，也不会污染总量（归零只会让总量偏小，不会偏大）。
    """
    if len(samples) < 2:
        return 0, 0

    def diff(first, last):
        delta = last - first
        # 计数器归零：接口重启过。这时 last 就是从 0 重新累计的量，
        # 直接用它本身，而不是那个负数差值。
        return last if delta < 0 else delta

    return (
        diff(int(samples[0].get("rx") or 0), int(samples[-1].get("rx") or 0)),
        diff(int(samples[0].get("tx") or 0), int(samples[-1].get("tx") or 0)),
    )


def _peer_window_delta(samples, name: str):
    if len(samples) < 2:
        return 0, 0

    def value(sample):
        entry = (sample.get("p") or {}).get(name)
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            return None
        return int(entry[0]), int(entry[1])

    first = last = None
    for sample in samples:
        val = value(sample)
        if val is None:
            continue
        if first is None:
            first = val
        last = val

    if first is None or last is None:
        return 0, 0

    def diff(a, b):
        delta = b - a
        return b if delta < 0 else delta

    return diff(first[0], last[0]), diff(first[1], last[1])


def _pair_delta(before, after):
    """两个累计快照之间的增量 (rx, tx)，带计数器归零钳制。"""
    def diff(key, index):
        a = int(before.get(key) or 0)
        b = int(after.get(key) or 0)
        delta = b - a
        # 计数器归零（接口重启 / Peer 重建）：b 就是从 0 重新累计的量，
        # 用它本身，而不是那个负数差值。
        return b if delta < 0 else delta

    return diff("rx", 0), diff("tx", 1)


def _bucket_series(samples, bucket_sec: int):
    """把累计快照折算成按 bucket_sec 分桶的区间流量。

    每个桶的值 = 桶内最后一个累计值 − 上一个桶的最后一个累计值
    （第一个桶用整个窗口的第一个采样点做基准）。

    刻意不用"桶内首尾相减"：桶宽经常和采样间隔是同一个量级
    （24h 范围对应 30 分钟桶），那样每个桶里只有一两个点，差值要么算不出来
    要么抖得没法看。用跨桶的基准点，结果就和采样密度无关了。

    没有任何采样的桶会补成 0 而不是直接跳过——采集断档几个小时的时候，
    跳过会把时间轴压缩，趋势图看起来像那段时间流量很密集，是误导。
    """
    if len(samples) < 2:
        return []

    # 每个桶只保留最后一个采样点
    last_in_bucket = {}
    for sample in samples[1:]:
        last_in_bucket[(sample["t"] // bucket_sec) * bucket_sec] = sample

    if not last_in_bucket:
        return []

    first_bucket = (samples[0]["t"] // bucket_sec) * bucket_sec
    last_bucket = max(last_in_bucket)

    series = []
    baseline = samples[0]
    for start in range(first_bucket, last_bucket + bucket_sec, bucket_sec):
        endpoint = last_in_bucket.get(start)
        if endpoint is None:
            # 这个桶里一个采样点都没有：断档，记 0，基准保持不变，
            # 等下一个有数据的桶再一起结算。
            series.append({"t": start, "rx": 0, "tx": 0, "gap": True})
            continue
        rx, tx = _pair_delta(baseline, endpoint)
        series.append({"t": start, "rx": rx, "tx": tx, "gap": False})
        baseline = endpoint

    return series


def _day_bounds(offset_days: int = 0):
    """本地时间某天的 [00:00, 24:00) 区间。offset_days=0 是今天，-1 是昨天。"""
    now = time.localtime()
    midnight = time.mktime(
        (now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, now.tm_isdst)
    )
    start = midnight + offset_days * 86400
    return int(start), int(start + 86400)


def _week_bounds():
    """本周（周一起算）到现在。"""
    now = time.localtime()
    midnight = time.mktime(
        (now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, now.tm_isdst)
    )
    # tm_wday：周一=0
    return int(midnight - now.tm_wday * 86400), int(time.time())


def _month_bounds():
    now = time.localtime()
    start = time.mktime(
        (now.tm_year, now.tm_mon, 1, 0, 0, 0, 0, 0, now.tm_isdst)
    )
    return int(start), int(time.time())


def _range_bounds(range_key: str):
    now = int(time.time())
    if range_key in _RANGE_SECONDS:
        return now - _RANGE_SECONDS[range_key], now
    if range_key == "today":
        return _day_bounds(0)
    if range_key == "yesterday":
        return _day_bounds(-1)
    if range_key == "week":
        return _week_bounds()
    if range_key == "month":
        return _month_bounds()
    return now - 86400, now


def build_report(range_key: str = "24h", by_peer: bool = False) -> dict:
    now = int(time.time())
    start, end = _range_bounds(range_key)
    # 报表不要越过"现在"，否则最后一个桶永远是半空的
    end = min(end, now)

    samples = list(_iter_raw(start, end))
    rx, tx = _window_delta(samples)
    bucket = _BUCKETS.get(range_key, 1800)

    report = {
        "range": range_key,
        "from": start,
        "to": end,
        "from_str": C.ts_str(start),
        "to_str": C.ts_str(end),
        "samples": len(samples),
        "bucket_sec": bucket,
        "total": {"rx": rx, "tx": tx, "rx_h": C.human_bytes(rx), "tx_h": C.human_bytes(tx)},
        "series": _bucket_series(samples, bucket),
        # 这四个固定周期是建议文档里明确画出来的那张表，
        # 不管你选的 range 是什么都一起给，省得来回切。
        "periods": [],
        "peers": [],
    }

    for key, label, bounds in (
        ("today", "今天", _day_bounds(0)),
        ("yesterday", "昨天", _day_bounds(-1)),
        ("week", "本周", _week_bounds()),
        ("month", "本月", _month_bounds()),
    ):
        p_start, p_end = bounds
        p_end = min(p_end, now)
        p_samples = list(_iter_raw(p_start, p_end))
        p_rx, p_tx = _window_delta(p_samples)
        report["periods"].append({
            "key": key,
            "label": label,
            "rx": p_rx,
            "tx": p_tx,
            "rx_h": C.human_bytes(p_rx),
            "tx_h": C.human_bytes(p_tx),
            "samples": len(p_samples),
        })

    if by_peer:
        names = []
        seen = set()
        for sample in samples:
            for name in (sample.get("p") or {}):
                if name not in seen:
                    seen.add(name)
                    names.append(name)

        status = C.load_status()
        kinds = {
            (p.get("name") or p.get("id")): p.get("kind", "")
            for p in (status.get("peers") or [])
        }

        for name in sorted(names):
            p_rx, p_tx = _peer_window_delta(samples, name)
            if p_rx == 0 and p_tx == 0:
                continue
            report["peers"].append({
                "name": name,
                "kind": kinds.get(name, ""),
                "rx": p_rx,
                "tx": p_tx,
                "rx_h": C.human_bytes(p_rx),
                "tx_h": C.human_bytes(p_tx),
            })
        report["peers"].sort(key=lambda item: item["rx"] + item["tx"], reverse=True)

    return report


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------

def _bar(value: float, peak: float, width: int = 40) -> str:
    if peak <= 0:
        return ""
    filled = int(round(value / peak * width))
    return "█" * max(0, min(width, filled))


def print_report(report: dict, by_peer: bool = False) -> None:
    total = report["total"]
    print("=" * 62)
    print("  流量统计  范围：%s（%s ~ %s）" % (
        report["range"], report["from_str"], report["to_str"]))
    print("=" * 62)
    print()

    print("  %-8s %14s %14s %8s" % ("周期", "接收 RX", "发送 TX", "采样点"))
    print("  %-8s %14s %14s %8s" % ("--------", "--------------",
                                    "--------------", "--------"))
    for period in report["periods"]:
        print("  %-8s %14s %14s %8d" % (
            period["label"], period["rx_h"], period["tx_h"], period["samples"]))
    print("  %-8s %14s %14s %8d" % (
        "所选范围", total["rx_h"], total["tx_h"], report["samples"]))
    print()

    if report["samples"] < 2:
        print("  采样点不足，无法画趋势。")
        print("  采集服务是否已经安装并启动？wgmgr web install / wgmgr web status")
        return

    series = report["series"]
    peak = max([max(point["rx"], point["tx"]) for point in series] or [0])
    print("  趋势（每格 %s，█ 接收 / ▒ 发送，峰值 %s）" % (
        C.human_duration(report["bucket_sec"]), C.human_bytes(peak)))
    print()
    for point in series:
        label = time.strftime("%m-%d %H:%M", time.localtime(point["t"]))
        rx_bar = _bar(point["rx"], peak, 30)
        tx_bar = _bar(point["tx"], peak, 30).replace("█", "▒")
        print("  %s │%-30s %s" % (label, rx_bar, C.human_bytes(point["rx"])))
        print("  %s │%-30s %s" % (" " * len(label), tx_bar, C.human_bytes(point["tx"])))
    print()

    if by_peer and report["peers"]:
        print("  按 Peer 汇总（所选范围）")
        print("  %-20s %-8s %12s %12s" % ("NAME", "KIND", "RX", "TX"))
        for peer in report["peers"]:
            print("  %-20s %-8s %12s %12s" % (
                peer["name"], peer["kind"] or "-", peer["rx_h"], peer["tx_h"]))
        print()
    elif by_peer:
        print("  按 Peer 汇总：所选范围内没有任何 Peer 产生流量。")
        print()


def print_chart(range_key: str = "24h") -> None:
    report = build_report(range_key)
    series = report["series"]
    if not series:
        print("没有可用的采样数据。")
        return

    peak = max([max(p["rx"], p["tx"]) for p in series] or [1]) or 1
    height = 14
    print()
    print("  流量趋势  %s  （峰值 %s / 桶，桶宽 %s）" % (
        range_key, C.human_bytes(peak), C.human_duration(report["bucket_sec"])))
    print()

    grid = [[" "] * len(series) for _ in range(height)]
    for col, point in enumerate(series):
        rx_level = int(round(point["rx"] / peak * (height - 1)))
        tx_level = int(round(point["tx"] / peak * (height - 1)))
        grid[height - 1 - rx_level][col] = "█"
        row = height - 1 - tx_level
        grid[row][col] = "▒" if grid[row][col] == " " else "▓"

    for row in grid:
        print("  │%s" % "".join(row))
    print("  └%s" % ("─" * len(series)))
    print("   %s%s" % (
        time.strftime("%m-%d %H:%M", time.localtime(series[0]["t"])),
        " " * max(1, len(series) - 22),
    ) + time.strftime("%m-%d %H:%M", time.localtime(series[-1]["t"])))
    print()
    print("   █ 接收 RX    ▒ 发送 TX    ▓ 两者重叠")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="WireGuard 流量统计")
    sub = parser.add_subparsers(dest="cmd")

    rep = sub.add_parser("report", help="输出报表")
    rep.add_argument("--range", dest="range_key", default="24h",
                     choices=sorted(_BUCKETS))
    rep.add_argument("--by-peer", action="store_true")
    rep.add_argument("--json", action="store_true")

    chart = sub.add_parser("chart", help="输出 ASCII 趋势图")
    chart.add_argument("--range", dest="range_key", default="24h",
                       choices=sorted(_BUCKETS))

    sample = sub.add_parser("sample", help="立即追加一个采样点（调试用）")
    sample.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "report":
        report = build_report(args.range_key, by_peer=args.by_peer)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print_report(report, by_peer=args.by_peer)
        return 0

    if args.cmd == "chart":
        print_chart(args.range_key)
        return 0

    if args.cmd == "sample":
        status = C.load_status()
        ok = append_sample(status)
        if args.json:
            print(json.dumps({"ok": ok, "peers": len((status.get("peers") or []))}))
        else:
            print("已采样" if ok else "采样失败（status.json 不存在？）")
        return 0 if ok else 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
