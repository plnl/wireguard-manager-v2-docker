#!/usr/bin/env python3
"""WireGuard Manager V2.0 -- Peer 分享链接模块。

生成限时公开链接，对方免登录下载客户端配置。
数据存储在 state/share_links.json，纯 JSON 文件，无需数据库。
"""

from __future__ import annotations

import json
import os
import secrets
import time

import wgm_common as C


_SHARE_FILE = os.path.join(C.STATE_DIR, "share_links.json")
_SHARE_TTL_DEFAULT = 86400
_SHARE_TTL_MAX = 7 * 86400


def _load() -> list:
    if not os.path.isfile(_SHARE_FILE):
        return []
    try:
        with open(_SHARE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save(links: list) -> None:
    C.atomic_write(_SHARE_FILE, json.dumps(links, ensure_ascii=False, indent=2))


def _purge_expired(links: list) -> list:
    now = int(time.time())
    alive = [l for l in links if not l.get("expire_at") or l.get("expire_at") > now]
    if len(alive) != len(links):
        _save(alive)
    return alive


def create_link(peer_name: str, expire_seconds: int = _SHARE_TTL_DEFAULT) -> dict:
    links = _purge_expired(_load())
    share_id = secrets.token_urlsafe(16)
    now = int(time.time())
    expire_at = now + min(max(expire_seconds, 60), _SHARE_TTL_MAX)
    link = {
        "id": share_id,
        "peer": peer_name,
        "created_at": now,
        "expire_at": expire_at,
    }
    links.append(link)
    _save(links)
    return link


def list_links(peer_name: str | None = None) -> list:
    links = _purge_expired(_load())
    if peer_name:
        return [l for l in links if l.get("peer") == peer_name]
    return links


def get_link(share_id: str) -> dict | None:
    links = _purge_expired(_load())
    for l in links:
        if l.get("id") == share_id:
            return l
    return None


def delete_link(share_id: str) -> bool:
    links = _purge_expired(_load())
    before = len(links)
    links = [l for l in links if l.get("id") != share_id]
    if len(links) != before:
        _save(links)
        return True
    return False


def is_valid(share_id: str) -> bool:
    link = get_link(share_id)
    if not link:
        return False
    now = int(time.time())
    if link.get("expire_at") and link["expire_at"] <= now:
        return False
    return True
