"""节点池：持久化、合并新采集、记录测试结果、淘汰长期失效节点。

pool.json 结构： { node_id: record }
record = {
  id, key, proxy{mihomo dict}, source,
  first_seen, last_seen, last_ok, fail_streak,
  latency_ms, purity{score,residential,broadcast,asn,org,cc,country,ip,ts}
}
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .util import log, node_id, node_key


def load(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("读取节点池失败（将重建）：%s", e)
        return {}


def save(path: Path, pool: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(pool, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def merge_collected(pool: dict[str, dict], nodes: list[dict]) -> int:
    now = int(time.time())
    added = 0
    for p in nodes:
        src = p.pop("_source", "")
        key = node_key(p)
        nid = node_id(p)
        if nid in pool:
            pool[nid]["last_seen"] = now
            if src:
                pool[nid]["source"] = src
        else:
            pool[nid] = {
                "id": nid, "key": key, "proxy": p, "source": src,
                "first_seen": now, "last_seen": now, "last_ok": 0,
                "fail_streak": 0, "latency_ms": None, "purity": None,
            }
            added += 1
    return added


def purity_from_api(data: dict) -> dict:
    def _int(v, d=None):
        try:
            return int(v)
        except (TypeError, ValueError):
            return d
    return {
        "score": _int(data.get("fraudScore")),
        "residential": bool(data.get("isResidential")),
        "broadcast": bool(data.get("isBroadcast")),
        "asn": _int(data.get("asn")),
        "org": data.get("asOrganization"),
        "cc": data.get("countryCode"),
        "country": data.get("country"),
        "ip": data.get("ip"),
        "ts": int(time.time()),
    }


def record_test(pool: dict[str, dict], nid: str, alive: bool, latency_ms: int | None) -> None:
    rec = pool.get(nid)
    if not rec:
        return
    now = int(time.time())
    if alive:
        rec["fail_streak"] = 0
        rec["last_ok"] = now
        rec["latency_ms"] = latency_ms
    else:
        rec["fail_streak"] = rec.get("fail_streak", 0) + 1


def record_purity(pool: dict[str, dict], nid: str, data: dict) -> None:
    rec = pool.get(nid)
    if rec:
        rec["purity"] = purity_from_api(data)


def prune(pool: dict[str, dict], max_fail: int) -> int:
    drop = [nid for nid, r in pool.items() if r.get("fail_streak", 0) >= max_fail]
    for nid in drop:
        del pool[nid]
    return len(drop)


def enforce_limits(pool: dict[str, dict], max_size: int, stale_days: float) -> int:
    """清理从未连通的陈旧节点，并把总量压到上限内（优先淘汰从未连通的旧节点）。"""
    now = time.time()
    removed = 0
    for nid in list(pool):
        r = pool[nid]
        if not r.get("last_ok") and (now - r.get("first_seen", now)) > stale_days * 86400:
            del pool[nid]
            removed += 1
    if len(pool) > max_size:
        never = [r for r in pool.values() if not r.get("last_ok")]
        never.sort(key=lambda r: r.get("last_seen", 0))
        for r in never[: len(pool) - max_size]:
            pool.pop(r["id"], None)
            removed += 1
    return removed


def select_candidates(pool: dict[str, dict], max_candidates: int) -> list[dict]:
    """挑选本轮要测试的节点（record 列表），优先保留历史可用节点。"""
    recs = list(pool.values())

    def rank(r):
        # 先测最近成功过的，再测新采集的，再测其它
        if r.get("last_ok"):
            return (0, -r["last_ok"])
        return (1, -r.get("first_seen", 0))

    recs.sort(key=rank)
    return recs[:max_candidates]


def fresh_purity(rec: dict, cache_hours: float) -> bool:
    p = rec.get("purity")
    if not p or not p.get("ts"):
        return False
    return (time.time() - p["ts"]) < cache_hours * 3600
