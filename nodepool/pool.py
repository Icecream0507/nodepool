"""持久化节点池：轮转探索、稳定节点晋升、失败冷却和历史迁移。"""
from __future__ import annotations

import json
import hashlib
import math
import time
from pathlib import Path

from .util import atomic_write, log, node_id, node_key


def connectivity_policy(cfg: dict) -> str:
    """Identify the evidence required for publication without deleting old tests."""
    policy = {"schema": 2, **{key: cfg.get(key) for key in (
        "test_url", "verification_url", "timeout_ms", "rounds", "min_pass")},
        "expected_status": cfg.get("expected_status", 204)}
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def tested_with_policy(rec: dict, policy: str) -> bool:
    return rec.get("last_test_policy") == policy


def _migrate(data: dict) -> dict[str, dict]:
    if not isinstance(data, dict):
        raise ValueError("节点池必须是对象")
    out = {}
    for old in data.values():
        if not isinstance(old, dict) or not isinstance(old.get("proxy"), dict):
            raise ValueError("节点池记录缺少 proxy")
        r = dict(old)
        nid = node_id(r["proxy"])
        r.update(id=nid, key=node_key(r["proxy"]))
        r.setdefault("last_test", r.get("last_ok", 0))
        r.setdefault("test_count", 1 if r.get("last_ok") else 0)
        r.setdefault("success_count", 1 if r.get("last_ok") else 0)
        r.setdefault("success_streak", 0)
        r.setdefault("stable", False)
        r.setdefault("stable_since", 0)
        r.setdefault("retired_until", 0)
        r.setdefault("history", [])
        previous = out.get(nid)
        if not previous:
            out[nid] = r
            continue
        latest, older = (r, previous) if r.get("last_test", 0) > previous.get("last_test", 0) else (previous, r)
        # Renamed legacy records can share one connection fingerprint. Keep
        # the newest health state while preserving the earned stable identity.
        if older.get("stable"):
            latest["stable"] = True
        since = [v for v in (latest.get("stable_since", 0), older.get("stable_since", 0)) if v > 0]
        if since:
            latest["stable_since"] = min(since)
        out[nid] = latest
    return out


def load(path: Path) -> dict[str, dict]:
    backup = path.with_suffix(".json.bak")
    if not path.exists() and not backup.exists():
        return {}
    for candidate in (path, backup):
        if not candidate.exists():
            continue
        try:
            result = _migrate(json.loads(candidate.read_text(encoding="utf-8")))
            if candidate == backup:
                log.warning("节点池主文件损坏，已从备份恢复")
            return result
        except (OSError, ValueError, TypeError, KeyError) as exc:
            log.warning("读取节点池 %s 失败：%s", candidate.name, exc)
    raise RuntimeError("节点池及备份均无法读取，停止更新以保护原有数据")


def save(path: Path, pool: dict[str, dict]) -> None:
    if path.exists():
        previous = path.read_text(encoding="utf-8")
        try:
            _migrate(json.loads(previous))
        except (ValueError, TypeError, KeyError):
            pass
        else:
            atomic_write(path.with_suffix(".json.bak"), previous)
    atomic_write(path, json.dumps(pool, ensure_ascii=False, indent=1))


def merge_collected(pool: dict[str, dict], nodes: list[dict]) -> int:
    now = int(time.time())
    added = 0
    for raw in nodes:
        p = {k: v for k, v in raw.items() if not k.startswith("_")}
        src = raw.get("_source", "")
        nid = node_id(p)
        if nid in pool:
            pool[nid]["last_seen"] = now
            pool[nid]["proxy"] = p
            if src:
                pool[nid]["source"] = src
        else:
            pool[nid] = {
                "id": nid, "key": node_key(p), "proxy": p, "source": src,
                "first_seen": now, "last_seen": now, "last_ok": 0,
                "last_test": 0, "test_count": 0, "success_count": 0,
                "success_streak": 0, "fail_streak": 0,
                "stable": False, "stable_since": 0, "retired_until": 0,
                "history": [], "latency_ms": None, "purity": None,
            }
            added += 1
    return added


def purity_from_api(data: dict) -> dict | None:
    if not isinstance(data, dict):
        return None
    raw = data.get("fraudScore")
    try:
        if isinstance(raw, bool) or raw is None or float(raw) != int(raw):
            return None
        score = int(raw)
        if not 0 <= score <= 100:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    try:
        asn = int(data.get("asn"))
    except (TypeError, ValueError):
        asn = None
    return {
        "score": score, "residential": data.get("isResidential") is True,
        "broadcast": data.get("isBroadcast") is True, "asn": asn,
        "org": data.get("asOrganization"), "cc": data.get("countryCode"),
        "country": data.get("country"), "ip": data.get("ip"), "ts": int(time.time()),
    }


def record_test(pool: dict[str, dict], nid: str, alive: bool,
                latency_ms: int | None, history_size: int = 20, *,
                policy: str | None = None) -> None:
    rec = pool.get(nid)
    if not rec:
        return
    now = int(time.time())
    rec["last_test"] = now
    rec["last_test_policy"] = policy
    rec["test_count"] = rec.get("test_count", 0) + 1
    rec["success_count"] = rec.get("success_count", 0) + int(alive)
    rec["success_streak"] = rec.get("success_streak", 0) + 1 if alive else 0
    if alive:
        rec.update(fail_streak=0, last_ok=now, latency_ms=latency_ms, retired_until=0)
    else:
        rec["fail_streak"] = rec.get("fail_streak", 0) + 1
    entry = {"ts": now, "ok": alive}
    if policy is not None:
        entry["policy"] = policy
    rec["history"] = (rec.get("history", []) + [entry])[-history_size:]


def record_purity(pool: dict[str, dict], nid: str, data: dict) -> bool:
    rec = pool.get(nid)
    purity = purity_from_api(data)
    if rec is None or purity is None:
        return False
    rec["purity"] = purity
    return True


def fresh_purity(rec: dict, cache_hours: float) -> bool:
    p = rec.get("purity")
    if not isinstance(p, dict) or not p.get("ts"):
        return False
    score = p.get("score")
    return (type(score) is int and 0 <= score <= 100
            and 0 <= time.time() - p["ts"] < cache_hours * 3600)


def promote_stable(pool: dict[str, dict], cfg: dict, cache_hours: float,
                   max_score: int, *, policy: str | None = None) -> int:
    promoted = 0
    for r in pool.values():
        if r.get("stable"):
            continue
        history = r.get("history", [])
        streak = r.get("success_streak", 0)
        if policy is not None:
            if not tested_with_policy(r, policy):
                continue
            # A new policy starts its own qualification streak. Earlier
            # evidence stays in history, but cannot satisfy stricter tests.
            streak = 0
            for item in reversed(history):
                if item.get("policy") != policy or not item.get("ok"):
                    break
                streak += 1
            history = [item for item in history if item.get("policy") == policy]
        if streak < cfg["stable_min_passes"]:
            continue
        rate = sum(h["ok"] for h in history) / len(history) if history else 0
        if rate >= cfg["stable_min_rate"] and fresh_purity(r, cache_hours) and r["purity"]["score"] <= max_score:
            r.update(stable=True, stable_since=int(time.time()))
            promoted += 1
    return promoted


def prune(pool: dict[str, dict], max_fail: int, *, stable_max_fail: int = 12,
          stable_grace_days: float = 7, cooldown_hours: float = 24) -> int:
    """普通节点连续失败后冷却；稳定节点同时达到失败次数和宽限期才冷却。"""
    now = time.time()
    retired = 0
    for r in pool.values():
        if r.get("retired_until", 0) > now:
            continue
        if r.get("retired_at", 0) >= r.get("last_test", 0):
            continue
        limit = stable_max_fail if r.get("stable") else max_fail
        if r.get("fail_streak", 0) < limit:
            continue
        if r.get("stable") and now - r.get("last_ok", now) < stable_grace_days * 86400:
            continue
        r["retired_until"] = int(now + cooldown_hours * 3600)
        r["retired_at"] = int(now)
        retired += 1
    return retired


def enforce_limits(pool: dict[str, dict], max_size: int, stale_days: float) -> int:
    if max_size < 1 or stale_days <= 0:
        raise ValueError("节点池容量和陈旧天数必须为正")
    now = time.time()
    drop = [nid for nid, r in pool.items() if not r.get("last_ok")
            and now - r.get("last_seen", now) > stale_days * 86400]
    for nid in drop:
        del pool[nid]
    overflow = max(0, len(pool) - max_size)
    ordered = sorted(pool.values(), key=lambda r: (
        bool(r.get("stable")), bool(r.get("last_ok")),
        r.get("last_ok", 0), r.get("last_seen", 0)))
    for r in ordered[:overflow]:
        del pool[r["id"]]
    return len(drop) + overflow


def select_candidates(pool: dict[str, dict], max_candidates: int,
                      exploration_ratio: float = 0.25, max_score: int = 40) -> list[dict]:
    if max_candidates < 1 or not 0 < exploration_ratio < 1:
        raise ValueError("候选上限必须为正，探索比例必须在 0 和 1 之间")
    now = time.time()
    eligible = [r for r in pool.values() if r.get("retired_until", 0) <= now]
    def proven(r):
        p = r.get("purity") or {}
        score = p.get("score")
        return bool(r.get("last_ok")) and (score is None or (type(score) is int and 0 <= score <= max_score))
    known = [r for r in eligible if proven(r)]
    explore = [r for r in eligible if not proven(r)]
    known.sort(key=lambda r: (r.get("last_test", 0), not r.get("stable", False), r["id"]))
    explore.sort(key=lambda r: (r.get("last_test", 0), -r.get("first_seen", 0), r["id"]))
    quota = min(len(explore), max(1, math.ceil(max_candidates * exploration_ratio)))
    if max_candidates == 1 and known:
        return sorted(eligible, key=lambda r: (r.get("last_test", 0), r["id"]))[:1]
    selected = known[:max_candidates - quota] + explore[:quota]
    seen = {r["id"] for r in selected}
    rest = [r for r in known + explore if r["id"] not in seen]
    return selected + rest[:max_candidates - len(selected)]
