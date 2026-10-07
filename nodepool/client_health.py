"""Persist client-side connectivity evidence separately from pool history."""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import re
import statistics
import time
from urllib.parse import unquote

import yaml

from .pool import connectivity_policy
from .util import atomic_write, dump_yaml, node_id

_ID = re.compile(r"[0-9a-f]{16}\Z")
_BUILTINS = {"DIRECT", "REJECT"}


def _timestamp(value, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite nonnegative timestamp")
    return float(value)


def validate_report(report: dict, *, now: float | None = None) -> dict:
    """Reject malformed reports before any subscription can be changed."""
    current = _timestamp(time.time() if now is None else now, "now")
    if not isinstance(report, dict) or set(report) != {"schema", "required", "tested_at", "policy", "nodes"}:
        raise ValueError("client health report has invalid fields")
    if type(report["schema"]) is not int or report["schema"] != 1:
        raise ValueError("unsupported client health report schema")
    if type(report["required"]) is not bool:
        raise ValueError("client health required must be boolean")
    tested_at = _timestamp(report["tested_at"], "tested_at")
    if tested_at > current + 300:
        raise ValueError("client health timestamp is in the future")
    if not isinstance(report["policy"], str) or not report["policy"].strip():
        raise ValueError("client health policy must be a nonempty string")
    if not isinstance(report["nodes"], dict):
        raise ValueError("client health nodes must be an object")
    for nid, result in report["nodes"].items():
        if not isinstance(nid, str) or _ID.fullmatch(nid) is None:
            raise ValueError("client health node id must be a canonical 16 digit hex id")
        if not isinstance(result, dict) or set(result) != {"ok", "latency_ms"}:
            raise ValueError("client health node result has invalid fields")
        if type(result["ok"]) is not bool:
            raise ValueError("client health node ok must be boolean")
        latency = result["latency_ms"]
        if latency is not None and (type(latency) is not int or latency <= 0):
            raise ValueError("client health latency must be a positive integer or null")
    return report


def load_report(path: Path, *, now: float | None = None) -> dict:
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read client health report") from exc
    return validate_report(report, now=now)


def save_report(path: Path, report: dict, *, now: float | None = None) -> None:
    validate_report(report, now=now)
    atomic_write(Path(path), json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))


def build_report(results: dict, proxies: list[dict], connectivity: dict,
                 required: bool = True, *, now: float | None = None) -> dict:
    """Bind complete, positive delay results to their actual connection settings."""
    if not isinstance(results, dict) or not isinstance(proxies, list):
        raise ValueError("client results and proxies have invalid types")
    rounds, minimum = connectivity.get("rounds"), connectivity.get("min_pass")
    if type(rounds) is not int or type(minimum) is not int or not 1 <= minimum <= rounds:
        raise ValueError("client connectivity requires valid rounds and min_pass")
    report = {"schema": 1, "required": required,
              "tested_at": time.time() if now is None else now,
              "policy": connectivity_policy(connectivity), "nodes": {}}
    names = set()
    for proxy in proxies:
        if not isinstance(proxy, dict) or not isinstance(proxy.get("name"), str) or not proxy["name"]:
            raise ValueError("client proxy must have a name")
        nid = node_id(proxy)
        if proxy["name"] in names or nid in report["nodes"]:
            raise ValueError("client proxies must have unique names and connections")
        names.add(proxy["name"])
        delays = results.get(proxy["name"], [])
        if not isinstance(delays, list):
            raise ValueError("client delay results must be lists")
        passed = [value for value in delays if type(value) is int and value > 0]
        ok = len(delays) == rounds and len(passed) >= minimum
        report["nodes"][nid] = {"ok": ok, "latency_ms": max(1, int(statistics.median(passed))) if ok else None}
    return validate_report(report, now=now)


def _allowed(report: dict | None, policy: str, now: float | None, max_age_hours: float) -> set[str] | None:
    if report is None:
        return None
    current = time.time() if now is None else now
    validate_report(report, now=current)
    if not report["required"]:
        return None
    if type(max_age_hours) not in (int, float) or not math.isfinite(max_age_hours) or max_age_hours <= 0:
        raise ValueError("client health maximum age must be positive and finite")
    if report["policy"] != policy or current - report["tested_at"] >= max_age_hours * 3600:
        return set()
    return {nid for nid, result in report["nodes"].items() if result["ok"]}


def filter_records(records: list[dict] | dict[str, dict], report: dict | None,
                   policy: str, *, now: float | None = None, max_age_hours: float = 24):
    """Select verified connections without changing pool records or their history."""
    allowed = _allowed(report, policy, now, max_age_hours)
    if allowed is None:
        return records
    if isinstance(records, dict):
        return {nid: rec for nid, rec in records.items() if node_id(rec["proxy"]) in allowed}
    return [rec for rec in records if node_id(rec["proxy"]) in allowed]


def _repair_groups(groups: list, proxy_names: set[str]) -> list[dict]:
    remaining = copy.deepcopy(groups)
    seen = set(proxy_names) | _BUILTINS
    for group in remaining:
        if (not isinstance(group, dict) or not isinstance(group.get("name"), str)
                or not group["name"] or group["name"] in seen
                or not isinstance(group.get("type"), str)
                or not isinstance(group.get("proxies"), list)
                or any(not isinstance(name, str) for name in group["proxies"])):
            raise ValueError("subscription has invalid or ambiguous proxy groups")
        seen.add(group["name"])
    while True:
        valid = proxy_names | _BUILTINS | {group["name"] for group in remaining}
        next_groups = []
        for group in remaining:
            group["proxies"] = [name for name in group["proxies"] if name in valid]
            if not group["proxies"]:
                if group["type"] != "select":
                    continue
                group["proxies"] = ["DIRECT"]
            next_groups.append(group)
        if len(next_groups) == len(remaining):
            break
        remaining = next_groups
    by_name = {group["name"]: group for group in remaining}
    visited, visiting = set(), set()

    def visit(name):
        if name in visiting:
            raise ValueError("subscription has cyclic proxy group references")
        if name not in by_name or name in visited:
            return
        visiting.add(name)
        for child in by_name[name]["proxies"]:
            visit(child)
        visiting.remove(name)
        visited.add(name)

    for name in by_name:
        visit(name)
    return remaining


def _repair_dns(value, removed: set[str], fallback: str):
    if isinstance(value, dict):
        return {key: _repair_dns(item, removed, fallback) for key, item in value.items()}
    if isinstance(value, list):
        return [_repair_dns(item, removed, fallback) for item in value]
    if isinstance(value, str) and "#" in value:
        address, fragment = value.split("#", 1)
        selected, separator, options = fragment.partition("&")
        if unquote(selected) in removed:
            return address + "#" + fallback + separator + options
    return value


def _repair_rules(value, removed: set[str], fallback: str):
    if isinstance(value, dict):
        return {key: _repair_rules(item, removed, fallback) for key, item in value.items()}
    if isinstance(value, list):
        return [_repair_rules(item, removed, fallback) for item in value]
    if isinstance(value, str):
        pieces = value.split(",")
        index = -2 if pieces[-1].strip() == "no-resolve" and len(pieces) > 1 else -1
        if pieces[index].strip() in removed:
            pieces[index] = fallback
            return ",".join(pieces)
    return value


def filter_subscription(text: str, report: dict | None, policy: str, *,
                        now: float | None = None, max_age_hours: float = 24) -> str:
    """Filter a subscription and repair references; reject an empty publication."""
    allowed = _allowed(report, policy, now, max_age_hours)
    if allowed is None:
        return text
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError("subscription YAML is invalid") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list):
        raise ValueError("subscription has no proxy list")
    originals = doc["proxies"]
    names = set()
    for proxy in originals:
        if (not isinstance(proxy, dict) or not isinstance(proxy.get("name"), str)
                or not proxy["name"] or proxy["name"] in names | _BUILTINS):
            raise ValueError("subscription has invalid or duplicate proxy names")
        names.add(proxy["name"])
    kept = [proxy for proxy in originals if node_id(proxy) in allowed]
    if not kept:
        raise ValueError("no client-verified nodes remain; preserve the existing subscription")
    groups = doc.get("proxy-groups", [])
    if not isinstance(groups, list):
        raise ValueError("subscription proxy groups must be a list")
    proxy_names = {proxy["name"] for proxy in kept}
    repaired = _repair_groups(groups, proxy_names)
    original_group_names = {group["name"] for group in groups}
    if original_group_names & names:
        raise ValueError("subscription proxy and group names overlap")
    remaining_names = proxy_names | {group["name"] for group in repaired}
    removed = (names | original_group_names) - remaining_names
    fallback = next((group["name"] for group in repaired if group["type"] == "select"),
                    repaired[0]["name"] if repaired else kept[0]["name"])
    doc["proxies"], doc["proxy-groups"] = kept, repaired
    if "dns" in doc:
        doc["dns"] = _repair_dns(doc["dns"], removed, fallback)
    for key in ("rules", "sub-rules"):
        if key in doc:
            doc[key] = _repair_rules(doc[key], removed, fallback)
    return dump_yaml(doc)
