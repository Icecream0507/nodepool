"""生成 Clash / mihomo 订阅 yaml。"""
from __future__ import annotations

import time

import yaml

from .util import flag_emoji

TEST_URL = "http://www.gstatic.com/generate_204"


def tier_of(score: int, tiers: list) -> tuple[int, str] | None:
    """返回 (档位序号, 名称)；超出所有档位返回 None。"""
    for i, (lo, hi, label) in enumerate(tiers):
        if lo <= score < hi or (i == len(tiers) - 1 and score == hi):
            return i, label
    return None


def _pretty_name(rec: dict, label: str, used: set) -> str:
    p = rec["purity"]
    cc = (p.get("cc") or "").upper()
    flag = flag_emoji(cc)
    score = p.get("score")
    kind = "住宅" if p.get("residential") else ("机房" if p.get("broadcast") else "")
    lat = rec.get("latency_ms")
    parts = [flag, cc or "??", str(score), label]
    if kind:
        parts.append(kind)
    base = " ".join(parts)
    if lat:
        base += f" · {lat}ms"
    name = base
    n = 2
    while name in used:
        name = f"{base} #{n}"
        n += 1
    used.add(name)
    return name


def build_subscription(final: list[dict], cfg: dict) -> tuple[str, dict]:
    """final：通过筛选的 record 列表。返回 (yaml 文本, 统计)。"""
    tiers = cfg["purity"]["tiers"]
    g_auto = cfg["output"]["group_auto"]
    g_select = cfg["output"]["group_select"]

    # 按 (档位, 延迟) 排序
    def sort_key(r):
        t = tier_of(r["purity"]["score"], tiers)
        return (t[0] if t else 99, r.get("latency_ms") or 99999)

    final = sorted(final, key=sort_key)

    used: set = set()
    proxies = []
    tier_members: dict[str, list[str]] = {label: [] for _, _, label in tiers}
    stats = {label: 0 for _, _, label in tiers}
    for rec in final:
        t = tier_of(rec["purity"]["score"], tiers)
        if not t:
            continue
        label = t[1]
        name = _pretty_name(rec, label, used)
        pd = dict(rec["proxy"])
        pd["name"] = name
        proxies.append(pd)
        tier_members[label].append(name)
        stats[label] += 1

    all_names = [p["name"] for p in proxies]
    groups = [
        {"name": g_select, "type": "select",
         "proxies": [g_auto] + [lbl for _, _, lbl in tiers if tier_members[lbl]] + ["DIRECT"]},
        {"name": g_auto, "type": "url-test", "url": TEST_URL, "interval": 300,
         "tolerance": 50, "proxies": all_names or ["DIRECT"]},
    ]
    for _, _, lbl in tiers:
        if tier_members[lbl]:
            groups.append({"name": lbl, "type": "url-test", "url": TEST_URL,
                           "interval": 300, "proxies": tier_members[lbl]})

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": ["223.5.5.5", "119.29.29.29", "https://doh.pub/dns-query"],
            "fallback": ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": [
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            f"MATCH,{g_select}",
        ],
    }
    body = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    dist = " / ".join(f"{lbl}:{stats[lbl]}" for _, _, lbl in tiers)
    header = (f"# nodepool 自动生成于 {ts}\n"
              f"# 共 {len(proxies)} 个节点（{dist}）\n"
              f"# IPPure 系数越低越纯净；仅收录系数 <= {cfg['purity']['max_score']} 的节点\n")
    return header + body, {"total": len(proxies), "tiers": stats}
