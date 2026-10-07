"""生成 Clash / mihomo 订阅 yaml。"""
from __future__ import annotations

import copy
import time

import yaml

from .util import flag_emoji

TEST_URL = "https://www.gstatic.com/generate_204"

# Keep frequently blocked services ahead of GEOIP: a poisoned CN answer must
# never turn these domains into direct traffic. No extra GeoSite download needed.
PROXY_DOMAINS = (
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "google.com", "google.cn", "google.com.hk", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "googlevideo.com", "youtube.com", "youtu.be", "ytimg.com",
    "github.com", "githubusercontent.com", "githubassets.com", "github.io", "githubcopilot.com",
)


def build_dns_config(group_auto: str) -> dict:
    """Separate node bootstrap DNS from destination DNS to avoid a proxy loop."""
    domestic = ["https://223.5.5.5/dns-query", "https://223.6.6.6/dns-query"]
    return {
        "enable": True,
        "enhanced-mode": "fake-ip",
        "ipv6": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "proxy-server-nameserver": list(domestic),
        "direct-nameserver": list(domestic),
        "nameserver": [
            f"https://1.1.1.1/dns-query#{group_auto}",
            f"https://8.8.8.8/dns-query#{group_auto}",
        ],
        "nameserver-policy": {"+.cn": list(domestic)},
        # Explicitly avoid GeoIP DNS filtering, including in offline validation.
        "fallback-filter": {"geoip": False},
    }


def proxy_domain_rules(group_auto: str) -> list[str]:
    return [f"DOMAIN-SUFFIX,{domain},{group_auto}" for domain in PROXY_DOMAINS]


def _auto_layout(document: dict, cfg: dict) -> dict:
    """Route proxy traffic straight to one automatic group with direct node members."""
    document = copy.deepcopy(document)
    proxies = document.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("没有可输出的节点，拒绝生成空订阅")
    group_auto = cfg["output"]["group_auto"]
    names = []
    for proxy in proxies:
        if (not isinstance(proxy, dict) or not isinstance(proxy.get("name"), str)
                or not proxy["name"] or proxy["name"] in (group_auto, "DIRECT", "REJECT", "GLOBAL")):
            raise ValueError("节点名称无效或与自动组冲突")
        names.append(proxy["name"])
    if len(set(names)) != len(names):
        raise ValueError("节点名称重复")
    group = {"name": group_auto, "type": "url-test", "proxies": names,
             "url": cfg["connectivity"]["test_url"], "interval": 180,
             "tolerance": 50, "lazy": False}
    if cfg["connectivity"].get("expected_status") is not None:
        group["expected-status"] = cfg["connectivity"]["expected_status"]
    document["mode"] = "rule"
    document["proxy-groups"] = [group]
    document["dns"] = build_dns_config(group_auto)
    document["rules"] = [
        *proxy_domain_rules(group_auto),
        "DOMAIN-SUFFIX,cn,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        f"MATCH,{group_auto}",
    ]
    return document


def simplify_subscription(text: str, cfg: dict) -> str:
    """Migrate a generated subscription without changing node settings or identities."""
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("订阅必须是 YAML 对象")
    return yaml.safe_dump(_auto_layout(document, cfg), allow_unicode=True, sort_keys=False)


def tier_of(score: int | None, tiers: list) -> tuple[int, str] | None:
    """返回 (档位序号, 名称)；超出所有档位返回 None。"""
    if type(score) is not int or not 0 <= score <= 100:
        return None
    for i, (lo, hi, label) in enumerate(tiers):
        if lo <= score < hi or (i == len(tiers) - 1 and score == hi):
            return i, label
    return None


def _pretty_name(rec: dict, label: str, used: set) -> str:
    p = rec.get("purity") if isinstance(rec.get("purity"), dict) else {}
    cc = (p.get("cc") or "").upper()
    flag = flag_emoji(cc)
    score = p.get("score")
    kind = "住宅" if p.get("residential") else ("机房" if p.get("broadcast") else "")
    lat = rec.get("latency_ms")
    parts = [flag, cc or "??", str(score) if type(score) is int and 0 <= score <= 100 else "未评分", label]
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
    g_other = cfg["output"].get("group_other", "其他节点")

    # Stability and measured latency take priority over reference IP scores.
    def sort_key(r):
        tested = r.get("test_count", 0)
        rate = r.get("success_count", 0) / tested if tested > 0 else 0
        return (not r.get("stable", False), -rate, r.get("latency_ms") or 99999)

    final = sorted(final, key=sort_key)

    labels = [t[2] for t in tiers] + [g_other]
    used: set = {g_auto, "DIRECT", "REJECT", "GLOBAL"}
    proxies = []
    stats = {label: 0 for label in labels}
    for rec in final:
        purity = rec.get("purity") if isinstance(rec.get("purity"), dict) else {}
        t = tier_of(purity.get("score"), tiers)
        if not t and cfg["purity"].get("required", True):
            continue
        label = t[1] if t else g_other
        name = _pretty_name(rec, label, used)
        pd = dict(rec["proxy"])
        pd["name"] = name
        proxies.append(pd)
        stats[label] += 1

    config = _auto_layout({
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
    }, cfg)
    body = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    dist = " / ".join(f"{lbl}:{stats[lbl]}" for lbl in labels if stats[lbl])
    score_note = (f"IPPure 系数越低越纯净；仅收录系数 <= {cfg['purity']['max_score']} 的节点"
                  if cfg["purity"].get("required", True)
                  else "按连通性和稳定性筛选；IPPure 评分仅作参考，缺失或过期不影响入选")
    header = (f"# nodepool 自动生成于 {ts}\n"
              f"# 共 {len(proxies)} 个节点（{dist}）\n"
              f"# {score_note}\n")
    return header + body, {"total": len(proxies), "tiers": stats}
