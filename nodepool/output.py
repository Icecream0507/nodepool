"""生成 Clash / mihomo 订阅 yaml。"""
from __future__ import annotations

import copy
import json
import re
import time

import yaml

from .util import dump_yaml, flag_emoji

TEST_URL = "https://www.gstatic.com/generate_204"

# Keep frequently blocked services ahead of GEOIP: a poisoned CN answer must
# never turn these domains into direct traffic. No extra GeoSite download needed.
PROXY_DOMAINS = (
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "google.com", "google.cn", "google.com.hk", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "googlevideo.com", "youtube.com", "youtu.be", "ytimg.com",
    "github.com", "githubusercontent.com", "githubassets.com", "github.io", "githubcopilot.com",
)


def build_dns_config(group_select: str) -> dict:
    """Separate node bootstrap DNS from destination DNS to avoid a proxy loop."""
    domestic = ["https://223.5.5.5/dns-query", "https://223.6.6.6/dns-query"]
    return {
        "enable": True,
        "enhanced-mode": "fake-ip",
        "ipv6": False,
        "use-system-hosts": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "proxy-server-nameserver": list(domestic),
        "direct-nameserver": list(domestic),
        "nameserver": [
            f"https://1.1.1.1/dns-query#{group_select}",
            f"https://8.8.8.8/dns-query#{group_select}",
        ],
        # Clash.Meta <= v1.13 only accepts a single string here; a list fails the whole file.
        "nameserver-policy": {"+.cn": domestic[0]},
        # Explicitly avoid GeoIP DNS filtering, including in offline validation.
        "fallback-filter": {"geoip": False},
    }


def proxy_domain_rules(group_select: str) -> list[str]:
    return [f"DOMAIN-SUFFIX,{domain},{group_select}" for domain in PROXY_DOMAINS]


def _selection_layout(document: dict, cfg: dict) -> dict:
    """Default to automatic selection while keeping nodes directly selectable in rule mode."""
    document = copy.deepcopy(document)
    proxies = document.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("没有可输出的节点，拒绝生成空订阅")
    group_auto = cfg["output"]["group_auto"]
    group_select = cfg["output"]["group_select"]
    names = []
    for proxy in proxies:
        if (not isinstance(proxy, dict) or not isinstance(proxy.get("name"), str)
                or not proxy["name"] or proxy["name"] in (group_auto, group_select, "DIRECT", "REJECT", "GLOBAL")):
            raise ValueError("节点名称无效或与代理组冲突")
        names.append(proxy["name"])
    if len(set(names)) != len(names):
        raise ValueError("节点名称重复")
    group = {"name": group_auto, "type": "url-test", "proxies": names,
             "url": cfg["connectivity"]["test_url"], "interval": 180,
             "timeout": cfg["connectivity"]["timeout_ms"],
             "tolerance": 50, "lazy": False}
    if cfg["connectivity"].get("expected_status") is not None:
        group["expected-status"] = cfg["connectivity"]["expected_status"]
    document["mode"] = "rule"
    document["proxy-groups"] = [
        {"name": group_select, "type": "select", "proxies": [group_auto, *names]},
        group,
    ]
    document["dns"] = build_dns_config(group_select)
    document["rules"] = [
        *proxy_domain_rules(group_select),
        "DOMAIN-SUFFIX,cn,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        f"MATCH,{group_select}",
    ]
    return document


def client_compatible(proxy: dict, cfg: dict) -> bool:
    """One unknown proxy type makes older clients reject the whole subscription."""
    return proxy.get("type") not in cfg["output"]["exclude_types"]


def simplify_subscription(text: str, cfg: dict) -> str:
    """Migrate a generated subscription without changing node settings or identities."""
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("订阅必须是 YAML 对象")
    if isinstance(document.get("proxies"), list):
        document["proxies"] = [p for p in document["proxies"]
                               if not isinstance(p, dict) or client_compatible(p, cfg)]
    return dump_yaml(_selection_layout(document, cfg))


# Shadowrocket imports a Clash-style proxy list and ignores groups, DNS and
# rules. Mirror Sub-Store's Shadowrocket producer, the de facto reference.
_SHADOWROCKET_NO_TLS_KEY = {"trojan", "tuic", "hysteria", "hysteria2", "anytls"}


def _ws_early_data(opts: dict) -> None:
    """Shadowrocket expects Xray's `?ed=` path hint as explicit early-data fields."""
    path, sep, query = str(opts.get("path") or "/").partition("?")
    parts = [part for part in query.split("&") if part] if sep else []
    ed = [part[3:] for part in parts if part.startswith("ed=")]
    if not ed or not ed[-1].isdigit():
        return
    rest = [part for part in parts if not part.startswith("ed=")]
    opts["path"] = path + ("?" + "&".join(rest) if rest else "")
    if opts.get("v2ray-http-upgrade"):
        opts["v2ray-http-upgrade-fast-open"] = True
        opts.pop("early-data-header-name", None)
        opts.pop("max-early-data", None)
        return
    if opts.get("early-data-header-name") is None:
        opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
    if opts.get("max-early-data") is None:
        opts["max-early-data"] = int(ed[-1])


def _shadowrocket_proxy(proxy: dict) -> dict:
    p = copy.deepcopy(proxy)
    kind = p.get("type")
    if kind in ("vmess", "vless") and "sni" in p:
        # mihomo verified the node with servername; keep it when both exist.
        sni = p.pop("sni")
        p.setdefault("servername", sni)
    if kind == "hysteria" and "auth-str" not in p and "auth_str" in p:
        p["auth-str"] = p.pop("auth_str")
    if kind in ("tuic", "hysteria", "hysteria2"):
        if isinstance(p.get("alpn"), str):
            p["alpn"] = [p["alpn"]]
        if p.get("tfo") and not p.get("fast-open"):
            p["fast-open"] = p["tfo"]
    if p.get("network") == "ws":
        opts = p["ws-opts"] = dict(p.get("ws-opts") or {})
        opts["path"] = opts.get("path") or "/"
        _ws_early_data(opts)
    if kind in _SHADOWROCKET_NO_TLS_KEY or not isinstance(p.get("tls", False), bool):
        p.pop("tls", None)
    for opts in [p] + [v for k, v in p.items() if k.endswith("-opts") and isinstance(v, dict)]:
        for key in [k for k, v in opts.items() if v is None or str(k).startswith("_")]:
            del opts[key]
    # mihomo, which verified these nodes, only authenticates when it has a
    # username (HTTP: both fields); don't let Shadowrocket send half a credential.
    if kind in ("http", "socks5") and not (p.get("username") and (kind == "socks5" or p.get("password"))):
        p.pop("username", None)
        p.pop("password", None)
    return p


def build_shadowrocket(text: str) -> str:
    """Shadowrocket copy of a finished subscription: same nodes, proxies only."""
    document = yaml.safe_load(text)
    proxies = document.get("proxies") if isinstance(document, dict) else None
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("没有可输出的节点，拒绝生成空 Shadowrocket 订阅")
    # Same shape as Sub-Store: one JSON flow mapping per YAML list item.
    lines = ["proxies:"]
    for proxy in proxies:
        if not isinstance(proxy, dict):
            raise ValueError("节点格式无效")
        lines.append("  - " + json.dumps(_shadowrocket_proxy(proxy), ensure_ascii=False))
    return "\n".join(lines) + "\n"


def build_shadowrocket_conf(cfg: dict) -> str:
    """Shadowrocket drops a subscription's groups, so auto-select ships as a config."""
    g_select, g_auto = cfg["output"]["group_select"], cfg["output"]["group_auto"]
    if any(c in name for name in (g_select, g_auto) for c in ",=\n"):
        raise ValueError("代理组名称不能包含逗号、等号或换行")
    # _pretty_name puts a tier label in every node name; match on those so the
    # group picks up this subscription's nodes without listing them.
    labels = [t[2] for t in cfg["purity"]["tiers"]] + [cfg["output"].get("group_other", "其他节点")]
    nodes = "|".join(re.escape(label) for label in labels)
    timeout = max(1, cfg["connectivity"]["timeout_ms"] // 1000)
    return "\n".join([
        "# nodepool 自动生成：节点来自同一 gist 的 shadowrocket.yaml 订阅，这里只提供分组和分流规则。",
        f"# {g_select} 默认走 {g_auto}；选 PROXY 则使用首页点选的节点。",
        "[General]",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.1, localhost, *.local, captive.apple.com",
        "dns-server = 223.5.5.5, 119.29.29.29",
        "fallback-dns-server = system",
        # Nodes are tested over IPv4 only, as in the Clash file.
        "ipv6 = false",
        "prefer-ipv6 = false",
        "private-ip-answer = true",
        "hijack-dns = *:53",
        # Most nodes are HTTP proxies without UDP: make QUIC fall back to TCP.
        "udp-policy-not-supported-behaviour = REJECT",
        "block-quic = all-proxy",
        "",
        "[Proxy Group]",
        f"{g_select} = select,{g_auto},PROXY,select=0",
        # 300s instead of Clash's 180s: gentler on phone battery and data.
        f"{g_auto} = url-test,url={cfg['connectivity']['test_url']},interval=300,tolerance=50,"
        f"timeout={timeout},select=0,policy-regex-filter={nodes}",
        "",
        "[Rule]",
        *proxy_domain_rules(g_select),
        "DOMAIN-SUFFIX,cn,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        f"FINAL,{g_select}",
        "",
    ])


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
    g_select = cfg["output"]["group_select"]
    g_other = cfg["output"].get("group_other", "其他节点")

    # Stability and measured latency take priority over reference IP scores.
    def sort_key(r):
        tested = r.get("test_count", 0)
        rate = r.get("success_count", 0) / tested if tested > 0 else 0
        return (not r.get("stable", False), -rate, r.get("latency_ms") or 99999)

    final = sorted(final, key=sort_key)

    labels = [t[2] for t in tiers] + [g_other]
    used: set = {g_auto, g_select, "DIRECT", "REJECT", "GLOBAL"}
    proxies = []
    stats = {label: 0 for label in labels}
    for rec in final:
        if not client_compatible(rec["proxy"], cfg):
            continue
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

    config = _selection_layout({
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
    }, cfg)
    body = dump_yaml(config)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    dist = " / ".join(f"{lbl}:{stats[lbl]}" for lbl in labels if stats[lbl])
    score_note = (f"IPPure 系数越低越纯净；仅收录系数 <= {cfg['purity']['max_score']} 的节点"
                  if cfg["purity"].get("required", True)
                  else "按连通性和稳定性筛选；IPPure 评分仅作参考，缺失或过期不影响入选")
    header = (f"# nodepool 自动生成于 {ts}\n"
              f"# 共 {len(proxies)} 个节点（{dist}）\n"
              f"# {score_note}\n")
    return header + body, {"total": len(proxies), "tiers": stats}
