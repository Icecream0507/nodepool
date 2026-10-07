"""配置加载与运行前校验，兼容尚未添加稳定池参数的旧配置。"""
from __future__ import annotations

import copy
import math
from pathlib import Path
from urllib.parse import urlparse

import yaml

DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULT_VERIFICATION_URL = "https://cp.cloudflare.com/generate_204"
LEGACY_TEST_URL = "http://www.gstatic.com/generate_204"

DEFAULTS = {
    "pool": {"stable_min_passes": 5, "stable_min_rate": 0.8, "history_size": 20,
             "stable_max_fail": 12, "stable_grace_days": 7, "cooldown_hours": 24,
             "exploration_ratio": 0.25},
    "output": {"group_stable": "🛡️ 稳定节点", "max_test_age_hours": 12},
    "purity": {"batch_size": 16, "max_seconds": 420},
    "search": {"max_seconds": 420},
    "publish": {"pool_filename": "stable-pool.json"},
}


def load_config(path: Path) -> dict:
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except yaml.YAMLError as exc:
        raise ValueError("配置 YAML 语法错误") from exc
    if not isinstance(cfg, dict):
        raise ValueError("配置必须是 YAML 对象")
    for section in ("search", "collect", "connectivity", "purity", "pool", "mihomo", "output", "publish"):
        if not isinstance(cfg.get(section), dict):
            raise ValueError(f"配置缺少 {section} 对象")
        for key, value in DEFAULTS.get(section, {}).items():
            cfg[section].setdefault(key, copy.deepcopy(value))
    # Upgrade the old built-in probe, while preserving a user's custom URL and
    # its previous status-code behavior unless they explicitly opt in.
    connectivity = cfg["connectivity"]
    if connectivity.get("test_url") in (LEGACY_TEST_URL, DEFAULT_TEST_URL):
        connectivity["test_url"] = DEFAULT_TEST_URL
        connectivity.setdefault("verification_url", DEFAULT_VERIFICATION_URL)
        connectivity.setdefault("expected_status", 204)
    else:
        connectivity.setdefault("verification_url", None)
        connectivity.setdefault("expected_status", None)
    validate_config(cfg)
    return cfg


def validate_config(cfg: dict) -> None:
    def number(section, key, lo, hi=None, integer=False):
        value = cfg[section].get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{section}.{key} 必须是有限数值")
        if value < lo or (hi is not None and value > hi) or (integer and int(value) != value):
            raise ValueError(f"{section}.{key} 超出合法范围")
    for section, keys in {
        "search": ("pages",), "collect": ("min_nodes_per_gist", "max_candidates"),
        "connectivity": ("timeout_ms", "rounds", "min_pass", "concurrency"),
        "purity": ("concurrency", "request_timeout", "batch_size"),
        "pool": ("max_fail", "max_size", "stable_min_passes", "history_size", "stable_max_fail"),
        "mihomo": ("startup_timeout",),
    }.items():
        for key in keys:
            number(section, key, 1, integer=True)
    for section, key in (("purity", "cache_hours"), ("pool", "stale_days"),
                         ("pool", "stable_grace_days"), ("pool", "cooldown_hours"),
                         ("output", "max_test_age_hours"), ("search", "max_seconds"), ("purity", "max_seconds")):
        number(section, key, 0.001)
    number("purity", "max_score", 0, 100, integer=True)
    number("purity", "stagger", 0)
    number("search", "page_delay", 0)
    number("pool", "stable_min_rate", 0.001, 1)
    number("pool", "exploration_ratio", 0.001, 0.999)
    number("mihomo", "base_listen_port", 1024, 65535, integer=True)
    if cfg["mihomo"]["base_listen_port"] + cfg["purity"]["batch_size"] - 1 > 65535:
        raise ValueError("纯净度监听端口范围超出 65535")
    if cfg["connectivity"]["min_pass"] > cfg["connectivity"]["rounds"]:
        raise ValueError("connectivity.min_pass 不能超过 rounds")
    number("connectivity", "timeout_ms", 1, 32767, integer=True)
    cc = cfg["connectivity"]
    if cc.get("expected_status") is not None:
        number("connectivity", "expected_status", 100, 599, integer=True)
    verification = cc.get("verification_url")
    if verification is not None and not isinstance(verification, str):
        raise ValueError("connectivity.verification_url 必须是 HTTP(S) URL 或 null")
    if verification:
        u = urlparse(verification)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("connectivity.verification_url 必须是 HTTP(S) URL")
        if verification == cc["test_url"]:
            raise ValueError("连通性两个测试目标必须不同")
        # Round-robin probes must require a success from both targets. A node
        # that can reach only one endpoint must never pass a full test.
        if cc["rounds"] < 2 or cc["min_pass"] <= (cc["rounds"] + 1) // 2:
            raise ValueError("多目标检测的 min_pass 必须超过单一目标的最大检测轮数")
    if cfg["pool"]["history_size"] < cfg["pool"]["stable_min_passes"]:
        raise ValueError("history_size 不能小于 stable_min_passes")
    if cfg["pool"]["stable_max_fail"] < cfg["pool"]["max_fail"]:
        raise ValueError("稳定节点失败容忍次数不能小于普通节点")
    for section, key in (("connectivity", "test_url"), ("purity", "api")):
        u = urlparse(str(cfg[section].get(key, "")))
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"{section}.{key} 必须是 HTTP(S) URL")
    for section, key in (("search", "query"), ("output", "file"), ("output", "group_auto"),
                         ("output", "group_select"), ("output", "group_stable"),
                         ("publish", "gist_filename"), ("publish", "gist_description"),
                         ("publish", "pool_filename"),
                         ("mihomo", "secret")):
        if not isinstance(cfg[section].get(key), str) or not cfg[section][key].strip():
            raise ValueError(f"{section}.{key} 不能为空")
    if type(cfg["publish"].get("enabled")) is not bool:
        raise ValueError("publish.enabled 必须为布尔值")
    if cfg["publish"]["pool_filename"] == cfg["publish"]["gist_filename"]:
        raise ValueError("稳定池备份文件名不能与订阅文件相同")
    tiers = cfg["purity"].get("tiers")
    if not isinstance(tiers, list) or not tiers:
        raise ValueError("purity.tiers 不能为空")
    previous = 0
    labels = [cfg["output"][k] for k in ("group_auto", "group_select", "group_stable")]
    for tier in tiers:
        if not isinstance(tier, list) or len(tier) != 3:
            raise ValueError("每个纯净度档位必须为 [下限, 上限, 名称]")
        lo, hi, label = tier
        if type(lo) is not int or type(hi) is not int or lo != previous or not lo < hi <= 100:
            raise ValueError("纯净度档位必须从 0 起连续覆盖且不重叠")
        if not isinstance(label, str) or not label.strip() or label in labels or label in ("DIRECT", "REJECT", "GLOBAL"):
            raise ValueError("代理组名称为空、重复或使用保留名称")
        labels.append(label)
        previous = hi
    if len(set(labels)) != len(labels) or any(n in ("DIRECT", "REJECT", "GLOBAL") for n in labels):
        raise ValueError("代理组名称重复或使用保留名称")
    if previous < cfg["purity"]["max_score"]:
        raise ValueError("purity.tiers 必须覆盖 max_score")
    controller = urlparse("http://" + str(cfg["mihomo"].get("controller", "")))
    if controller.hostname not in ("127.0.0.1", "localhost", "::1") or not controller.port:
        raise ValueError("mihomo.controller 必须是本地回环地址和端口")
