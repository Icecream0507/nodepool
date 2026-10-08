#!/usr/bin/env python3
"""在使用订阅的本机复测候选，并把严格通过的节点发布到固定订阅。"""
from __future__ import annotations

import argparse
import copy
import json
import socket
import sys
from pathlib import Path

import yaml

from nodepool import client_health, mihomo, output, pool, publish
from nodepool.config import load_config
from nodepool.util import atomic_write, log, make_session, run_lock

ROOT = Path(__file__).resolve().parent


def _complete_pass(delays, expected: int) -> bool:
    return (isinstance(delays, list) and len(delays) == expected
            and all(type(delay) is int and delay > 0 for delay in delays))


def verify_document(text: str, exe: Path, cfg: dict) -> tuple[str | None, dict]:
    text = output.simplify_subscription(text, cfg)
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or not isinstance(document.get("proxies"), list) or not document["proxies"]:
        raise ValueError("候选文件缺少节点")
    proxies = [{**p, "name": pool.node_id(p)} for p in document["proxies"]]
    if len({p["name"] for p in proxies}) != len(proxies):
        raise ValueError("候选包含重复连接参数")
    local_cfg = copy.deepcopy(cfg)
    local_cfg["connectivity"]["concurrency"] = min(8, cfg["connectivity"]["concurrency"])
    mc = local_cfg["mihomo"]
    # Separate from the live client and any update.py core.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        mc["controller"] = f"127.0.0.1:{sock.getsockname()[1]}"
    valid = mihomo.prune_invalid(exe, proxies, mc["controller"], mc["secret"], mc["startup_timeout"])
    results = {p["name"]: [None] * cfg["connectivity"]["rounds"] for p in proxies}
    results.update(mihomo.test_connectivity(exe, valid, local_cfg))
    # A local publishing check is deliberately stricter than exploration: all
    # four requests, two real service pages and a second full pass must succeed.
    eligible = [p for p in valid if _complete_pass(results.get(p["name"]), cfg["connectivity"]["rounds"])]
    log.info("本机首轮严格通过 %d/%d；继续验证 GitHub、ChatGPT 和第二轮连接", len(eligible), len(proxies))
    if eligible:
        web_cfg = copy.deepcopy(local_cfg)
        web_cfg["connectivity"].update(test_url="https://github.com/robots.txt",
                                       verification_url="https://chatgpt.com/cdn-cgi/trace",
                                       expected_status=200, rounds=2, min_pass=2)
        web = mihomo.test_connectivity(exe, eligible, web_cfg)
        eligible = [p for p in eligible if _complete_pass(web.get(p["name"]), 2)]
        confirmation = mihomo.test_connectivity(exe, eligible, local_cfg)
        approved = {p["name"] for p in eligible
                    if _complete_pass(confirmation.get(p["name"]), cfg["connectivity"]["rounds"])}
        for name in results:
            if name not in approved:
                results[name] = [None] * cfg["connectivity"]["rounds"]
            else:
                results[name] = confirmation[name]
    else:
        results = {name: [None] * cfg["connectivity"]["rounds"] for name in results}
    report = client_health.build_report(results, proxies, cfg["connectivity"], required=True)
    try:
        filtered = client_health.filter_subscription(text, report, pool.connectivity_policy(cfg["connectivity"]),
                                                     max_age_hours=cfg["publish"]["client_health_max_age_hours"])
    except ValueError:
        if any(r["ok"] for r in report["nodes"].values()):
            raise
        return None, report
    mihomo.validate_subscription(exe, filtered, mc["startup_timeout"])
    return filtered, report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    ap.add_argument("--input", type=Path, help="复测本地候选 YAML；默认读取远端候选")
    ap.add_argument("--core", type=Path, help="使用客户端相同的 mihomo 内核")
    ap.add_argument("--proxy", default=None, help="仅用于读取/发布 Gist，节点测试始终独立直连")
    ap.add_argument("--no-publish", action="store_true")
    args = ap.parse_args()
    cfg = load_config(Path(args.config))
    token = publish.load_token(ROOT)
    if not args.no_publish and not token:
        ap.error("发布需要配置 GITHUB_TOKEN；也可使用 --no-publish")
    with run_lock(ROOT / "data" / "update.lock"), make_session(args.proxy if args.proxy is not None else cfg["proxy"]) as session:
        if args.input:
            source = args.input.read_text(encoding="utf-8-sig")
        else:
            if not token:
                ap.error("读取远端需要 token；本地检测使用 --input")
            source = publish.read_remote_file(ROOT, session, token, cfg, cfg["publish"]["candidate_filename"])
            if source is None:
                source = publish.read_remote_file(ROOT, session, token, cfg, cfg["publish"]["gist_filename"])
            if source is None:
                raise RuntimeError("远端没有候选或订阅文件")
        exe = args.core.resolve() if args.core else mihomo.ensure_binary(ROOT, session, cfg["mihomo"]["version"])
        filtered, report = verify_document(source, exe, cfg)
        atomic_write(ROOT / "data" / "local-verification.json", json.dumps(report, ensure_ascii=False, indent=2))
        if filtered is None:
            log.error("本机没有严格合格节点；保留已有订阅和已发布白名单")
            return 4
        count = sum(r["ok"] for r in report["nodes"].values())
        if not args.no_publish:
            link = publish.publish(ROOT, session, token, filtered, cfg, candidates=source, client_report=report)
            if not link:
                return 3
            client_health.save_report(ROOT / "data" / "client-health.json", report)
        atomic_write(ROOT / cfg["output"]["file"], filtered)
        atomic_write(ROOT / "output" / "candidates.yaml", source)
        log.info("本机严格验证完成：%d/%d 个节点；通过两轮多目标 HTTPS 和 GitHub/ChatGPT 访问", count, len(report["nodes"]))
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        log.error("本机验证失败：%s", exc)
        sys.exit(1)
