#!/usr/bin/env python3
"""在使用订阅的本机复测候选，并把严格通过的节点发布到固定订阅。"""
from __future__ import annotations

import argparse
import copy
import json
import math
import socket
import sys
import time
from pathlib import Path

import yaml

from nodepool import client_health, mihomo, output, pool, publish
from nodepool.config import load_config
from nodepool.util import atomic_write, log, make_session, run_lock

ROOT = Path(__file__).resolve().parent
_LOCAL_STAGE = 1  # Increment whenever the strict GET or confirmation stages change.
_LOCAL_BATCH_SIZE = 64
_RESUME_MAX_AGE = 30 * 60


def _complete_pass(delays, expected: int) -> bool:
    return (isinstance(delays, list) and len(delays) == expected
            and all(type(delay) is int and delay > 0 for delay in delays))


def _load_progress(path: Path | None, source_ids: list[str], policy: str) -> dict:
    fresh = {"schema": 1, "stage": _LOCAL_STAGE, "source_ids": source_ids,
             "policy": policy, "batches": {}}
    if path is not None and path.exists():
        try:
            stored = json.loads(path.read_text(encoding="utf-8-sig"))
            json.dumps(stored, allow_nan=False)
            if (isinstance(stored, dict) and type(stored.get("schema")) is int and stored["schema"] == 1
                    and type(stored.get("stage")) is int and stored["stage"] == _LOCAL_STAGE
                    and stored.get("source_ids") == source_ids and stored.get("policy") == policy
                    and isinstance(stored.get("batches"), dict)):
                return stored
        except (OSError, ValueError):
            pass
        log.info("本机验证检查点不匹配或无法读取，重新检测候选")
    return fresh


def _reusable_batch(progress: dict, index: int, proxies: list[dict], rounds: int):
    saved = progress["batches"].get(str(index))
    if not isinstance(saved, dict):
        return None
    tested_at, results = saved.get("tested_at"), saved.get("results")
    if (type(tested_at) not in (int, float) or not math.isfinite(tested_at) or tested_at < 0
            or not 0 <= time.time() - tested_at < _RESUME_MAX_AGE
            or not isinstance(results, dict) or set(results) != {p["name"] for p in proxies}):
        return None
    # Only completed strict passes or completed failures are written. A partial
    # native result must never be promoted via the less strict report builder.
    if not all(_complete_pass(delays, rounds) or delays == [None] * rounds for delays in results.values()):
        return None
    return results, tested_at


def _verify_batch(proxies: list[dict], exe: Path, local_cfg: dict) -> dict:
    mc = local_cfg["mihomo"]
    rounds = local_cfg["connectivity"]["rounds"]
    valid = mihomo.prune_invalid(exe, proxies, mc["controller"], mc["secret"], mc["startup_timeout"])
    results = {p["name"]: [None] * rounds for p in proxies}
    results.update(mihomo.test_connectivity(exe, valid, local_cfg, require_all=True))
    # A local publishing check is deliberately stricter than exploration: all
    # four native health checks, three public GET requests and a second full pass
    # must succeed. Native URLTest uses HEAD, which some service URLs reject.
    eligible = [p for p in valid if _complete_pass(results.get(p["name"]), rounds)]
    log.info("本机首轮严格通过 %d/%d；继续验证 Google、GitHub、ChatGPT 和第二轮连接", len(eligible), len(proxies))
    if eligible:
        web = mihomo.test_http_get(exe, eligible, local_cfg, {
            "https://www.gstatic.com/generate_204": 204,
            "https://github.com/robots.txt": 200,
            "https://chatgpt.com/cdn-cgi/trace": 200,
        })
        eligible = [p for p in eligible if web.get(p["name"]) is True]
        confirmation = mihomo.test_connectivity(exe, eligible, local_cfg, require_all=True)
        approved = {p["name"] for p in eligible
                    if _complete_pass(confirmation.get(p["name"]), rounds)}
        for name in results:
            if name not in approved:
                results[name] = [None] * rounds
            else:
                results[name] = confirmation[name]
    else:
        results = {name: [None] * rounds for name in results}
    return results


def verify_document(text: str, exe: Path, cfg: dict, *,
                    checkpoint_path: Path | None = None) -> tuple[str | None, dict]:
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
    checkpoint_path = Path(checkpoint_path) if checkpoint_path is not None else None
    policy = pool.connectivity_policy(cfg["connectivity"])
    progress = _load_progress(checkpoint_path, [p["name"] for p in proxies], policy)
    results, batch_times = {}, []
    for start in range(0, len(proxies), _LOCAL_BATCH_SIZE):
        batch = proxies[start:start + _LOCAL_BATCH_SIZE]
        index = start // _LOCAL_BATCH_SIZE
        cached = _reusable_batch(progress, index, batch, cfg["connectivity"]["rounds"])
        if cached is not None:
            batch_results, tested_at = cached
            log.info("本机验证批次 %d-%d/%d：复用 30 分钟内的完整严格检测", start + 1, start + len(batch), len(proxies))
        else:
            log.info("本机验证批次 %d-%d/%d：开始完整严格检测", start + 1, start + len(batch), len(proxies))
            batch_results = _verify_batch(batch, exe, local_cfg)
            tested_at = time.time()
            progress["batches"][str(index)] = {"tested_at": tested_at, "results": batch_results}
            if checkpoint_path is not None:
                atomic_write(checkpoint_path, json.dumps(progress, ensure_ascii=False, allow_nan=False))
        results.update(batch_results)
        batch_times.append(tested_at)
    report = client_health.build_report(results, proxies, cfg["connectivity"], required=True,
                                        now=min(batch_times))
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
        checkpoint_path = ROOT / "data" / "local-verification-progress.json"
        filtered, report = verify_document(source, exe, cfg, checkpoint_path=checkpoint_path)
        atomic_write(ROOT / "data" / "local-verification.json", json.dumps(report, ensure_ascii=False, indent=2))
        if filtered is None:
            checkpoint_path.unlink(missing_ok=True)
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
        checkpoint_path.unlink(missing_ok=True)
        log.info("本机严格验证完成：%d/%d 个节点；通过两轮原生 HTTPS 测速及 Google/GitHub/ChatGPT 公开地址 GET", count, len(report["nodes"]))
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        log.error("本机验证失败：%s", exc)
        sys.exit(1)
