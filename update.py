#!/usr/bin/env python3
"""nodepool 一键更新：采集 -> 测活 -> 测纯净度 -> 维护池 -> 生成并发布 Clash 订阅。

用法：
    python update.py                 # 跑完整流程
    python update.py --no-publish    # 只生成本地文件，不发布 gist
    python update.py --skip-collect  # 不采集新节点，只复测现有池
    python update.py --pages 5       # 覆盖搜索页数
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from pathlib import Path

import yaml

from nodepool import collect, mihomo, output, pool, publish
from nodepool.util import log, make_session

ROOT = Path(__file__).resolve().parent


def _alive_and_latency(rounds: list, min_pass: int):
    ok = [d for d in rounds if d is not None]
    if len(ok) >= min_pass:
        return True, min(ok)
    return False, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    ap.add_argument("--proxy", default=None,
                    help='覆盖代理，云端用 --proxy "" 直连')
    ap.add_argument("--pages", type=int, default=None)
    ap.add_argument("--no-publish", action="store_true")
    ap.add_argument("--skip-collect", action="store_true")
    ap.add_argument("--max-candidates", type=int, default=None)
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    if args.pages is not None:
        cfg["search"]["pages"] = args.pages
    if args.max_candidates is not None:
        cfg["collect"]["max_candidates"] = args.max_candidates
    if args.proxy is not None:
        cfg["proxy"] = args.proxy

    t0 = time.time()
    proxy = cfg.get("proxy") or None
    session = make_session(proxy)
    token = publish.load_token(ROOT)
    log.info("代理=%s  token=%s", proxy or "直连", "有" if token else "无（读取受 60 次/小时限制，发布不可用）")

    pool_path = ROOT / "data" / "pool.json"
    pl = pool.load(pool_path)
    log.info("当前节点池：%d 个", len(pl))

    # 1) 采集
    if not args.skip_collect:
        try:
            nodes = collect.collect(cfg, session, token)
            added = pool.merge_collected(pl, nodes)
            log.info("新增 %d 个节点入池", added)
        except Exception as e:
            log.error("采集阶段出错（继续用现有池）：%s", e)
    else:
        log.info("跳过采集")

    if not pl:
        log.error("池为空且无新节点，退出。通常是代理到 gist.github.com 不通，请稍后重试。")
        return 2

    # 2) 挑候选
    exe = mihomo.ensure_binary(ROOT, session)
    cands = pool.select_candidates(pl, int(cfg["collect"]["max_candidates"]))
    test_proxies = [{**r["proxy"], "name": r["id"]} for r in cands]
    log.info("本轮测试候选：%d 个", len(test_proxies))

    # 3) 连通性（先剔除 mihomo 无法解析的非法节点）
    mc = cfg["mihomo"]
    valid = mihomo.prune_invalid(exe, test_proxies, mc["controller"], mc["secret"],
                                 int(mc["startup_timeout"]))
    valid_ids = {p["name"] for p in valid}
    results = mihomo.test_connectivity(exe, valid, cfg) if valid else {}
    min_pass = int(cfg["connectivity"]["min_pass"])
    alive_ids = []
    for r in cands:
        if r["id"] in valid_ids:
            alive, lat = _alive_and_latency(results.get(r["id"], []), min_pass)
        else:
            alive, lat = False, None  # 非法节点计为失败
        pool.record_test(pl, r["id"], alive, lat)
        if alive:
            alive_ids.append(r["id"])
    log.info("连通性通过：%d / %d", len(alive_ids), len(test_proxies))

    # 4) 淘汰
    dropped = pool.prune(pl, int(cfg["pool"]["max_fail"]))
    if dropped:
        log.info("淘汰连续失败节点：%d 个", dropped)

    # 5) 纯净度（仅测活着且缓存过期的）
    cache_h = float(cfg["purity"]["cache_hours"])
    need = [r for r in cands if r["id"] in alive_ids and not pool.fresh_purity(r, cache_h)]
    reused = len(alive_ids) - len(need)
    if need:
        log.info("纯净度检测：%d 个（复用缓存 %d 个）", len(need), reused)
        probe_proxies = [{**r["proxy"], "name": r["id"]} for r in need]

        def on_res(nid, data):
            pool.record_purity(pl, nid, data)
        mihomo.probe_purity(exe, probe_proxies, cfg, on_result=on_res)
    else:
        log.info("纯净度检测：无需新测（复用缓存 %d 个）", reused)

    # 6) 最终筛选
    max_score = int(cfg["purity"]["max_score"])
    final = []
    for r in cands:
        if r["id"] not in alive_ids:
            continue
        p = r.get("purity")
        if p and p.get("score") is not None and p["score"] <= max_score:
            final.append(r)
    log.info("最终入选（可用且系数<=%d）：%d 个", max_score, len(final))

    # 7) 生成订阅
    sub_text, stats = output.build_subscription(final, cfg)
    out_path = ROOT / cfg["output"]["file"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(sub_text, encoding="utf-8")
    log.info("已写入 %s", out_path)

    # 8) 发布
    link = None
    if not args.no_publish and cfg["publish"]["enabled"]:
        if token:
            link = publish.publish(ROOT, session, token, sub_text, cfg)
        else:
            log.warning("未配置 GITHUB_TOKEN，跳过发布。在 .env 写入 GITHUB_TOKEN=xxx 即可自动发布。")

    removed = pool.enforce_limits(pl, int(cfg["pool"]["max_size"]),
                                  float(cfg["pool"]["stale_days"]))
    if removed:
        log.info("清理陈旧/超量节点：%d 个", removed)
    pool.save(pool_path, pl)

    # 9) 汇总
    _summary(pl, final, stats, link, out_path, cfg, time.time() - t0)
    return 0


def _summary(pl, final, stats, link, out_path, cfg, elapsed):
    print("\n" + "=" * 56)
    print(f"  节点池总量 {len(pl)}  |  本次入选 {len(final)}  |  用时 {elapsed:.0f}s")
    for _, _, lbl in cfg["purity"]["tiers"]:
        print(f"    {lbl}: {stats['tiers'].get(lbl, 0)}")
    top = sorted(final, key=lambda r: (r['purity']['score'], r.get('latency_ms') or 9e9))[:10]
    if top:
        print("  最纯净的若干个：")
        from nodepool.util import flag_emoji
        for r in top:
            p = r["purity"]
            print(f"    {flag_emoji(p.get('cc'))} {p.get('cc'):<3} 系数{p['score']:<3} "
                  f"{r.get('latency_ms') or '--'}ms  {p.get('org') or ''}")
    print(f"  本地文件: {out_path}")
    if link:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("  已发布到 secret gist（链接不在公开日志中显示）")
        else:
            print(f"  订阅链接: {link}")
            print("  （导入客户端后请开启“通过代理更新订阅”）")
    print("=" * 56)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断")
        sys.exit(130)
