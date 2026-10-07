#!/usr/bin/env python3
"""采集、维护稳定节点池、测活、测纯净度并安全更新订阅。"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from pathlib import Path

from nodepool import collect, mihomo, output, pool, publish
from nodepool.config import load_config, validate_config
from nodepool.util import atomic_write, log, make_session, run_lock

ROOT = Path(__file__).resolve().parent


def _alive_and_latency(rounds: list, min_pass: int):
    ok = [d for d in rounds if type(d) is int and d >= 0]
    return (True, int(statistics.median(ok))) if len(ok) >= min_pass else (False, None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    ap.add_argument("--proxy", default=None, help='覆盖代理，云端用 --proxy "" 直连')
    ap.add_argument("--pages", type=int)
    ap.add_argument("--max-candidates", type=int)
    ap.add_argument("--no-publish", action="store_true")
    ap.add_argument("--skip-collect", action="store_true")
    args = ap.parse_args()
    try:
        cfg = load_config(Path(args.config))
        if args.pages is not None:
            cfg["search"]["pages"] = args.pages
        if args.max_candidates is not None:
            cfg["collect"]["max_candidates"] = args.max_candidates
        if args.proxy is not None:
            cfg["proxy"] = args.proxy
        validate_config(cfg)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    with run_lock(ROOT / "data" / "update.lock"):
        return _run(cfg, args)


def _run(cfg, args) -> int:
    t0 = time.time()
    pool_path = ROOT / "data" / "pool.json"
    pl = pool.load(pool_path)
    session = make_session(cfg.get("proxy") or None)
    token = publish.load_token(ROOT)
    log.info("代理=%s token=%s", cfg.get("proxy") or "直连", "有" if token else "无")
    pc = cfg["pool"]
    test_policy = pool.connectivity_policy(cfg["connectivity"])
    try:
        remote_ready = True
        if token:
            try:
                restored = publish.restore_stable_pool(ROOT, session, token, cfg)
            except RuntimeError:
                if not pl:
                    raise
                remote_ready = False
                log.warning("远端稳定池备份暂不可读，继续使用本地节点池")
            else:
                for nid, recovered in restored.items():
                    current = pl.get(nid)
                    if current is None or recovered.get("last_test", 0) > current.get("last_test", 0):
                        pl[nid] = recovered
                    elif recovered.get("stable"):
                        current["stable"] = True
                        current["stable_since"] = recovered.get("stable_since", 0)
        log.info("当前节点池：%d 个（稳定 %d 个）", len(pl), sum(bool(r.get("stable")) for r in pl.values()))
        if not args.skip_collect:
            try:
                nodes = collect.collect(cfg, session, token)
                log.info("新增 %d 个节点入池", pool.merge_collected(pl, nodes))
            except Exception as exc:
                log.error("采集阶段出错，继续使用现有池：%s", exc)
        if not pl:
            log.error("节点池为空且没有采集到新节点")
            return 2
        pool.enforce_limits(pl, pc["max_size"], pc["stale_days"])
        pool.save(pool_path, pl)
        cands = pool.select_candidates(pl, cfg["collect"]["max_candidates"],
                                       pc["exploration_ratio"], cfg["purity"]["max_score"])
        alive_ids = set()
        exe = mihomo.ensure_binary(ROOT, session) if cands else None
        if cands:
            mc = cfg["mihomo"]
            test_proxies = [{**r["proxy"], "name": r["id"]} for r in cands]
            log.info("本轮测试候选：%d 个（稳定 %d 个）", len(cands), sum(bool(r.get("stable")) for r in cands))
            valid = mihomo.prune_invalid(exe, test_proxies, mc["controller"], mc["secret"], mc["startup_timeout"])
            results = mihomo.test_connectivity(exe, valid, cfg) if valid else {}
            for r in cands:
                alive, lat = _alive_and_latency(results.get(r["id"], []), cfg["connectivity"]["min_pass"])
                pool.record_test(pl, r["id"], alive, lat, pc["history_size"], policy=test_policy)
                if alive:
                    alive_ids.add(r["id"])
            log.info("连通性通过：%d / %d", len(alive_ids), len(cands))
            pool.save(pool_path, pl)
        cache_h = cfg["purity"]["cache_hours"]
        need = [r for r in cands if r["id"] in alive_ids and not pool.fresh_purity(r, cache_h)]
        log.info("纯净度待测 %d 个，复用缓存 %d 个", len(need), len(alive_ids) - len(need))
        if need:
            probes = [{**r["proxy"], "name": r["id"]} for r in need]
            mihomo.probe_purity(exe, probes, cfg,
                               on_result=lambda nid, data: pool.record_purity(pl, nid, data))
        promoted = pool.promote_stable(pl, pc, cache_h, cfg["purity"]["max_score"], policy=test_policy)
        retired = pool.prune(pl, pc["max_fail"], stable_max_fail=pc["stable_max_fail"],
                             stable_grace_days=pc["stable_grace_days"], cooldown_hours=pc["cooldown_hours"])
        log.info("晋升稳定节点 %d 个；进入冷却 %d 个", promoted, retired)
        # 未轮到本次复测的节点，在连通性与纯净度有效期内继续服务。
        now = time.time()
        final = [r for r in pl.values() if r.get("last_ok", 0) > 0
                 and pool.tested_with_policy(r, test_policy)
                 and r.get("last_test") == r.get("last_ok") and r.get("fail_streak", 0) == 0
                 and 0 <= now - r["last_ok"] < cfg["output"]["max_test_age_hours"] * 3600
                 and pool.fresh_purity(r, cache_h) and r["purity"]["score"] <= cfg["purity"]["max_score"]]
        log.info("最终入选：%d 个（稳定 %d 个）", len(final), sum(bool(r.get("stable")) for r in final))
        if not final:
            log.error("本轮没有通过有效期内检测的合格节点，保留原订阅，不发布空结果")
            if token and remote_ready and not args.no_publish and cfg["publish"]["enabled"]:
                if not publish.backup_stable_pool(ROOT, session, token, pl, cfg):
                    log.error("远端稳定池备份未成功，本地状态仍会保存")
            return 4
        sub_text, stats = output.build_subscription(final, cfg)
        if not stats["total"]:
            raise RuntimeError("订阅没有可输出的节点")
        if exe is None:
            exe = mihomo.ensure_binary(ROOT, session)
        mihomo.validate_subscription(exe, sub_text, cfg["mihomo"]["startup_timeout"])
        out_path = ROOT / cfg["output"]["file"]
        atomic_write(out_path, sub_text)
        # 发布前持久化；网络错误不能丢失本轮积累。
        pool.save(pool_path, pl)
        link = None
        status = 0
        if not args.no_publish and cfg["publish"]["enabled"]:
            if not token:
                log.error("发布已启用但未配置 GITHUB_TOKEN；本地订阅已生成")
                status = 3
            else:
                link = publish.publish(ROOT, session, token, sub_text, cfg,
                                       records=pl if remote_ready else None)
                if not link:
                    status = 3
        _summary(pl, final, stats, link, out_path, cfg, time.time() - t0)
        return status
    finally:
        try:
            if pl:
                pool.enforce_limits(pl, pc["max_size"], pc["stale_days"])
                pool.save(pool_path, pl)
        finally:
            session.close()


def _summary(pl, final, stats, link, out_path, cfg, elapsed):
    print("\n" + "=" * 56)
    print(f"  节点池总量 {len(pl)} | 稳定 {sum(bool(r.get('stable')) for r in pl.values())} | 本次输出 {stats['total']} | 用时 {elapsed:.0f}s")
    for _, _, label in cfg["purity"]["tiers"]:
        print(f"    {label}: {stats['tiers'].get(label, 0)}")
    from nodepool.util import flag_emoji
    for r in sorted(final, key=lambda r: (r["purity"]["score"], r.get("latency_ms") or 9e9))[:10]:
        p = r["purity"]
        cc = str(p.get("cc") or "??")
        print(f"    {flag_emoji(cc)} {cc:<3} 系数{p['score']:<3} {r.get('latency_ms')}ms {p.get('org') or ''}")
    print(f"  本地文件: {out_path}")
    if link:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("  已发布到 secret gist（链接不在公开日志中显示）")
        else:
            print(f"  订阅链接: {link}")
    print("=" * 56)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断，已完成阶段的节点池状态已保存")
        sys.exit(130)
    except Exception as exc:
        log.error("更新失败：%s", exc)
        sys.exit(1)
