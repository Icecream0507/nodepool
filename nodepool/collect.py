"""采集：从 gist 搜索结果里抓节点。

- 搜索：爬 gist.github.com/search（无官方接口，只能爬 HTML）
- 读取内容：优先用 api.github.com/gists/{id}（带 token 更稳、支持多文件与截断），
  失败则回退 raw。
"""
from __future__ import annotations

import re
import time
from urllib.parse import quote

from .parse import extract_from_text
from .util import get_with_retry, log, node_key

SEARCH_URL = "https://gist.github.com/search"
API_URL = "https://api.github.com/gists/{}"

# /owner/<32hex>  —— 搜索结果里的 gist 链接
GIST_HREF = re.compile(r'href="/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?)/([0-9a-f]{20,})"')


def search_gist_ids(cfg, session) -> list[tuple[str, str]]:
    q = cfg["search"]["query"]
    pages = int(cfg["search"]["pages"])
    delay = float(cfg["search"]["page_delay"])
    found: list[tuple[str, str]] = []
    seen = set()
    for page in range(1, pages + 1):
        url = f"{SEARCH_URL}?o=desc&q={quote(q)}&s=updated&p={page}"
        r = get_with_retry(session, url, tries=3, timeout=30)
        if r is None or r.status_code != 200:
            code = getattr(r, "status_code", "ERR")
            log.warning("搜索第 %d 页失败(%s)，跳过", page, code)
            if page == 1:
                log.warning("  首页就失败——通常是代理到 gist.github.com 不通，可稍后重试")
            continue
        page_hits = []
        for owner, gid in GIST_HREF.findall(r.text):
            if gid not in seen:
                seen.add(gid)
                page_hits.append((owner, gid))
        found.extend(page_hits)
        log.info("搜索第 %d 页：+%d 个 gist（累计 %d）", page, len(page_hits), len(found))
        if not page_hits:
            break
        if page < pages:
            time.sleep(delay)
    return found


def _api_headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def fetch_gist_nodes(owner: str, gid: str, session, token: str | None) -> list[dict]:
    """返回该 gist 解析出的节点列表（未跨 gist 去重）。"""
    nodes: list[dict] = []
    r = get_with_retry(session, API_URL.format(gid), tries=2, timeout=30,
                        headers=_api_headers(token))
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        for fn, f in (data.get("files") or {}).items():
            content = f.get("content") or ""
            if f.get("truncated") and f.get("raw_url"):
                rr = get_with_retry(session, f["raw_url"], tries=2, timeout=40)
                if rr is not None and rr.status_code == 200:
                    content = rr.text
            nodes.extend(extract_from_text(content))
        return nodes

    # 回退：raw 第一个文件（api 不可用时）
    raw = f"https://gist.githubusercontent.com/{owner}/{gid}/raw"
    rr = get_with_retry(session, raw, tries=2, timeout=40)
    if rr is not None and rr.status_code == 200:
        nodes.extend(extract_from_text(rr.text))
    return nodes


def collect(cfg, session, token: str | None) -> list[dict]:
    ids = search_gist_ids(cfg, session)
    log.info("共发现 %d 个候选 gist，开始读取内容…", len(ids))
    min_n = int(cfg["collect"]["min_nodes_per_gist"])
    uniq: dict[str, dict] = {}
    skipped_small = 0
    for i, (owner, gid) in enumerate(ids, 1):
        nodes = fetch_gist_nodes(owner, gid, session, token)
        if len(nodes) < min_n:
            skipped_small += 1
            continue
        src = f"gist:{owner}/{gid[:8]}"
        for p in nodes:
            k = node_key(p)
            if k not in uniq:
                p["_source"] = src
                uniq[k] = p
        if i % 20 == 0:
            log.info("  已读取 %d/%d 个 gist，去重后 %d 个节点", i, len(ids), len(uniq))
    log.info("采集完成：%d 个唯一节点（跳过 %d 个节点过少的 gist）", len(uniq), skipped_small)
    return list(uniq.values())
