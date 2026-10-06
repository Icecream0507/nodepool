"""把订阅 yaml 发布到 secret gist（创建或更新），返回稳定的 raw 链接。"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .util import log

API = "https://api.github.com/gists"


def load_token(root: Path) -> str | None:
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok.strip()
    env = root / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == "GITHUB_TOKEN":
                return v.strip().strip('"').strip("'")
    return None


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def publish(root: Path, session, token: str, content: str, cfg: dict) -> str | None:
    fn = cfg["publish"]["gist_filename"]
    desc = cfg["publish"]["gist_description"]
    state_path = root / "data" / "gist.json"
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    # 云端用环境变量传入固定 gist id（避免把订阅链接写进公开仓库/日志）
    gid = os.environ.get("NODEPOOL_GIST_ID") or state.get("id")
    payload = {"description": desc, "files": {fn: {"content": content}}}

    if gid:
        r = session.patch(f"{API}/{gid}", headers=_headers(token),
                          data=json.dumps(payload), timeout=40)
        if r.status_code == 404:
            log.warning("已记录的 gist 不存在，重新创建")
            gid = None
        elif r.status_code not in (200, 201):
            log.error("更新 gist 失败：%s %s", r.status_code, r.text[:200])
            return None
    if not gid:
        payload["public"] = False
        r = session.post(API, headers=_headers(token),
                         data=json.dumps(payload), timeout=40)
        if r.status_code not in (200, 201):
            log.error("创建 gist 失败：%s %s", r.status_code, r.text[:200])
            return None

    data = r.json()
    gid = data["id"]
    owner = (data.get("owner") or {}).get("login", "")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"id": gid, "owner": owner, "filename": fn},
                                     ensure_ascii=False, indent=1), encoding="utf-8")
    # 稳定 raw 链接（不带版本号，始终取最新）
    return f"https://gist.githubusercontent.com/{owner}/{gid}/raw/{fn}"
