"""安全更新固定 secret gist；失败可重试，固定 ID 失效时不偷偷更换链接。"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests
import yaml

from .util import atomic_write, log

API = "https://api.github.com/gists"


def load_token(root: Path) -> str | None:
    tok = os.environ.get("GITHUB_TOKEN")
    if tok and tok.strip():
        return tok.strip()
    env = root / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == "GITHUB_TOKEN":
                return v.strip().strip('"').strip("'") or None
    return None


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def _request(session, method, url, token, payload=None, retries=3):
    for attempt in range(retries):
        try:
            response = session.request(method, url, headers=_headers(token), json=payload, timeout=40)
            if response.status_code not in (429, 500, 502, 503, 504) or attempt == retries - 1:
                return response
        except requests.RequestException:
            if attempt == retries - 1:
                log.error("Gist %s 请求失败：网络连接或超时", method)
                return None
        time.sleep(2 * (attempt + 1))
    return None


def _fixed_id(root: Path) -> str | None:
    fixed = os.environ.get("NODEPOOL_GIST_ID")
    if fixed:
        return fixed
    path = root / "data" / "gist.json"
    if path.exists():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            return state.get("id") if isinstance(state, dict) else None
        except (OSError, ValueError):
            return None
    return None


def _stable_file(records: dict, cfg: dict) -> dict:
    stable = {nid: r for nid, r in records.items() if r.get("stable")}
    text = json.dumps(stable, ensure_ascii=False, separators=(",", ":"))
    return {cfg["publish"].get("pool_filename", "stable-pool.json"): {"content": text}}


def restore_stable_pool(root: Path, session, token: str, cfg: dict) -> dict:
    """本地缓存为空时恢复稳定池；读取失败不静默重建并覆盖远端备份。"""
    gid = _fixed_id(root)
    if not gid:
        return {}
    response = _request(session, "GET", f"{API}/{gid}", token)
    if response is None or response.status_code != 200:
        raise RuntimeError("节点池缓存为空且无法读取远端稳定池备份，保留远端状态")
    try:
        data = response.json()
        if data.get("public") is not False:
            raise ValueError("备份目标不是 secret gist")
        file = (data.get("files") or {}).get(cfg["publish"].get("pool_filename", "stable-pool.json"))
        if not file:
            return {}  # 旧版本没有备份，正常从采集开始
        content = file.get("content") or "{}"
        if file.get("truncated"):
            raw = _request(session, "GET", file["raw_url"], token)
            if raw is None or raw.status_code != 200:
                raise ValueError("截断备份无法读取完整内容")
            content = raw.content.decode("utf-8")
        from .pool import _migrate
        restored = _migrate(json.loads(content))
        if any(not r.get("stable") for r in restored.values()):
            raise ValueError("稳定池备份包含非稳定记录")
        log.info("已从 secret gist 恢复稳定节点 %d 个", len(restored))
        return restored
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise RuntimeError("远端稳定池备份格式异常，停止更新以保护历史") from exc


def backup_stable_pool(root: Path, session, token: str, records: dict, cfg: dict) -> bool:
    """没有合格订阅时只保存稳定池历史，不修改订阅文件。"""
    gid = _fixed_id(root)
    if not gid or not any(r.get("stable") for r in records.values()):
        return True
    response = _request(session, "GET", f"{API}/{gid}", token)
    if response is None or response.status_code != 200:
        return False
    try:
        if response.json().get("public") is not False:
            return False
    except (ValueError, AttributeError):
        return False
    response = _request(session, "PATCH", f"{API}/{gid}", token,
                        {"files": _stable_file(records, cfg)})
    return response is not None and response.status_code == 200


def _file_content(data: dict, filename: str, session, token: str) -> str | None:
    file = (data.get("files") or {}).get(filename)
    if file is None:
        return None
    if not isinstance(file, dict):
        raise ValueError("Gist 文件格式异常")
    if file.get("truncated"):
        raw = _request(session, "GET", file["raw_url"], token)
        if raw is None or raw.status_code != 200:
            raise ValueError("无法读取完整 Gist 文件")
        return raw.content.decode("utf-8")
    content = file.get("content")
    if not isinstance(content, str):
        raise ValueError("Gist 文件内容异常")
    return content


def read_remote_file(root: Path, session, token: str, cfg: dict, filename: str) -> str | None:
    gid = _fixed_id(root)
    if not gid:
        return None
    response = _request(session, "GET", f"{API}/{gid}", token)
    try:
        if response is None or response.status_code != 200:
            raise ValueError("不可访问")
        data = response.json()
        if not isinstance(data, dict) or data.get("public") is not False:
            raise ValueError("目标不是 secret gist")
        return _file_content(data, filename, session, token)
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise RuntimeError("无法安全读取远端验证状态，保留现有订阅") from exc


def restore_client_health(root: Path, session, token: str, cfg: dict) -> dict | None:
    from .client_health import validate_report
    text = read_remote_file(root, session, token, cfg, cfg["publish"]["client_health_filename"])
    if text is None:
        return None
    try:
        return validate_report(json.loads(text))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("远端客户端验证记录损坏，保留现有订阅") from exc


def publish_candidates(root: Path, session, token: str, content: str, cfg: dict) -> bool:
    """Keep new cloud discoveries available for local verification without changing the subscription."""
    document = yaml.safe_load(content)
    if not isinstance(document, dict) or not document.get("proxies"):
        raise ValueError("拒绝发布空候选")
    from .output import simplify_subscription
    content = simplify_subscription(content, cfg)
    gid = _fixed_id(root)
    if not gid:
        return False
    existing = _request(session, "GET", f"{API}/{gid}", token)
    try:
        if existing is None or existing.status_code != 200 or existing.json().get("public") is not False:
            return False
    except (ValueError, AttributeError):
        return False
    result = _request(session, "PATCH", f"{API}/{gid}", token,
                      {"files": {cfg["publish"]["candidate_filename"]: {"content": content}}})
    return result is not None and result.status_code == 200


def publish(root: Path, session, token: str, content: str, cfg: dict,
            records: dict | None = None, candidates: str | None = None,
            client_report: dict | None = None) -> str | None:
    document = yaml.safe_load(content)
    if not isinstance(document, dict) or not document.get("proxies"):
        raise ValueError("拒绝发布空订阅")
    from .output import simplify_subscription
    content = simplify_subscription(content, cfg)
    fn = cfg["publish"]["gist_filename"]
    state_path = root / "data" / "gist.json"
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("状态不是对象")
        except (OSError, ValueError) as exc:
            if not os.environ.get("NODEPOOL_GIST_ID"):
                log.error("Gist 状态损坏，停止发布以保护固定订阅地址")
                return None
    gid = os.environ.get("NODEPOOL_GIST_ID") or state.get("id")
    payload = {"description": cfg["publish"]["gist_description"], "files": {fn: {"content": content}}}
    if candidates is not None:
        candidate_doc = yaml.safe_load(candidates)
        if not isinstance(candidate_doc, dict) or not candidate_doc.get("proxies"):
            raise ValueError("拒绝发布空候选")
        candidates = simplify_subscription(candidates, cfg)
        payload["files"][cfg["publish"]["candidate_filename"]] = {"content": candidates}
    if records is not None:
        payload["files"].update(_stable_file(records, cfg))
    if gid:
        # 更新前确认目标可读且为 secret，避免把节点内容写入 public gist。
        existing = _request(session, "GET", f"{API}/{gid}", token)
        if existing is None or existing.status_code != 200:
            log.error("固定 Gist 不可访问，保留订阅地址并停止发布")
            return None
        try:
            data = existing.json()
            if data.get("public") is not False:
                log.error("目标 Gist 不是 secret，停止发布")
                return None
            # A local diagnostic report gates cloud publication only when
            # explicitly enabled in project configuration.
            if cfg["publish"]["client_health_required"] or client_report is not None:
                from .client_health import filter_subscription, load_report, validate_report
                from .pool import connectivity_policy
                report = client_report
                remote_report = _file_content(data, cfg["publish"]["client_health_filename"], session, token)
                previous_report = validate_report(json.loads(remote_report)) if remote_report is not None else None
                local_report_path = root / "data" / "client-health.json"
                if previous_report is None and client_report is None and local_report_path.exists():
                    if load_report(local_report_path)["required"]:
                        raise ValueError("已启用的远端验证文件缺失")
                if report is None:
                    report = previous_report
                else:
                    report = validate_report(report)
                    if previous_report is not None and previous_report["tested_at"] > report["tested_at"]:
                        raise ValueError("已有更新的客户端验证记录")
                    payload["files"][cfg["publish"]["client_health_filename"]] = {
                        "content": json.dumps(report, ensure_ascii=False, separators=(",", ":"))}
                if report is not None:
                    payload["files"][fn]["content"] = filter_subscription(
                        candidates if candidates is not None else content, report,
                        connectivity_policy(cfg["connectivity"]),
                        max_age_hours=cfg["publish"]["client_health_max_age_hours"])
        except (ValueError, AttributeError, KeyError, TypeError):
            log.error("Gist 或客户端验证状态异常/无合格节点，保留原订阅")
            return None
        r = _request(session, "PATCH", f"{API}/{gid}", token, payload)
    else:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            log.error("云端首次运行需要配置 GIST_ID，防止缓存丢失时改变订阅地址")
            return None
        payload["public"] = False
        # 创建不是幂等请求，超时后由用户核对，避免自动生成多个 gist。
        r = _request(session, "POST", API, token, payload, retries=1)
    if r is None:
        return None
    if r.status_code not in (200, 201):
        log.error("发布 Gist 失败：HTTP %s", r.status_code)
        return None
    try:
        data = r.json()
        new_id = data["id"]
        owner = data["owner"]["login"]
        if gid and new_id != gid:
            raise ValueError("Gist ID 不一致")
        if not isinstance(owner, str) or not owner:
            raise ValueError("缺少 owner")
    except (ValueError, KeyError, TypeError):
        log.error("发布响应格式异常，未修改本地 Gist 状态")
        return None
    atomic_write(state_path, json.dumps({"id": new_id, "owner": owner, "filename": fn}, ensure_ascii=False, indent=1))
    log.info("订阅已发布到固定 secret gist")
    return f"https://gist.githubusercontent.com/{owner}/{new_id}/raw/{fn}"
