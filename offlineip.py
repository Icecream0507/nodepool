"""OfflineIP 客户 API 只读客户端：签名、账号信息、已交付 IP 列表。

下单 / 续费会从余额扣款，这里刻意不实现。签名规则见 https://www.offlineip.com/api-docs
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlencode, urlsplit

import requests

DEFAULT_BASE = "https://www.offlineip.com"


def _rfc3986(value: str) -> str:
    return quote(value, safe="-_.~")


def canonical_query(raw: str) -> str:
    """key/value 先解码再 rawurlencode，按 key、value 升序；重复 key 不合并。"""
    if not raw:
        return ""
    pairs = []
    for pair in raw.split("&"):
        key, _, value = pair.partition("=")
        pairs.append((_rfc3986(unquote(key)), _rfc3986(unquote(value))))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def sign(secret: str, method: str, url: str, timestamp: str, nonce: str, body: bytes = b"") -> str:
    parts = urlsplit(url)
    canonical = "\n".join([
        method.upper(),
        (parts.hostname or "").lower(),
        parts.path or "/",
        canonical_query(parts.query),
        timestamp,
        nonce,
        hashlib.sha256(body).hexdigest(),
    ])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


class OfflineIPError(RuntimeError):
    pass


class Client:
    def __init__(self, app_id: str, secret: str, base_url: str = DEFAULT_BASE, session=None):
        self.app_id, self.secret = app_id, secret
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()

    def get(self, path: str, params: dict | None = None):
        url = self.base_url + path + (f"?{urlencode(params)}" if params else "")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = f"nce_{secrets.token_hex(16)}"
        headers = {
            "X-API-AppId": self.app_id,
            "X-API-Timestamp": timestamp,
            "X-API-Nonce": nonce,
            "X-API-Signature": sign(self.secret, "GET", url, timestamp, nonce),
            "Accept": "application/json",
            "User-Agent": "nodepool-chain-sub/1.0",
        }
        response = self.session.get(url, headers=headers, timeout=30)
        try:
            payload = response.json()
        except ValueError:
            raise OfflineIPError(f"HTTP {response.status_code}：响应不是 JSON") from None
        if not payload.get("success"):
            raise OfflineIPError(f"{payload.get('code')}: {payload.get('message')} (trace {payload.get('trace_id')})")
        return payload["data"]

    def account(self) -> dict:
        return self.get("/api/v1/account")

    def proxies(self, **filters) -> list[dict]:
        """翻完所有页，返回已交付 IP；filters 原样作为查询参数（如 status、country_code）。"""
        items, token = [], None
        while True:
            params = {"page_size": 100, **filters}
            if token:
                params["page_token"] = token
            data = self.get("/api/v1/proxies", params)
            items.extend(data.get("proxies", []))
            if not data.get("has_more"):
                return items
            token = data.get("next_page_token")


def dump(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)
