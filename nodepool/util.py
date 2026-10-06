"""通用工具：日志、代理 session、base64 解码、国旗、节点指纹。"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import sys
import time

import requests

# ---------------------------------------------------------------- 日志

def get_logger(name: str = "nodepool") -> logging.Logger:
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname).1s %(message)s", "%H:%M:%S"))
    log.addHandler(h)
    return log


log = get_logger()


# ---------------------------------------------------------------- HTTP

def make_session(proxy: str | None, trust_env: bool = False) -> requests.Session:
    """创建一个固定走 proxy 的 session，并忽略系统环境里的代理变量。"""
    s = requests.Session()
    s.trust_env = trust_env
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    })
    return s


def get_with_retry(session: requests.Session, url: str, *, tries: int = 3,
                   timeout: int = 30, **kw) -> requests.Response | None:
    for i in range(tries):
        try:
            r = session.get(url, timeout=timeout, **kw)
            if r.status_code == 200:
                return r
            # gist/api 限流会给 403/429
            if r.status_code in (403, 429) and i < tries - 1:
                wait = 5 * (i + 1)
                log.warning("  %s -> %s，等待 %ss 重试", url[:70], r.status_code, wait)
                time.sleep(wait)
                continue
            return r
        except requests.RequestException as e:
            if i < tries - 1:
                time.sleep(2 * (i + 1))
                continue
            log.warning("  请求失败 %s: %s", url[:70], e)
    return None


# ---------------------------------------------------------------- base64

def try_b64decode(text: str) -> str | None:
    """尽量把一段可能的 base64（含 url-safe / 无填充）解码成文本。失败返回 None。"""
    s = "".join(text.split())
    if len(s) < 16:
        return None
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    s += "=" * pad
    try:
        raw = base64.b64decode(s, validate=False)
    except Exception:
        return None
    try:
        out = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            out = raw.decode("utf-8", "ignore")
        except Exception:
            return None
    # 解出来得像订阅内容（含协议头）才算成功
    if "://" in out:
        return out
    return None


# ---------------------------------------------------------------- 国旗

def resolve_ipv4(host: str) -> list[str]:
    """本地解析域名的 A 记录（仅 IPv4）。失败返回 []。"""
    import socket
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def flag_emoji(cc: str | None) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🏳"
    cc = cc.upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


# ---------------------------------------------------------------- 节点

def is_bogus_host(host: str) -> bool:
    """占位 / 内网 / 非法地址，直接丢弃。"""
    if not host:
        return True
    h = host.strip("[]").lower()
    if h in ("localhost", "example.com", "127.0.0.1", "0.0.0.0", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified or ip.is_link_local
    except ValueError:
        return False  # 域名


def node_key(p: dict) -> str:
    """节点去重指纹：类型 + 服务器 + 端口 + 凭据 + 传输 + sni + 路径。"""
    cred = p.get("uuid") or p.get("password") or ""
    net = p.get("network", "")
    sni = p.get("servername") or p.get("sni") or ""
    path = ""
    if "ws-opts" in p:
        path = (p["ws-opts"] or {}).get("path", "")
    elif "grpc-opts" in p:
        path = (p["grpc-opts"] or {}).get("grpc-service-name", "")
    parts = [str(p.get("type")), str(p.get("server")).lower(), str(p.get("port")),
             str(cred), str(net), str(sni), str(path)]
    return "|".join(parts)


def node_id(p: dict) -> str:
    return hashlib.sha1(node_key(p).encode("utf-8")).hexdigest()[:10]
