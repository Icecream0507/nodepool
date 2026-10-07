"""通用工具：日志、代理 session、base64 解码、国旗、节点指纹。"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

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
            if r.status_code in (403, 429, 500, 502, 503, 504) and i < tries - 1:
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
    if not isinstance(cc, str) or len(cc) != 2 or not cc.isascii() or not cc.isalpha():
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
    """所有连接参数参与去重；展示名称和采集元数据不参与。"""
    data = {k: v for k, v in p.items() if k != "name" and not k.startswith("_")}
    data["server"] = str(data.get("server", "")).strip().lower()
    data["port"] = int(data["port"])
    if data.get("type") in ("vless", "vmess", "trojan"):
        data.setdefault("network", "tcp")
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def node_id(p: dict) -> str:
    return hashlib.sha256(node_key(p).encode("utf-8")).hexdigest()[:16]


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def run_lock(path: Path):
    """进程退出时由操作系统释放锁，防止本机并行更新互相覆盖。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as f:
        if f.tell() == 0:
            f.write(b"0")
            f.flush()
        f.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("另一个 nodepool 更新进程正在运行") from exc
        try:
            yield
        finally:
            f.seek(0)
            if os.name == "nt":
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
