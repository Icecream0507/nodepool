"""mihomo 内核：下载、生成测试配置、测延迟、测纯净度。

- 测延迟：external-controller 的 /proxies/{name}/delay（并发）
- 测纯净度：给每个节点开一个本地 mixed 监听端口，用 IN-NAME 规则把该端口的流量
  定向到对应节点，然后通过该端口请求 ippure，拿到真实出口 IP 与 fraudScore。
"""
from __future__ import annotations

import concurrent.futures as cf
import io
import hashlib
import os
import platform
import re
import subprocess
import secrets
import socket
import tempfile
import threading
import time
import zipfile
from pathlib import Path

import requests
import yaml

from .util import get_with_retry, log
from .pool import purity_from_api

RELEASE_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"


# ---------------------------------------------------------------- 下载内核

def _arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return m


def ensure_binary(root: Path, session: requests.Session) -> Path:
    system = platform.system().lower()
    target = root / "bin" / ("mihomo.exe" if system == "windows" else "mihomo")
    if target.exists() and target.stat().st_size > 1_000_000:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    log.info("未找到 mihomo 内核，开始下载…（%s/%s）", system, _arch())
    r = get_with_retry(session, RELEASE_API, tries=3, timeout=30,
                        headers={"Accept": "application/vnd.github+json"})
    if r is None or r.status_code != 200:
        raise RuntimeError(f"获取 mihomo release 失败：{getattr(r,'status_code','ERR')}")
    names = {a["name"]: a["browser_download_url"] for a in r.json().get("assets", [])}
    arch = _arch()
    if system == "windows":
        pats = [rf"mihomo-windows-{arch}-compatible-v[\d.]+\.zip$",
                rf"mihomo-windows-{arch}-v[\d.]+\.zip$"]
    else:  # linux（CI runner）等：发布的是 .gz 压缩的单个二进制
        pats = [rf"mihomo-{system}-{arch}-compatible-v[\d.]+\.gz$",
                rf"mihomo-{system}-{arch}-v[\d.]+\.gz$"]
    pick = None
    for pat in pats:
        for n in names:
            if re.match(pat, n):
                pick = n
                break
        if pick:
            break
    if not pick:
        raise RuntimeError(f"未找到合适的 {system}-{arch} 资产：{list(names)[:8]}")
    log.info("  下载 %s", pick)
    rr = get_with_retry(session, names[pick], tries=3, timeout=180)
    if rr is None:
        raise RuntimeError("mihomo 内核下载失败")
    rr.raise_for_status()
    asset = next(a for a in r.json()["assets"] if a["name"] == pick)
    digest = asset.get("digest") or ""
    if digest.startswith("sha256:") and hashlib.sha256(rr.content).hexdigest() != digest[7:]:
        raise RuntimeError("mihomo 下载文件校验失败")
    if pick.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(rr.content)) as z:
            member = next(m for m in z.namelist() if m.endswith(".exe"))
            binary = z.read(member)
    else:  # .gz
        import gzip
        binary = gzip.decompress(rr.content)
    fd, tmp = tempfile.mkstemp(prefix="mihomo_", suffix=target.suffix, dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(binary)
        if system != "windows":
            os.chmod(tmp, 0o755)
        subprocess.run([tmp, "-v"], check=True, capture_output=True, timeout=10)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    log.info("  内核已保存：%s", target)
    return target


# ---------------------------------------------------------------- 进程管理

class Mihomo:
    def __init__(self, exe: Path, cfg_text: str, controller: str, secret: str,
                 startup_timeout: int = 20):
        self.exe = exe
        self.controller = controller
        self.secret = secrets.token_urlsafe(24)
        self.startup_timeout = startup_timeout
        self._temp = tempfile.TemporaryDirectory(prefix="mihomo_")
        self._dir = self._temp.name
        self._cfg_path = os.path.join(self._dir, "config.yaml")
        with open(self._cfg_path, "w", encoding="utf-8") as f:
            config = yaml.safe_load(cfg_text)
            config["secret"] = self.secret
            f.write(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
        self._proc: subprocess.Popen | None = None
        self.base = f"http://{controller}"
        self.sess = requests.Session()
        self.sess.trust_env = False
        self.sess.headers["Authorization"] = f"Bearer {self.secret}"
        self._log = None

    def __enter__(self):
        try:
            from urllib.parse import urlparse
            address = urlparse(self.base)
            with socket.socket(socket.AF_INET6 if ":" in address.hostname else socket.AF_INET) as check:
                check.bind((address.hostname, address.port))
            self._log = open(os.path.join(self._dir, "mihomo.log"), "w+b")
            self._proc = subprocess.Popen(
                [str(self.exe), "-f", self._cfg_path, "-d", self._dir],
                stdout=self._log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if self._proc.poll() is not None:
                    self._log.seek(0)
                    out = self._log.read().decode("utf-8", "replace")
                    raise RuntimeError(f"mihomo 启动即退出：\n{out[-1500:]}")
                try:
                    r = self.sess.get(self.base + "/version", timeout=1)
                    if r.status_code == 200 and self._proc.poll() is None:
                        log.info("  mihomo 已就绪 %s", r.json().get("version", ""))
                        return self
                except (requests.RequestException, ValueError):
                    pass
                time.sleep(0.2)
            raise RuntimeError("mihomo 控制接口未在超时内就绪")
        except BaseException:
            self.stop()
            raise

    def _read_tail_and_raise(self):
        self.stop()
        raise RuntimeError("mihomo 控制接口未在超时内就绪")

    def __exit__(self, *exc):
        self.stop()

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        self._proc = None
        self.sess.close()
        if self._log:
            self._log.close()
            self._log = None
        self._temp.cleanup()

    # ---- API ----
    def delay(self, name: str, url: str, timeout_ms: int) -> int | None:
        from urllib.parse import quote
        try:
            r = self.sess.get(f"{self.base}/proxies/{quote(name, safe='')}/delay",
                              params={"timeout": timeout_ms, "url": url},
                              timeout=timeout_ms / 1000 + 3)
            if r.status_code == 200:
                return int(r.json().get("delay"))
        except (requests.RequestException, ValueError, TypeError):
            pass
        return None


# ---------------------------------------------------------------- 配置生成

_BASE_CFG = {
    "mixed-port": 0,
    "allow-lan": False,
    "mode": "rule",
    "log-level": "warning",
    "ipv6": False,
    "unified-delay": True,
    "geodata-mode": False,
    "geo-auto-update": False,
}


def prune_invalid(exe: Path, proxies: list[dict], controller: str, secret: str,
                  timeout: int, max_drops: int = 400) -> list[dict]:
    """使用配置检查剔除非法节点；不反复启动监听服务。"""
    proxies = list(proxies)
    drops = 0
    while drops < max_drops:
        text = build_test_config(proxies, controller, secret)
        try:
            check_config(exe, text, timeout)
            if drops:
                log.info("  剔除无法解析的节点 %d 个", drops)
            return proxies
        except RuntimeError as e:
            mm = re.search(r"proxy (\d+)", str(e))
            if mm and int(mm.group(1)) < len(proxies):
                proxies.pop(int(mm.group(1)))
                drops += 1
                continue
            raise
    raise RuntimeError(f"剔除非法节点已达上限 {max_drops}，停止使用未校验的配置")


def check_config(exe: Path, text: str, timeout: int = 20) -> None:
    with tempfile.TemporaryDirectory(prefix="mihomo_check_") as td:
        path = Path(td) / "config.yaml"
        path.write_text(text, encoding="utf-8")
        try:
            r = subprocess.run([str(exe), "-t", "-f", str(path), "-d", td],
                               capture_output=True, timeout=timeout,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("mihomo 配置检查超时") from exc
        if r.returncode:
            message = (r.stdout + r.stderr).decode("utf-8", "replace")
            index = re.search(r"proxy (\d+)", message)
            detail = f"proxy {index.group(1)} 无法解析" if index else "配置或内核无法使用"
            raise RuntimeError(f"mihomo 配置检查失败：{detail}")


def validate_subscription(exe: Path, text: str, timeout: int = 20) -> None:
    config = yaml.safe_load(text)
    if not config.get("proxies"):
        raise RuntimeError("拒绝生成空订阅")
    # GEOIP 数据由客户端管理；离线校验不触发数据库下载。
    config["rules"] = [r for r in config["rules"] if not r.startswith(("GEOIP,", "GEOSITE,"))]
    config["geodata-mode"] = False
    config["geo-auto-update"] = False
    if config.get("dns", {}).get("fallback"):
        # DNS fallback 默认也会加载 GeoIP，即使 rules 中没有 GEOIP。
        config["dns"].setdefault("fallback-filter", {})["geoip"] = False
    check_config(exe, yaml.safe_dump(config, allow_unicode=True, sort_keys=False), timeout)


def build_test_config(proxies: list[dict], controller: str, secret: str) -> str:
    cfg = dict(_BASE_CFG)
    cfg["external-controller"] = controller
    cfg["secret"] = secret
    cfg["proxies"] = proxies
    cfg["proxy-groups"] = [{"name": "GLOBAL", "type": "select",
                             "proxies": ["DIRECT"] + [p["name"] for p in proxies]}]
    cfg["rules"] = ["MATCH,DIRECT"]
    return yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)


def build_purity_config(proxies: list[dict], controller: str, secret: str,
                        base_port: int, hosts: dict | None = None) -> tuple[str, dict[str, int]]:
    """返回 (配置文本, {proxy_name: listen_port})。

    hosts：静态域名->IPv4 映射，用于强制 ippure 走 IPv4（否则 IPv6 出口拿不到系数）。
    """
    cfg = dict(_BASE_CFG)
    cfg["external-controller"] = controller
    cfg["secret"] = secret
    cfg["ipv6"] = False
    if hosts:
        cfg["hosts"] = hosts
    cfg["proxies"] = proxies
    cfg["proxy-groups"] = [{"name": "GLOBAL", "type": "select", "proxies": ["DIRECT"]}]
    listeners = []
    rules = []
    port_map = {}
    for i, p in enumerate(proxies):
        port = base_port + i
        lname = f"in-{i}"
        listeners.append({"name": lname, "type": "mixed",
                          "listen": "127.0.0.1", "port": port})
        rules.append(f"IN-NAME,{lname},{p['name']}")
        port_map[p["name"]] = port
    cfg["listeners"] = listeners
    cfg["rules"] = rules + ["MATCH,DIRECT"]
    return yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), port_map


# ---------------------------------------------------------------- 测延迟

def test_connectivity(exe: Path, proxies: list[dict], cfg: dict) -> dict[str, list[int | None]]:
    """多轮测延迟，返回 {name: [r1, r2, r3]}（None 表示该轮失败）。"""
    cc = cfg["connectivity"]
    url = cc["test_url"]
    tmo = int(cc["timeout_ms"])
    rounds = int(cc["rounds"])
    conc = int(cc["concurrency"])
    mc = cfg["mihomo"]
    text = build_test_config(proxies, mc["controller"], mc["secret"])
    results: dict[str, list] = {p["name"]: [] for p in proxies}
    if not proxies:
        return results
    with Mihomo(exe, text, mc["controller"], mc["secret"], int(mc["startup_timeout"])) as m:
        for rnd in range(1, rounds + 1):
            ok = 0
            with cf.ThreadPoolExecutor(max_workers=conc) as ex:
                futs = {ex.submit(m.delay, p["name"], url, tmo): p["name"] for p in proxies}
                for fut in cf.as_completed(futs):
                    name = futs[fut]
                    d = fut.result()
                    results[name].append(d)
                    if d is not None:
                        ok += 1
            log.info("  连通性第 %d/%d 轮：%d/%d 通过", rnd, rounds, ok, len(proxies))
    return results


# ---------------------------------------------------------------- 测纯净度

def probe_purity(exe: Path, proxies: list[dict], cfg: dict,
                 on_result=None) -> dict[str, dict]:
    """小批次检测、及时回写；只缓存包含有效评分的对象。"""
    out = {}
    size = int(cfg["purity"].get("batch_size", 32))
    deadline = time.monotonic() + cfg["purity"].get("max_seconds", 420)
    for start in range(0, len(proxies), size):
        if time.monotonic() >= deadline:
            log.warning("纯净度时间预算已到，未测节点留待下次运行")
            break
        batch = proxies[start:start + size]
        out.update(_probe_batch(exe, batch, cfg, on_result))
        log.info("  纯净度进度 %d/%d，有效结果 %d", min(start + size, len(proxies)), len(proxies), len(out))
    return out


def _probe_batch(exe: Path, proxies: list[dict], cfg: dict, on_result=None) -> dict[str, dict]:
    pc = cfg["purity"]
    mc = cfg["mihomo"]
    api = pc["api"]
    conc = int(pc["concurrency"])
    stagger = float(pc.get("stagger", 0.3))
    rtmo = int(pc["request_timeout"])
    # 强制 ippure 走 IPv4：本地解析其 A 记录作为 mihomo 静态 hosts
    from urllib.parse import urlparse

    from .util import resolve_ipv4
    api_host = urlparse(api).hostname or ""
    v4 = resolve_ipv4(api_host)
    hosts = {api_host: v4} if v4 else None
    if v4:
        log.info("  ippure 锁定 IPv4：%s -> %s", api_host, ", ".join(v4))
    else:
        log.warning("  未能解析 %s 的 IPv4，纯净度可能因 IPv6 出口而缺失", api_host)
    text, port_map = build_purity_config(proxies, mc["controller"], mc["secret"],
                                         int(mc["base_listen_port"]), hosts=hosts)
    out: dict[str, dict] = {}
    lock_time = [0.0]
    rate_lock = threading.Lock()

    def one(name: str) -> tuple[str, dict | None]:
        port = port_map[name]
        with requests.Session() as s:
            s.trust_env = False
            prox = f"http://127.0.0.1:{port}"
            s.proxies = {"http": prox, "https": prox}
            for attempt in range(2):
                with rate_lock:
                    time.sleep(max(0, lock_time[0] - time.monotonic()))
                    lock_time[0] = time.monotonic() + stagger
                try:
                    r = s.get(api, timeout=rtmo)
                    if r.status_code == 200:
                        data = r.json()
                        if purity_from_api(data) is not None:
                            return name, data
                except (requests.RequestException, ValueError):
                    pass
        return name, None

    with Mihomo(exe, text, mc["controller"], mc["secret"], int(mc["startup_timeout"])) as m:
        names = [p["name"] for p in proxies]
        with cf.ThreadPoolExecutor(max_workers=conc) as ex:
            futs = []
            for name in names:
                futs.append(ex.submit(one, name))
            done = 0
            for fut in cf.as_completed(futs):
                name, data = fut.result()
                done += 1
                if data:
                    out[name] = data
                    if on_result:
                        on_result(name, data)
    return out
