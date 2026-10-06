"""mihomo 内核：下载、生成测试配置、测延迟、测纯净度。

- 测延迟：external-controller 的 /proxies/{name}/delay（并发）
- 测纯净度：给每个节点开一个本地 mixed 监听端口，用 IN-NAME 规则把该端口的流量
  定向到对应节点，然后通过该端口请求 ippure，拿到真实出口 IP 与 fraudScore。
"""
from __future__ import annotations

import concurrent.futures as cf
import io
import os
import platform
import re
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

import requests
import yaml

from .util import get_with_retry, log

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
    rr = session.get(names[pick], timeout=180)
    rr.raise_for_status()
    if pick.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(rr.content)) as z:
            member = next(m for m in z.namelist() if m.endswith(".exe"))
            with z.open(member) as src, open(target, "wb") as dst:
                dst.write(src.read())
    else:  # .gz
        import gzip
        with open(target, "wb") as dst:
            dst.write(gzip.decompress(rr.content))
        target.chmod(0o755)
    log.info("  内核已保存：%s", target)
    return target


# ---------------------------------------------------------------- 进程管理

class Mihomo:
    def __init__(self, exe: Path, cfg_text: str, controller: str, secret: str,
                 startup_timeout: int = 20):
        self.exe = exe
        self.controller = controller
        self.secret = secret
        self.startup_timeout = startup_timeout
        self._dir = tempfile.mkdtemp(prefix="mihomo_")
        self._cfg_path = os.path.join(self._dir, "config.yaml")
        with open(self._cfg_path, "w", encoding="utf-8") as f:
            f.write(cfg_text)
        self._proc: subprocess.Popen | None = None
        self.base = f"http://{controller}"
        self.sess = requests.Session()
        self.sess.trust_env = False
        self.sess.headers["Authorization"] = f"Bearer {secret}"

    def __enter__(self):
        self._proc = subprocess.Popen(
            [str(self.exe), "-f", self._cfg_path, "-d", self._dir],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace",
        )
        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                out = self._proc.stdout.read() if self._proc.stdout else ""
                raise RuntimeError(f"mihomo 启动即退出：\n{out[-1500:]}")
            try:
                r = self.sess.get(self.base + "/version", timeout=2)
                if r.status_code == 200:
                    log.info("  mihomo 已就绪 %s", r.json().get("version", ""))
                    return self
            except requests.RequestException:
                time.sleep(0.3)
        self._read_tail_and_raise()

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
        self._proc = None

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
    """逐个剔除 mihomo 拒绝解析的非法节点，直到配置能启动。"""
    proxies = list(proxies)
    drops = 0
    while drops < max_drops:
        text = build_test_config(proxies, controller, secret)
        try:
            m = Mihomo(exe, text, controller, secret, timeout)
            m.__enter__()
            m.stop()
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
    log.warning("  剔除非法节点已达上限 %d", max_drops)
    return proxies


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
    """通过每个节点访问 ippure，返回 {name: {ip,fraudScore,...}}。"""
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

    def one(name: str) -> tuple[str, dict | None]:
        port = port_map[name]
        s = requests.Session()
        s.trust_env = False
        prox = f"http://127.0.0.1:{port}"
        s.proxies = {"http": prox, "https": prox}
        for attempt in range(2):
            try:
                r = s.get(api, timeout=rtmo)
                if r.status_code == 200:
                    data = r.json()
                    # 拿到 JSON 但没有系数（通常是 IPv6 出口）——重试一次
                    if data.get("fraudScore") is None and attempt == 0:
                        continue
                    return name, data
            except (requests.RequestException, ValueError):
                pass
        return name, None

    with Mihomo(exe, text, mc["controller"], mc["secret"], int(mc["startup_timeout"])) as m:
        names = [p["name"] for p in proxies]
        with cf.ThreadPoolExecutor(max_workers=conc) as ex:
            futs = []
            for name in names:
                # 轻微错峰，避免对 ippure 瞬时并发过高
                gap = max(0.0, lock_time[0] - time.time())
                time.sleep(gap)
                lock_time[0] = time.time() + stagger
                futs.append(ex.submit(one, name))
            done = 0
            for fut in cf.as_completed(futs):
                name, data = fut.result()
                done += 1
                if data and "fraudScore" in data:
                    out[name] = data
                    if on_result:
                        on_result(name, data)
    return out
