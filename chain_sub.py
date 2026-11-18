"""把一个落地代理包装成「freenode 出海 → 落地代理」的链式 Clash 订阅，并发布到 secret gist。

用法:
    python chain_sub.py "133.157.53.81:7077:user:pass"
    python chain_sub.py "socks5://user:pass@1.2.3.4:1080" --name 东京住宅
    python chain_sub.py "http://user:pass@1.2.3.4:8080" --no-test
    python chain_sub.py --offlineip                 # 从 OfflineIP 账号自动拉取全部生效 IP
    python chain_sub.py --offlineip --only 1.2.3.4  # 只处理指定 IP

--offlineip 需要 .env 里的 OFFLINEIP_API_APP_ID / OFFLINEIP_API_SECRET（只读接口，不会下单或续费）。

支持的输入: host:port:user:pass / host:port / user:pass@host:port / socks5:// / http:// URL。
分段格式默认按 socks5（静态住宅代理普遍推荐 socks5），可用 --type http 覆盖。

同一个 host:port 再次运行会更新原 gist，订阅链接保持不变；--new 强制新建。
默认先用本地 mihomo 真跑一遍链式配置，确认出口 IP 就是落地代理再发布。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import yaml

ROOT = Path(__file__).resolve().parent
API = "https://api.github.com/gists"
STATE = ROOT / "data" / "chain-subs.json"
GROUP_OUT = "出海(freenode)"
GROUP_MAIN = "🎯 落地(链式)"
HEALTH_URL = "https://cp.cloudflare.com/generate_204"
SCHEMES = {"socks5": "socks5", "socks5h": "socks5", "socks": "socks5", "http": "http", "https": "http"}


def parse_proxy(text: str, default_type: str = "socks5") -> dict:
    """解析各种常见代理写法，返回 mihomo proxy 字段（不含 name）。"""
    text = text.strip()
    if not text:
        raise ValueError("代理为空")
    kind = default_type
    user = password = None
    if "://" in text:
        u = urlparse(text)
        if u.scheme.lower() not in SCHEMES:
            raise ValueError(f"不支持的协议: {u.scheme}")
        kind = SCHEMES[u.scheme.lower()]
        host, port = u.hostname, u.port
        user = unquote(u.username) if u.username else None
        password = unquote(u.password) if u.password else None
    elif "@" in text:
        cred, _, addr = text.rpartition("@")
        user, _, password = cred.partition(":")
        host, _, port = addr.rpartition(":")
    else:
        parts = text.split(":")
        if len(parts) == 2:
            host, port = parts
        elif len(parts) == 4:
            host, port, user, password = parts
        else:
            raise ValueError("分段格式应为 host:port 或 host:port:user:pass")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError("端口必须是数字") from None
    if not host or not 0 < port < 65536:
        raise ValueError("主机或端口不合法")
    proxy = {"type": kind, "server": host, "port": port}
    if user:
        proxy["username"] = user
        proxy["password"] = password or ""
    if kind == "socks5":
        proxy["udp"] = True
    return proxy


# 国家 → 浏览器语言（Accept-Language / 指纹浏览器语言设置用），未列出的国家不给建议。
LANGUAGES = {
    "JP": "ja-JP 日语", "US": "en-US 英语", "GB": "en-GB 英语", "CA": "en-CA 英语 / fr-CA 法语",
    "AU": "en-AU 英语", "NZ": "en-NZ 英语", "IE": "en-IE 英语", "SG": "en-SG 英语 / zh-SG 中文",
    "HK": "zh-HK 繁体中文", "TW": "zh-TW 繁体中文", "KR": "ko-KR 韩语", "DE": "de-DE 德语",
    "FR": "fr-FR 法语", "ES": "es-ES 西班牙语", "MX": "es-MX 西班牙语", "BR": "pt-BR 葡萄牙语",
    "IT": "it-IT 意大利语", "NL": "nl-NL 荷兰语", "RU": "ru-RU 俄语", "TH": "th-TH 泰语",
    "VN": "vi-VN 越南语", "ID": "id-ID 印尼语", "MY": "ms-MY 马来语", "PH": "en-PH 英语 / fil-PH",
    "IN": "en-IN 英语 / hi-IN 印地语", "TR": "tr-TR 土耳其语", "AE": "ar-AE 阿拉伯语",
}


def lookup_ip(host: str) -> dict:
    """查询落地 IP 的位置、时区、运营商；失败返回空字典，不影响发布。"""
    try:
        ip = socket.gethostbyname(host)
        info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
    except (OSError, requests.RequestException, ValueError):
        return {}
    info["language"] = LANGUAGES.get(info.get("country", ""))
    return info


def describe(info: dict) -> list[str]:
    if not info:
        return ["位置: 查询失败"]
    place = ", ".join(p for p in (info.get("city"), info.get("region"), info.get("country")) if p)
    return [f"IP:   {info.get('ip', '?')}",
            f"位置: {place or '?'}",
            f"时区: {info.get('timezone') or '?'}",
            f"语言: {info.get('language') or '未知(按当地主要语言设置)'}",
            f"运营商: {info.get('org') or '?'}"]


def out_group(front: str = "freenode") -> str:
    return GROUP_OUT if front == "freenode" else f"出海({front})"


def build_config(proxy: dict, name: str, provider_url: str, port: int = 7890,
                 notes: list[str] | None = None, front: str = "freenode",
                 exclude: str | None = None, include: str | None = None) -> str:
    group_out = out_group(front)
    landing = {"name": name, **proxy, "dialer-proxy": group_out}
    out = {"name": group_out, "type": "url-test", "use": ["front"],
           "url": HEALTH_URL, "interval": 300, "tolerance": 50}
    if exclude:
        # 机场订阅常带「剩余流量/套餐到期」之类的信息节点，不能进自动选择。
        out["exclude-filter"] = exclude
    if include:
        # 只收能连上落地的线路（实测良心云港/日/专线连不上东京落地，延迟却最低）。
        out["filter"] = include
    inline = None
    if Path(provider_url).is_file():
        # 本地 Clash 配置（如客户端缓存的机场订阅）：节点直接内嵌，不再在线拉取。
        drop = re.compile(exclude) if exclude else None
        keep = re.compile(include) if include else None
        inline = [p for p in yaml.safe_load(Path(provider_url).read_text(encoding="utf-8"))["proxies"]
                  if not (drop and drop.search(p["name"])) and not (keep and not keep.search(p["name"]))]
        if not inline:
            raise ValueError(f"{provider_url} 里没有可用节点")
        del out["use"]
        out.pop("exclude-filter", None)
        out.pop("filter", None)
        out["proxies"] = [p["name"] for p in inline]
    host = None if inline else urlparse(provider_url).hostname
    direct = ["DOMAIN-SUFFIX,githubusercontent.com,DIRECT", "DOMAIN-SUFFIX,github.com,DIRECT"]
    if host and not any(host.endswith(d) for d in ("githubusercontent.com", "github.com")):
        direct.append(f"DOMAIN,{host},DIRECT")
    cfg = {
        "mixed-port": port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        # 落地代理和免费节点都只走 IPv4，开着 IPv6 会让真实 IPv6 绕过代理泄露。
        "ipv6": False,
        "proxy-providers": {"front": {
            "type": "http", "url": provider_url, "interval": 3600,
            "path": "./providers/freenode.yaml" if front == "freenode" else "./providers/front.yaml",
            "health-check": {"enable": True, "url": HEALTH_URL, "interval": 300},
        }},
        "proxies": (inline or []) + [landing],
        "proxy-groups": [
            out,
            {"name": GROUP_MAIN, "type": "select", "proxies": [name, group_out]},
        ],
        # 拉取前置订阅必须直连：否则下载节点要先走链式、链式又要先有节点，形成死锁。
        "rules": direct + [f"MATCH,{GROUP_MAIN}"],
    }
    if inline:
        del cfg["proxy-providers"]
        # 机场的部分线路（实测良心云港/日线）连不上落地，但它们自身延迟最低，按前置测速会
        # 一直选中死路。改为每个前置节点各配一份落地，url-test 直接测「前置+落地」整条链。
        copies = [{**landing, "name": f"{name} ← {p['name']}", "dialer-proxy": p["name"]} for p in inline]
        auto = {"name": f"⚡ 自动前置({front})", "type": "url-test", "proxies": [c["name"] for c in copies],
                "url": HEALTH_URL, "interval": 300, "tolerance": 100, "lazy": False}
        cfg["proxies"] = inline + copies
        cfg["proxy-groups"] = [auto, {"name": GROUP_MAIN, "type": "select",
                                      "proxies": [auto["name"], *auto["proxies"]]}]
    header = f"# 链式订阅: 本机 → {front} 出海 → {name} 落地\n# 由 chain_sub.py 生成，含明文账密，勿外传\n"
    header += "".join(f"# {line}\n" for line in notes or [])
    return header + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)


def env_value(name: str, default: str | None = None) -> str | None:
    """先读环境变量，再读项目根目录 .env。"""
    if os.environ.get(name):
        return os.environ[name]
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8-sig").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name:
                return value.strip().strip("'\"")
    return default


def load_token() -> str:
    token = env_value("GITHUB_TOKEN")
    if not token:
        raise SystemExit("缺少 GITHUB_TOKEN（环境变量或 .env）")
    return token


def offlineip_proxies(only: list[str] | None = None) -> list[tuple[dict, str | None, list[str]]]:
    """从 OfflineIP 账号拉取生效中的静态 IP，返回 (proxy, 备注名, 附加说明)。"""
    from offlineip import DEFAULT_BASE, Client
    app_id, secret = env_value("OFFLINEIP_API_APP_ID"), env_value("OFFLINEIP_API_SECRET")
    if not app_id or not secret:
        raise SystemExit("缺少 OFFLINEIP_API_APP_ID / OFFLINEIP_API_SECRET（环境变量或 .env）")
    client = Client(app_id, secret, env_value("OFFLINEIP_API_BASE_URL", DEFAULT_BASE))
    result = []
    for item in client.proxies():
        if item.get("status") != "active" or not item.get("socks5_uri"):
            continue
        if only and item.get("host") not in only and item.get("proxy_id") not in only:
            continue
        extra = [f"类型: {item.get('ip_type_name') or '?'} / {item.get('line_name') or '?'}",
                 f"到期: {item.get('expires_at') or '?'}"]
        result.append((parse_proxy(item["socks5_uri"]), item.get("note"), extra))
    return result


def provider_url(token: str) -> str:
    """freenode 订阅的纯节点列表地址，gist ID 与主流程共用。"""
    gid = os.environ.get("NODEPOOL_GIST_ID")
    state = ROOT / "data" / "gist.json"
    if not gid and state.exists():
        gid = json.loads(state.read_text(encoding="utf-8")).get("id")
    if not gid:
        raise SystemExit("找不到 freenode gist ID（NODEPOOL_GIST_ID 或 data/gist.json），可用 --provider 指定")
    owner = _gist(token, "GET", gid)["owner"]["login"]
    return f"https://gist.githubusercontent.com/{owner}/{gid}/raw/shadowrocket.yaml"


def _gist(token: str, method: str, gid: str | None = None, payload: dict | None = None) -> dict:
    url = f"{API}/{gid}" if gid else API
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    r = requests.request(method, url, headers=headers, json=payload, timeout=40)
    if r.status_code >= 300:
        raise SystemExit(f"GitHub API {method} 失败: HTTP {r.status_code}")
    return r.json()


def find_mihomo() -> Path | None:
    for name in ("mihomo.exe", "mihomo"):
        if (ROOT / "bin" / name).exists():
            return ROOT / "bin" / name
    return None


def test_chain(config_text: str, mihomo: Path, timeout: float = 60) -> str | None:
    """用本地 mihomo 跑链式配置，返回经链路访问到的出口 IP。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = yaml.safe_load(config_text)
    cfg["mixed-port"] = port
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.yaml"
        path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        proc = subprocess.Popen([str(mihomo), "-d", tmp, "-f", str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proxies = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=20).text.strip()
                    if ip:
                        return ip
                except requests.RequestException:
                    pass
                time.sleep(3)
            return None
        finally:
            proc.kill()
            proc.wait()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="生成 freenode → 落地代理 的链式 Clash 订阅链接")
    ap.add_argument("proxy", nargs="?", help="host:port:user:pass / socks5://... / http://...")
    ap.add_argument("--offlineip", action="store_true", help="从 OfflineIP 账号自动拉取所有生效中的静态 IP")
    ap.add_argument("--only", nargs="+", metavar="IP", help="配合 --offlineip，只处理这些 IP 或 proxy_id")
    ap.add_argument("--type", choices=["socks5", "http"], default="socks5", help="分段格式的协议，默认 socks5")
    ap.add_argument("--name", help="落地节点名，默认按 IP 归属自动生成")
    ap.add_argument("--provider", help="出海节点订阅地址（Clash 格式）或本地 Clash 配置文件（节点内嵌），默认用 freenode")
    ap.add_argument("--front", default="freenode", help="前置名称，用于组名和区分链接，如 良心云")
    ap.add_argument("--exclude", help="前置节点排除正则，如 '剩余流量|套餐到期'")
    ap.add_argument("--include", help="前置节点保留正则，只用能连上落地的线路，如 '新加坡高速|美国|英国|台湾'")
    ap.add_argument("--new", action="store_true", help="强制新建 gist，不复用旧链接")
    ap.add_argument("--no-test", action="store_true", help="跳过本地 mihomo 链路测试")
    ap.add_argument("--force", action="store_true", help="测试不通过也发布")
    ap.add_argument("--mihomo", type=Path, help="mihomo 内核路径，默认 bin/mihomo.exe")
    ap.add_argument("--dry-run", action="store_true", help="只生成并测试，不发布到 gist")
    args = ap.parse_args(argv)
    if bool(args.proxy) == args.offlineip:
        ap.error("要么给一个代理，要么用 --offlineip")

    if args.offlineip:
        jobs = offlineip_proxies(args.only)
        if not jobs:
            print("OfflineIP 账号里没有生效中的静态 IP")
            return 1
        print(f"OfflineIP: 找到 {len(jobs)} 个生效中的静态 IP")
    else:
        try:
            jobs = [(parse_proxy(args.proxy, args.type), None, [])]
        except ValueError as exc:
            print(f"输入有误: {exc}", file=sys.stderr)
            return 2
    token = load_token()
    provider = args.provider or provider_url(token)
    failed = 0
    for proxy, note, extra in jobs:
        print()
        failed += publish_one(args, token, provider, proxy, args.name or note, extra) != 0
    return 1 if failed else 0


def publish_one(args, token: str, provider: str, proxy: dict, name: str | None, extra: list[str]) -> int:
    key = f"{proxy['server']}:{proxy['port']}"
    if args.front != "freenode":
        key += f"|{args.front}"  # 换前置单独出一条链接，不覆盖 freenode 版
    info = lookup_ip(proxy["server"])
    label = "-".join(p for p in (info.get("country"), info.get("city")) if p) or "Proxy"
    name = name or f"{label}-{proxy['server']}"
    notes = describe(info) + extra
    content = build_config(proxy, name, provider, notes=notes, front=args.front,
                           exclude=args.exclude, include=args.include)
    print(f"落地节点: {name} ({proxy['type']})")
    for line in notes:
        print("  " + line)

    if not args.no_test:
        mihomo = args.mihomo or find_mihomo()
        if mihomo is None:
            print("未找到 bin/mihomo，跳过链路测试")
        else:
            print(f"本地链路测试中（拉取 {args.front} 节点并经链路访问外网）…")
            exit_ip = test_chain(content, mihomo)
            try:
                expected = socket.gethostbyname(proxy["server"])
            except OSError:
                expected = proxy["server"]
            if exit_ip == expected:
                print(f"[OK] 链路通过，出口 {exit_ip}")
            else:
                print(f"[FAIL] 链路未落地：出口 {exit_ip or '无'}，期望 {expected}")
                if not args.force:
                    print("未发布。检查账密/协议(--type)，或加 --force 强制发布", file=sys.stderr)
                    return 1

    if args.dry_run:
        print("--dry-run: 未发布")
        return 0
    state = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    filename = "chain.yaml"
    files = {filename: {"content": content}}
    gid = None if args.new else state.get(key)
    if gid:
        data = _gist(token, "PATCH", gid, {"files": files})
    else:
        data = _gist(token, "POST", payload={"description": f"chain sub {name} via {args.front}", "public": False, "files": files})
        gid = data["id"]
    state[key] = gid
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    owner = data["owner"]["login"]
    print("订阅链接（含明文账密，勿外传）:")
    print(f"https://gist.githubusercontent.com/{owner}/{gid}/raw/{filename}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
