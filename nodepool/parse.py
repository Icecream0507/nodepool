"""把各种来源解析成 mihomo 的 proxy dict。

三种来源：
  1. 分享链接 URI（vless:// vmess:// trojan:// ss:// hysteria2:// tuic:// anytls://）
  2. base64 订阅块（解码后又是 URI 列表）
  3. Clash / mihomo YAML（已含 proxies 列表，直接提取）
"""
from __future__ import annotations

import json
import re
import uuid as uuid_module
from urllib.parse import parse_qs, unquote, urlparse

import yaml

from .util import is_bogus_host, log, try_b64decode

# mihomo 支持的协议类型（校验用）
KNOWN_TYPES = {"vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2",
               "tuic", "anytls", "wireguard", "socks5", "http", "snell", "mieru"}

URI_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|anytls)://[^\s\"'<>`]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------- 小工具

def _b64_to_text(s: str) -> str:
    import base64
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def _qget(q: dict, *keys, default=""):
    for k in keys:
        if k in q and q[k]:
            v = q[k][0] if isinstance(q[k], list) else q[k]
            if v != "":
                return v
    return default


def _truthy(v) -> bool:
    return str(v).lower() in ("1", "true", "yes", "on")


def _name(fragment: str, fallback: str) -> str:
    n = unquote(fragment).strip() if fragment else ""
    return n or fallback


def _transport_opts(p: dict, net: str, q: dict, *, ws_path_key="path", host_key="host",
                    grpc_key="serviceName"):
    """根据传输类型补 ws-opts / grpc-opts / h2-opts。"""
    net = (net or "tcp").lower()
    if net in ("ws", "websocket"):
        p["network"] = "ws"
        path = _qget(q, ws_path_key, "path", default="/")
        host = _qget(q, host_key, "host")
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        svc = _qget(q, grpc_key, "serviceName", "servicename")
        p["grpc-opts"] = {"grpc-service-name": svc} if svc else {}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        host = _qget(q, host_key, "host")
        path = _qget(q, ws_path_key, "path", default="/")
        opts = {"path": path or "/"}
        if host:
            opts["host"] = [host]
        p["h2-opts"] = opts
    else:
        p["network"] = "tcp"


# ---------------------------------------------------------------- 各协议 URI

def parse_vless(uri: str) -> dict | None:
    u = urlparse(uri)
    q = parse_qs(u.query)
    uuid = unquote(u.username or "")
    host = (u.hostname or "")
    port = u.port
    if not uuid or not host or not port:
        return None
    p: dict = {"name": _name(u.fragment, f"vless-{host}"), "type": "vless",
               "server": host, "port": int(port), "uuid": uuid, "udp": True}
    security = _qget(q, "security").lower()
    sni = _qget(q, "sni", "servername", "peer")
    fp = _qget(q, "fp", "client-fingerprint")
    flow = _qget(q, "flow")
    if flow:
        p["flow"] = flow
    if fp:
        p["client-fingerprint"] = fp
    if security in ("tls", "xtls"):
        p["tls"] = True
        if sni:
            p["servername"] = sni
        alpn = _qget(q, "alpn")
        if alpn:
            p["alpn"] = [a for a in alpn.split(",") if a]
        if _truthy(_qget(q, "allowInsecure", "insecure")):
            p["skip-cert-verify"] = True
    elif security == "reality":
        p["tls"] = True
        if sni:
            p["servername"] = sni
        pbk = _qget(q, "pbk", "publicKey", "public-key")
        sid = _qget(q, "sid", "shortId", "short-id")
        ro = {}
        if pbk:
            ro["public-key"] = pbk
        # short-id 必须是 16 进制且不超过 16 字符，否则 mihomo 拒绝解析——非法就丢弃
        if sid:
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", sid):
                return None
            ro["short-id"] = sid
        if not pbk:
            return None
        if ro:
            p["reality-opts"] = ro
        if not fp:
            p["client-fingerprint"] = "chrome"
    net = _qget(q, "type", "network", default="tcp")
    _transport_opts(p, net, q)
    return p


def parse_vmess(uri: str) -> dict | None:
    body = uri[8:]  # 去掉 vmess://
    # 绝大多数是 base64(json)
    try:
        j = json.loads(_b64_to_text(body))
    except Exception:
        # 少数是 vmess://auto 之类非标准，放弃
        return None
    host = str(j.get("add", "")).strip()
    port = j.get("port")
    uuid = str(j.get("id", "")).strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not host or not uuid or not port:
        return None
    net = str(j.get("net", "tcp")).lower()
    p: dict = {"name": str(j.get("ps") or f"vmess-{host}"), "type": "vmess",
               "server": host, "port": port, "uuid": uuid,
               "alterId": int(j.get("aid", 0) or 0),
               "cipher": str(j.get("scy") or "auto"), "udp": True}
    tls = str(j.get("tls", "")).lower()
    if tls in ("tls", "reality", "true", "1"):
        p["tls"] = True
        sni = j.get("sni") or j.get("host")
        if sni:
            p["servername"] = str(sni)
        if j.get("alpn"):
            p["alpn"] = [a for a in str(j["alpn"]).split(",") if a]
        if _truthy(j.get("skip-cert-verify") or j.get("allowInsecure")):
            p["skip-cert-verify"] = True
    if net in ("ws", "websocket"):
        p["network"] = "ws"
        opts = {"path": str(j.get("path") or "/")}
        if j.get("host"):
            opts["headers"] = {"Host": str(j["host"])}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": str(j.get("path") or "")}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        opts = {"path": str(j.get("path") or "/")}
        if j.get("host"):
            opts["host"] = [str(j["host"])]
        p["h2-opts"] = opts
    else:
        p["network"] = "tcp"
    return p


def parse_trojan(uri: str) -> dict | None:
    u = urlparse(uri)
    q = parse_qs(u.query)
    pwd = unquote(u.username or "")
    host = u.hostname or ""
    port = u.port
    if not pwd or not host or not port:
        return None
    p: dict = {"name": _name(u.fragment, f"trojan-{host}"), "type": "trojan",
               "server": host, "port": int(port), "password": pwd, "udp": True}
    sni = _qget(q, "sni", "peer", "servername")
    if sni:
        p["sni"] = sni
    alpn = _qget(q, "alpn")
    if alpn:
        p["alpn"] = [a for a in alpn.split(",") if a]
    if _truthy(_qget(q, "allowInsecure", "insecure")):
        p["skip-cert-verify"] = True
    net = _qget(q, "type", "network", default="tcp")
    if net and net.lower() != "tcp":
        _transport_opts(p, net, q)
    return p


def parse_ss(uri: str) -> dict | None:
    body = uri[5:]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = _name(frag, "")
    body, _, query = body.partition("?")
    q = parse_qs(query)
    # 形式 A: base64(method:pass)@host:port
    # 形式 B: base64(method:pass@host:port)
    host = port = method = password = None
    if "@" in body:
        userinfo, hostpart = body.rsplit("@", 1)
        plain_userinfo = ":" in userinfo
        # userinfo 可能是 base64
        if ":" not in userinfo:
            dec = try_b64decode(userinfo) or ""
            if ":" in dec:
                userinfo = dec
            else:
                try:
                    userinfo = _b64_to_text(userinfo)
                except Exception:
                    return None
        if ":" not in userinfo:
            return None
        method, password = (unquote(userinfo) if plain_userinfo else userinfo).split(":", 1)
        hostpart = hostpart.split("/")[0].split("?")[0]
        if ":" not in hostpart:
            return None
        host, port = hostpart.rsplit(":", 1)
    else:
        try:
            dec = _b64_to_text(body)
        except Exception:
            return None
        if "@" not in dec or ":" not in dec:
            return None
        userinfo, hostpart = dec.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostpart.rsplit(":", 1)
    host = (host or "").strip("[]")
    try:
        port = int(str(port).strip())
    except ValueError:
        return None
    if not host or not method or password is None:
        return None
    p = {"name": name or f"ss-{host}", "type": "ss", "server": host,
         "port": port, "cipher": method.strip(), "password": password, "udp": True}
    plugin = _qget(q, "plugin")
    if plugin:
        pieces = plugin.split(";")
        opts = dict(piece.split("=", 1) if "=" in piece else (piece, True) for piece in pieces[1:] if piece)
        if pieces[0] in ("obfs-local", "simple-obfs"):
            p["plugin"] = "obfs"
            p["plugin-opts"] = {"mode": opts.get("obfs", "http"), "host": opts.get("obfs-host", "")}
        elif pieces[0] == "v2ray-plugin":
            p["plugin"] = "v2ray-plugin"
            p["plugin-opts"] = {"mode": opts.get("mode", "websocket"),
                                "tls": "tls" in opts, "host": opts.get("host", ""), "path": opts.get("path", "/")}
        else:
            return None
    return p


def parse_ssr(uri: str) -> dict | None:
    body = _b64_to_text(uri.split("://", 1)[1])
    main, _, query = body.partition("/?")
    host, port, protocol, cipher, obfs, password = main.rsplit(":", 5)
    q = parse_qs(query)
    p = {"name": _b64_to_text(_qget(q, "remarks")) or f"ssr-{host}",
         "type": "ssr", "server": host.strip("[]"), "port": int(port),
         "protocol": protocol, "cipher": cipher, "obfs": obfs,
         "password": _b64_to_text(password), "udp": True}
    for key, target in (("protoparam", "protocol-param"), ("obfsparam", "obfs-param")):
        if _qget(q, key):
            p[target] = _b64_to_text(_qget(q, key))
    return p


def parse_hysteria(uri: str) -> dict | None:
    u = urlparse(uri)
    q = parse_qs(u.query)
    if not u.hostname:
        return None
    p = {"name": _name(u.fragment, f"hy-{u.hostname}"), "type": "hysteria",
         "server": u.hostname, "port": u.port or 443,
         "auth-str": _qget(q, "auth") or unquote(u.username or ""),
         "up": _qget(q, "upmbps", "up", default="10"),
         "down": _qget(q, "downmbps", "down", default="50")}
    if _qget(q, "peer", "sni"):
        p["sni"] = _qget(q, "peer", "sni")
    if _truthy(_qget(q, "insecure")):
        p["skip-cert-verify"] = True
    if _qget(q, "obfsParam", "obfs"):
        p["obfs"] = _qget(q, "obfsParam", "obfs")
    return p


def parse_hysteria2(uri: str) -> dict | None:
    u = urlparse(uri)
    q = parse_qs(u.query)
    host = u.hostname or ""
    port = u.port or 443
    pwd = unquote(u.username or "")
    if u.password:  # user:pass@ 形式
        pwd = unquote(u.username + ":" + u.password)
    if not host or not pwd:
        return None
    p: dict = {"name": _name(u.fragment, f"hy2-{host}"), "type": "hysteria2",
               "server": host, "port": int(port), "password": pwd}
    sni = _qget(q, "sni", "peer")
    if sni:
        p["sni"] = sni
    if _truthy(_qget(q, "insecure", "allowInsecure")):
        p["skip-cert-verify"] = True
    obfs = _qget(q, "obfs")
    if obfs:
        p["obfs"] = obfs
        op = _qget(q, "obfs-password", "obfsParam")
        if op:
            p["obfs-password"] = op
    alpn = _qget(q, "alpn")
    if alpn:
        p["alpn"] = [a for a in alpn.split(",") if a]
    return p


def parse_tuic(uri: str) -> dict | None:
    u = urlparse(uri)
    q = parse_qs(u.query)
    host = u.hostname or ""
    port = u.port or 443
    if not host or not u.username:
        return None
    p: dict = {"name": _name(u.fragment, f"tuic-{host}"), "type": "tuic",
               "server": host, "port": int(port),
               "uuid": unquote(u.username), "password": unquote(u.password or "")}
    sni = _qget(q, "sni", "peer")
    if sni:
        p["sni"] = sni
    alpn = _qget(q, "alpn")
    p["alpn"] = [a for a in alpn.split(",") if a] if alpn else ["h3"]
    cc = _qget(q, "congestion_control", "congestion-controller")
    if cc:
        p["congestion-controller"] = cc
    udp = _qget(q, "udp_relay_mode", "udp-relay-mode")
    if udp:
        p["udp-relay-mode"] = udp
    if _truthy(_qget(q, "allow_insecure", "insecure")):
        p["skip-cert-verify"] = True
    return p


def parse_anytls(uri: str) -> dict | None:
    u = urlparse(uri)
    q = parse_qs(u.query)
    host = u.hostname or ""
    port = u.port or 443
    pwd = unquote(u.username or "")
    if not host or not pwd:
        return None
    p: dict = {"name": _name(u.fragment, f"anytls-{host}"), "type": "anytls",
               "server": host, "port": int(port), "password": pwd, "udp": True}
    sni = _qget(q, "sni", "servername", "peer")
    if sni:
        p["sni"] = sni
    if (_truthy(_qget(q, "insecure", "allowInsecure"))
            or _qget(q, "tls-verification").lower() in ("false", "0", "no", "off")):
        p["skip-cert-verify"] = True
    return p


_DISPATCH = {
    "vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan,
    "ss": parse_ss, "ssr": parse_ssr, "hysteria": parse_hysteria,
    "hysteria2": parse_hysteria2, "hy2": parse_hysteria2,
    "tuic": parse_tuic, "anytls": parse_anytls,
}


def parse_uri(uri: str) -> dict | None:
    scheme = uri.split("://", 1)[0].lower()
    fn = _DISPATCH.get(scheme)
    if not fn:
        return None
    try:
        p = fn(uri.strip())
        return p if validate(p) else None
    except Exception:
        return None


# ---------------------------------------------------------------- YAML 提取

# YAML 里 proxies 可能带客户端专有键，剔除后交给 mihomo
_PASS_KEYS = None  # 不做白名单，整体透传（mihomo 对多数键宽容），只做基本校验


def lift_yaml_proxies(text: str) -> list[dict]:
    """从一段 Clash/mihomo YAML 中提取 proxies 列表。"""
    try:
        doc = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies")
    if not isinstance(proxies, list):
        return []
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        try:
            p = _normalize_yaml_proxy(p)
            if validate(p):
                out.append(p)
        except (TypeError, ValueError, OverflowError):
            continue
    return out


def _normalize_yaml_proxy(p: dict) -> dict:
    p = dict(p)
    # 常见字符串化字段修正
    for k in ("port", "alterId"):
        if k in p and isinstance(p[k], str) and p[k].strip().lstrip("-").isdigit():
            p[k] = int(p[k])
    if "name" in p and not isinstance(p["name"], str):
        p["name"] = str(p["name"])
    return p


# ---------------------------------------------------------------- 校验

def validate(p: dict | None) -> bool:
    if not isinstance(p, dict):
        return False
    t = p.get("type")
    if not isinstance(t, str) or t not in KNOWN_TYPES:
        return False
    host = p.get("server")
    if not isinstance(host, str) or not host.strip() or any(c.isspace() for c in host):
        return False
    if is_bogus_host(host):
        return False
    try:
        if isinstance(p.get("port"), bool):
            return False
        port = int(p.get("port"))
    except (TypeError, ValueError):
        return False
    if not (0 < port < 65536):
        return False
    # 占位 uuid / 空凭据
    if t in ("vless", "vmess", "tuic") and not p.get("uuid"):
        return False
    if t in ("vless", "vmess", "tuic"):
        try:
            p["uuid"] = str(uuid_module.UUID(str(p["uuid"])))
        except ValueError:
            # 部分内核支持非标准用户 ID，交由 mihomo 实际校验。
            pass
    if t == "vless" and str(p.get("uuid")).replace("-", "") == "0" * 32:
        return False
    if t in ("trojan", "ss", "ssr", "hysteria2", "anytls") and not (p.get("password") is not None and
                                                             str(p.get("password")) != ""):
        return False
    if p.get("dialer-proxy"):
        return False  # 单节点订阅不能保留依赖原订阅其它代理名称的链式节点
    p["port"] = port
    if not p.get("name"):
        p["name"] = f"{t}-{host}"
    return True


# ---------------------------------------------------------------- 顶层入口

def extract_from_text(text: str) -> list[dict]:
    """对单个 gist 文件内容，尽力提取出所有 proxy dict。"""
    out: list[dict] = []

    # 1) 看起来是 Clash/mihomo YAML（含 proxies:）
    if re.search(r"^\s*proxies\s*:", text, re.MULTILINE):
        lifted = lift_yaml_proxies(text)
        out.extend(lifted)
        # YAML 里一般就是全部节点，但仍继续扫 URI 以防混排

    # 2) 直接出现的 URI
    for m in URI_RE.findall(text):
        p = parse_uri(m)
        if p:
            out.append(p)

    # 3) 整段 / 分段 base64（订阅常见）
    stripped = text.strip()
    if "://" not in stripped[:200]:  # 开头不像明文 URI，试着整体解码
        dec = try_b64decode(stripped)
        if dec:
            for m in URI_RE.findall(dec):
                p = parse_uri(m)
                if p:
                    out.append(p)
    return out
