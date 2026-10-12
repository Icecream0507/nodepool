from __future__ import annotations

from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import socket
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import requests
import yaml

from nodepool import mihomo
from nodepool.config import load_config

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / ("mihomo.exe" if sys.platform == "win32" else "mihomo")


class HttpGetTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(ROOT / "config.yaml")
        self.cfg["connectivity"].update(timeout_ms=2500, concurrency=32)
        self.proxies = [{"name": name, "type": "http", "server": "8.8.8.8", "port": 80}
                        for name in ("0089885980956613", "other")]

    def test_empty_inputs_do_not_start_a_core(self):
        with patch.object(mihomo, "Mihomo") as core:
            self.assertEqual(mihomo.test_http_get(EXE, [], self.cfg, {"https://example.com/": 200}), {})
            with self.assertRaises(ValueError):
                mihomo.test_http_get(EXE, self.proxies, self.cfg, {})
            with self.assertRaises(ValueError):
                mihomo.test_http_get(EXE, [], self.cfg, {})
            core.assert_not_called()

    def test_matching_config_independent_routes_fixed_sessions_and_cleanup(self):
        sessions = []
        targets = {"https://example.com/": 200, "https://example.org/": 204}

        class Session:
            def __init__(self):
                self.closed = False
                self.trust_env = True
                self.proxies = {}
                self.headers = {}
                self.calls = []
                sessions.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.closed = True

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs, self.trust_env, self.proxies.copy()))
                response = MagicMock(status_code=targets[url])
                response.__enter__.return_value = response
                return response

        original_executor = mihomo.cf.ThreadPoolExecutor
        with patch.object(mihomo, "Mihomo") as core, \
                patch.object(mihomo.requests, "Session", Session), \
                patch.object(mihomo.cf, "ThreadPoolExecutor", wraps=original_executor) as executor:
            result = mihomo.test_http_get(EXE, self.proxies, self.cfg, targets)
        self.assertEqual(result, {p["name"]: True for p in self.proxies})
        executor.assert_called_once_with(max_workers=8)
        text = core.call_args.args[1]
        document = yaml.safe_load(text)
        controller = core.call_args.args[2]
        expected = yaml.safe_load(mihomo.build_test_config(self.proxies, controller, self.cfg["mihomo"]["secret"], self.cfg))
        self.assertEqual(document["dns"], expected["dns"])
        self.assertEqual(document["ipv6"], expected["ipv6"])
        self.assertEqual(document["proxy-groups"], expected["proxy-groups"])
        listeners = document["listeners"]
        self.assertEqual(len(listeners), 2)
        self.assertTrue(all(item["type"] == "mixed" and item["listen"] == "127.0.0.1" for item in listeners))
        self.assertEqual(document["rules"][:2], [f"IN-NAME,http-get-{i},{p['name']}" for i, p in enumerate(self.proxies)])
        self.assertEqual(document["rules"][2:], expected["rules"])
        ports = [int(controller.rsplit(":", 1)[1])] + [item["port"] for item in listeners]
        self.assertEqual(len(set(ports)), 3)
        self.assertEqual(len(sessions), 2)
        self.assertTrue(all(session.closed for session in sessions))
        for session in sessions:
            self.assertEqual([call[0] for call in session.calls], list(targets))
            for _, kwargs, trust_env, routes in session.calls:
                self.assertEqual(kwargs, {"timeout": 2.5, "allow_redirects": False})
                self.assertFalse(trust_env)
                self.assertEqual(routes["http"], routes["https"])
        self.assertEqual(len({session.calls[0][3]["https"] for session in sessions}), 2)
        core.return_value.__exit__.assert_called_once()
        for port in ports:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))

    def test_redirect_error_status_or_connection_failure_rejects_node(self):
        for failure in (302, 403, requests.ConnectionError("offline")):
            with self.subTest(failure=str(failure)):
                session = MagicMock()
                session.__enter__.return_value = session
                first = MagicMock(status_code=200)
                first.__enter__.return_value = first
                if isinstance(failure, Exception):
                    session.get.side_effect = [first, failure]
                else:
                    second = MagicMock(status_code=failure)
                    second.__enter__.return_value = second
                    session.get.side_effect = [first, second]
                with patch.object(mihomo, "Mihomo") as core, \
                        patch.object(mihomo.requests, "Session", return_value=session):
                    result = mihomo.test_http_get(EXE, self.proxies[:1], self.cfg,
                                                   {"https://example.com/": 200, "https://example.org/": 200})
                self.assertEqual(result, {self.proxies[0]["name"]: False})
                session.__exit__.assert_called_once()
                core.return_value.__exit__.assert_called_once()


@unittest.skipUnless(EXE.exists(), "mihomo binary not available")
class NativeHttpGetTests(unittest.TestCase):
    def test_head_challenge_get_success_independent_routes_and_core_cleanup(self):
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.methods.append(self.command)
                time.sleep(0.02)
                status = 403 if self.command == "HEAD" else self.server.get_status
                self.send_response(status)
                self.send_header("Content-Length", "0")
                if status == 403:
                    self.send_header("cf-mitigated", "challenge")
                self.end_headers()

            do_HEAD = do_GET

            def log_message(self, *args):
                pass

        class Upstream(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                try:
                    with socket.create_connection(self.server.target, timeout=2) as remote:
                        self.send_response(200)
                        self.end_headers()
                        while True:
                            ready, _, _ = select.select([self.connection, remote], [], [], 2)
                            if not ready:
                                break
                            for incoming in ready:
                                data = incoming.recv(65536)
                                if not data:
                                    return
                                (remote if incoming is self.connection else self.connection).sendall(data)
                except OSError:
                    pass
                finally:
                    self.close_connection = True

            def log_message(self, *args):
                pass

        with ExitStack() as stack:
            targets, proxies = [], []
            for name, status in (("get-ok", 200), ("get-forbidden", 403)):
                target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
                target.methods, target.get_status = [], status
                upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
                upstream.target = ("127.0.0.1", target.server_port)
                for server in (target, upstream):
                    worker = threading.Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    stack.callback(worker.join, timeout=5)
                    stack.callback(server.server_close)
                    stack.callback(server.shutdown)
                targets.append(target)
                proxies.append({"name": name, "type": "http", "server": "127.0.0.1", "port": upstream.server_port})
            cfg = load_config(ROOT / "config.yaml")
            cfg["connectivity"].update(timeout_ms=2000, concurrency=2, rounds=1,
                                       test_url="http://get-only.invalid/page", verification_url=None,
                                       expected_status=200)
            with socket.socket() as allocation:
                allocation.bind(("127.0.0.1", 0))
                cfg["mihomo"]["controller"] = f"127.0.0.1:{allocation.getsockname()[1]}"
            cores = []
            listener_ports = []
            original_core = mihomo.Mihomo

            def track_core(exe, text, *args):
                core = original_core(exe, text, *args)
                cores.append(core)
                listener_ports.extend(item["port"] for item in yaml.safe_load(text).get("listeners", []))
                return core

            with patch.object(mihomo, "Mihomo", side_effect=track_core), \
                    patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
                                             "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}):
                native = mihomo.test_connectivity(EXE, proxies, cfg)
                actual = mihomo.test_http_get(EXE, proxies, cfg, {cfg["connectivity"]["test_url"]: 200})
            self.assertEqual(native, {"get-ok": [None], "get-forbidden": [None]})
            self.assertEqual(actual, {"get-ok": True, "get-forbidden": False})
            self.assertTrue(all("HEAD" in target.methods and "GET" in target.methods for target in targets))
            self.assertEqual(len(listener_ports), 2)
            self.assertEqual(len(set(listener_ports)), 2)
            for core in cores:
                self.assertIsNone(core._proc)
                self.assertFalse(Path(core._dir).exists())
            for port in listener_ports:
                with socket.socket() as sock:
                    sock.settimeout(0.2)
                    self.assertNotEqual(sock.connect_ex(("127.0.0.1", port)), 0)


if __name__ == "__main__":
    unittest.main()
