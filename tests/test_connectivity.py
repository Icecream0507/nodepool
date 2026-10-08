from __future__ import annotations

import copy
import base64
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import requests
import yaml

from nodepool import mihomo
from nodepool.config import (DEFAULT_TEST_URL, DEFAULT_VERIFICATION_URL,
                             LEGACY_TEST_URL, load_config, validate_config)

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / ("mihomo.exe" if sys.platform == "win32" else "mihomo")


class ConnectivityConfigTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(ROOT / "config.yaml")

    def load_variant(self, connectivity):
        cfg = copy.deepcopy(self.cfg)
        cfg["connectivity"] = connectivity
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "config.yaml"
            path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
            return load_config(path)

    def test_legacy_builtin_probe_upgrades_to_two_https_targets(self):
        cc = self.cfg["connectivity"].copy()
        cc.update(test_url=LEGACY_TEST_URL)
        cc.pop("verification_url", None)
        cc.pop("expected_status", None)
        actual = self.load_variant(cc)["connectivity"]
        self.assertEqual(actual["test_url"], DEFAULT_TEST_URL)
        self.assertEqual(actual["verification_url"], DEFAULT_VERIFICATION_URL)
        self.assertEqual(actual["expected_status"], 204)

    def test_custom_legacy_probe_keeps_its_url_and_status_behavior(self):
        cc = self.cfg["connectivity"].copy()
        cc.update(test_url="https://health.example.test/probe", rounds=1, min_pass=1)
        cc.pop("verification_url", None)
        cc.pop("expected_status", None)
        actual = self.load_variant(cc)["connectivity"]
        self.assertEqual(actual["test_url"], cc["test_url"])
        self.assertIsNone(actual["verification_url"])
        self.assertIsNone(actual["expected_status"])

    def test_explicit_custom_status_and_disabled_second_target_are_retained(self):
        cc = self.cfg["connectivity"].copy()
        cc.update(test_url="https://health.example.test/", verification_url=None,
                  expected_status=200, rounds=1, min_pass=1)
        self.assertEqual(self.load_variant(cc)["connectivity"], cc)

    def test_two_targets_cannot_pass_if_only_one_is_reachable(self):
        for rounds, min_pass in ((4, 2), (3, 2), (1, 1)):
            cfg = copy.deepcopy(self.cfg)
            cfg["connectivity"]["verification_url"] = DEFAULT_VERIFICATION_URL
            cfg["connectivity"].update(rounds=rounds, min_pass=min_pass)
            with self.subTest(rounds=rounds), self.assertRaises(ValueError):
                validate_config(cfg)

    def test_cloud_gate_and_pinned_version_require_explicit_valid_values(self):
        for section, key, value in (("publish", "client_health_required", "false"),
                                    ("mihomo", "version", "latest"),
                                    ("mihomo", "version", "v1.19.11/other")):
            cfg = copy.deepcopy(self.cfg)
            cfg[section][key] = value
            with self.subTest(section=section, value=value), self.assertRaises(ValueError):
                validate_config(cfg)

    def test_invalid_status_url_or_api_timeout_is_rejected(self):
        for key, value in (("expected_status", True), ("expected_status", 99),
                           ("expected_status", 600), ("expected_status", 204.5),
                           ("verification_url", []), ("verification_url", "ftp://example.test/"),
                           ("verification_url", DEFAULT_TEST_URL), ("timeout_ms", 32768)):
            cfg = copy.deepcopy(self.cfg)
            cfg["connectivity"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_config(cfg)


class DelayApiTests(unittest.TestCase):
    def make_api(self, value=15, status_code=200):
        api = mihomo.Mihomo.__new__(mihomo.Mihomo)
        api.base = "http://127.0.0.1:12345"
        api.sess = Mock()
        api._delay_response = Mock(status_code=status_code)
        api._delay_response.json.return_value = {"delay": value}
        api._state_response = Mock(status_code=200)
        api._state_response.json.return_value = {
            "extra": {DEFAULT_TEST_URL: {"alive": True, "history": [{"delay": 15}]}}}
        api.sess.get.side_effect = [api._delay_response, api._state_response]
        return api

    def test_expected_status_is_passed_to_core_and_name_is_escaped(self):
        api = self.make_api()
        self.assertEqual(api.delay("node/a b", DEFAULT_TEST_URL, 5000, 204), 15)
        args, kwargs = api.sess.get.call_args_list[0]
        self.assertEqual(args[0], api.base + "/proxies/node%2Fa%20b/delay")
        self.assertEqual(kwargs["params"], {"timeout": 5000, "url": DEFAULT_TEST_URL, "expected": "204"})

    def test_custom_legacy_status_does_not_send_expected_parameter(self):
        api = self.make_api()
        self.assertEqual(api.delay("a", DEFAULT_TEST_URL, 5000), 15)
        self.assertNotIn("expected", api.sess.get.call_args.kwargs["params"])

    def test_invalid_delay_values_or_wrong_status_are_failures(self):
        for value in (True, 0, -1, "15", None, 1.5):
            with self.subTest(value=value):
                self.assertIsNone(self.make_api(value).delay("a", DEFAULT_TEST_URL, 5000, 204))
        self.assertIsNone(self.make_api(status_code=503).delay("a", DEFAULT_TEST_URL, 5000, 204))
        api = self.make_api()
        api._delay_response.json.return_value = []
        self.assertIsNone(api.delay("a", DEFAULT_TEST_URL, 5000, 204))
        api.sess.get.side_effect = requests.Timeout()
        self.assertIsNone(api.delay("a", DEFAULT_TEST_URL, 5000, 204))

    def test_positive_delay_with_wrong_status_or_missing_state_is_rejected(self):
        for detail in ({}, {"extra": {DEFAULT_TEST_URL: {"alive": False, "history": [{"delay": 0}]}}},
                       {"extra": {DEFAULT_TEST_URL: {"alive": True, "history": []}}}):
            api = self.make_api()
            api._state_response.json.return_value = detail
            with self.subTest(detail=detail):
                self.assertIsNone(api.delay("a", DEFAULT_TEST_URL, 5000, 204))


class PinnedCoreTests(unittest.TestCase):
    def cached_core(self, root):
        path = root / "bin" / ("mihomo.exe" if sys.platform == "win32" else "mihomo")
        path.parent.mkdir()
        path.write_bytes(b"x" * 1_000_001)
        return path

    def test_matching_cached_core_is_reused_without_download(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = self.cached_core(root)
            with patch.object(mihomo.subprocess, "run", return_value=Mock(stdout=b"Mihomo Meta v1.19.11 windows amd64")), \
                    patch.object(mihomo, "get_with_retry") as download:
                self.assertEqual(mihomo.ensure_binary(root, Mock(), "v1.19.11"), path)
                download.assert_not_called()

    def test_mismatched_cache_requires_pinned_release_and_survives_download_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = self.cached_core(root)
            with patch.object(mihomo.subprocess, "run", return_value=Mock(stdout=b"Mihomo Meta v1.19.32 linux amd64")), \
                    patch.object(mihomo, "get_with_retry", return_value=Mock(status_code=404)) as download, \
                    self.assertRaises(RuntimeError):
                mihomo.ensure_binary(root, Mock(), "v1.19.11")
            self.assertEqual(download.call_args.args[1], "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.11")
            self.assertEqual(path.stat().st_size, 1_000_001)


class ConnectivityRoundTests(unittest.TestCase):
    def test_optional_second_target_uses_native_api_and_rejects_partial_reachability(self):
        cfg = load_config(ROOT / "config.yaml")
        cfg["connectivity"]["verification_url"] = DEFAULT_VERIFICATION_URL
        api = Mock()
        api.delay.side_effect = lambda name, url, timeout, status: 20 if name == "both" or url == DEFAULT_TEST_URL else None
        with patch.object(mihomo, "Mihomo") as process:
            process.return_value.__enter__.return_value = api
            results = mihomo.test_connectivity(Path("unused"), [{"name": "one"}, {"name": "both"}], cfg)
        self.assertEqual(results["one"], [20, None, 20, None])
        self.assertEqual(results["both"], [20] * 4)
        self.assertTrue(all(call.args[2:] == (5000, 204) for call in api.delay.call_args_list))

    def test_default_repeats_same_native_clash_delay_test_four_times(self):
        cfg = load_config(ROOT / "config.yaml")
        api = Mock()
        api.delay.side_effect = [20, None, 30, 25]
        with patch.object(mihomo, "Mihomo") as process:
            process.return_value.__enter__.return_value = api
            result = mihomo.test_connectivity(Path("unused"), [{"name": "one"}], cfg)
        self.assertEqual(result["one"], [20, None, 30, 25])
        self.assertEqual(api.delay.call_count, 4)
        self.assertTrue(all(call.args == ("one", DEFAULT_TEST_URL, 5000, 204) for call in api.delay.call_args_list))

    def test_bounded_batches_share_subscription_dns_and_have_no_probe_listeners(self):
        from nodepool.output import build_dns_config
        cfg = load_config(ROOT / "config.yaml")
        proxies = [{"name": f"node-{n}"} for n in range(65)]
        with patch.object(mihomo, "Mihomo") as process:
            process.return_value.__enter__.return_value.delay.return_value = 10
            result = mihomo.test_connectivity(Path("unused"), proxies, cfg)
        self.assertEqual(len(result), 65)
        self.assertTrue(all(value == [10] * 4 for value in result.values()))
        configs = [yaml.safe_load(call.args[1]) for call in process.call_args_list]
        self.assertEqual([len(c["proxies"]) for c in configs], [64, 1])
        for config in configs:
            self.assertNotIn("listeners", config)
            self.assertEqual(config["dns"], build_dns_config(cfg["output"]["group_select"]))
            self.assertTrue(config["unified-delay"])
            self.assertTrue(config["ipv6"])
            auto = config["proxy-groups"][1]
            self.assertEqual(auto["interval"], 0)
            self.assertTrue(auto["lazy"])

    def test_changed_core_version_invalidates_previous_connectivity_evidence(self):
        from nodepool.pool import connectivity_policy
        cfg = load_config(ROOT / "config.yaml")
        current = cfg["connectivity"]
        self.assertNotEqual(connectivity_policy(current), connectivity_policy({**current, "core_version": "v1.19.32"}))


@unittest.skipUnless(EXE.exists(), "mihomo binary is not installed")
class NativeStatusTests(unittest.TestCase):
    def test_numeric_looking_names_survive_config_checks_and_process_rewrite(self):
        names = ("0089885980956613", "0123456789", "1e3", "1.0", ".NaN", "true")
        proxies = [{"name": name, "type": "http", "server": "127.0.0.1", "port": 9,
                    "username": "00089", "password": "0089885980956613"} for name in names]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            controller = f"127.0.0.1:{sock.getsockname()[1]}"
        text, _ = mihomo.build_purity_config(proxies, controller, "unused", 26000)
        mihomo.check_config(EXE, text)
        # Avoid opening the fixed listener ports for this API-only check.
        document = yaml.safe_load(text)
        document["listeners"] = []
        document["rules"] = ["MATCH,DIRECT"]
        with mihomo.Mihomo(EXE, yaml.safe_dump(document), controller, "unused") as api:
            response = api.sess.get(api.base + "/proxies", timeout=3)
            response.raise_for_status()
            self.assertTrue(set(names).issubset(response.json()["proxies"]))

    def test_native_api_routes_each_node_and_rejects_error_pages_and_redirects(self):
        auth_headers = []
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.paths.append(self.path)
                self.server.methods.append(self.command)
                time.sleep(0.02)
                status = 302 if self.path == "/redirect" else self.server.status
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/204")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_HEAD = do_GET

            def log_message(self, *args):
                pass

        class Upstream(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                auth_headers.append(self.headers.get("Proxy-Authorization"))
                # The target name deliberately does not resolve locally. Only
                # the selected upstream can deliver its test response.
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
            servers = []
            proxies = []
            good_name, bad_name = "0089885980956613", "1e3"
            for name, status in ((good_name, 204), (bad_name, 200)):
                target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
                target.paths, target.methods, target.status = [], [], status
                upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
                upstream.target = ("127.0.0.1", target.server_port)
                for server in (target, upstream):
                    worker = threading.Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    stack.callback(worker.join, timeout=5)
                    stack.callback(server.server_close)
                    stack.callback(server.shutdown)
                servers.append(target)
                proxies.append({"name": name, "type": "http", "server": "127.0.0.1",
                                "port": upstream.server_port, "username": "00089",
                                "password": "0089885980956613"})
            cfg = load_config(ROOT / "config.yaml")
            with socket.socket() as controller:
                controller.bind(("127.0.0.1", 0))
                controller_port = controller.getsockname()[1]
                cfg["mihomo"]["controller"] = f"127.0.0.1:{controller_port}"
            for _ in range(100):
                with socket.socket() as first:
                    first.bind(("127.0.0.1", 0))
                    base_port = first.getsockname()[1]
                    if base_port == 65535 or base_port <= controller_port < base_port + 2:
                        continue
                    try:
                        with socket.socket() as second:
                            second.bind(("127.0.0.1", base_port + 1))
                    except OSError:
                        continue
                    break
            else:
                self.fail("could not reserve adjacent local test ports")
            cfg["mihomo"]["base_listen_port"] = base_port
            cfg["connectivity"].update(test_url="http://health.invalid/204", verification_url=None,
                                       expected_status=204, rounds=2, min_pass=2,
                                       timeout_ms=1000, concurrency=2)
            with patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:1",
                                           "HTTPS_PROXY": "http://127.0.0.1:1",
                                           "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}):
                results = mihomo.test_connectivity(EXE, proxies, cfg)
                self.assertTrue(all(delay is not None for delay in results[good_name]))
                self.assertEqual(results[bad_name], [None, None])
                cfg["connectivity"]["test_url"] = "http://health.invalid/redirect"
                redirects = mihomo.test_connectivity(EXE, proxies[:1], cfg)
                self.assertEqual(redirects[good_name], [None, None])
            self.assertGreaterEqual(servers[0].paths.count("/204"), 2)
            self.assertGreaterEqual(servers[0].paths.count("/redirect"), 2)
            self.assertEqual(set(servers[0].paths), {"/204", "/redirect"})
            self.assertGreaterEqual(servers[1].paths.count("/204"), 2)
            self.assertEqual(set(servers[1].paths), {"/204"})
            self.assertEqual(set(servers[0].methods + servers[1].methods), {"HEAD"})
            expected_auth = "Basic " + base64.b64encode(b"00089:0089885980956613").decode("ascii")
            self.assertGreaterEqual(len(auth_headers), 6)
            self.assertTrue(all(header == expected_auth for header in auth_headers))

    def test_http_error_page_cannot_pass_expected_204(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Ensure the core reports a positive millisecond delay.
                time.sleep(0.02)
                self.send_response(204 if self.path == "/204" else 200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_HEAD = do_GET

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with socket.socket() as port:
                port.bind(("127.0.0.1", 0))
                controller = f"127.0.0.1:{port.getsockname()[1]}"
            text = mihomo.build_test_config([], controller, "unused")
            with mihomo.Mihomo(EXE, text, controller, "unused") as api:
                url = f"http://127.0.0.1:{server.server_port}"
                self.assertIsNone(api.delay("DIRECT", url + "/200", 1000, 204))
                self.assertIsNotNone(api.delay("DIRECT", url + "/204", 1000, 204))
                self.assertIsNotNone(api.delay("DIRECT", url + "/200", 1000))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
