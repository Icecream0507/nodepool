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
            cfg["connectivity"].update(rounds=rounds, min_pass=min_pass)
            with self.subTest(rounds=rounds), self.assertRaises(ValueError):
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


class ConnectivityRoundTests(unittest.TestCase):
    def test_default_rounds_reject_a_node_that_only_reaches_one_target(self):
        cfg = load_config(ROOT / "config.yaml")
        calls = []

        def request(port, url, timeout_ms, expected_status):
            name = "one" if port == cfg["mihomo"]["base_listen_port"] else "both"
            calls.append((name, url, expected_status))
            return 20 if name == "both" or url == cfg["connectivity"]["test_url"] else None

        api = Mock()
        api.delay.side_effect = AssertionError("the delay API is not an HTTP proof")
        with patch.object(mihomo, "Mihomo") as process, \
                patch.object(mihomo, "_connectivity_get", side_effect=request), \
                patch.object(mihomo.socket, "socket"):
            process.return_value.__enter__.return_value = api
            results = mihomo.test_connectivity(Path("unused"), [{"name": "one"}, {"name": "both"}], cfg)
        self.assertEqual(results["one"], [20, None, 20, None])
        self.assertEqual(results["both"], [20, 20, 20, 20])
        self.assertLess(sum(d is not None for d in results["one"]), cfg["connectivity"]["min_pass"])
        self.assertEqual([url for name, url, status in calls if name == "both"],
                         [DEFAULT_TEST_URL, DEFAULT_VERIFICATION_URL] * 2)
        self.assertTrue(all(status == 204 for name, url, status in calls))

    def test_candidates_are_split_into_bounded_independent_listener_batches(self):
        cfg = load_config(ROOT / "config.yaml")
        proxies = [{"name": f"node-{n}"} for n in range(65)]
        with patch.object(mihomo, "Mihomo") as process, \
                patch.object(mihomo, "_connectivity_get", return_value=10), \
                patch.object(mihomo.socket, "socket"):
            result = mihomo.test_connectivity(Path("unused"), proxies, cfg)
        self.assertEqual(len(result), 65)
        self.assertTrue(all(value == [10] * 4 for value in result.values()))
        configs = [yaml.safe_load(call.args[1]) for call in process.call_args_list]
        self.assertEqual([len(c["listeners"]) for c in configs], [64, 1])
        self.assertEqual(configs[0]["rules"][0], "IN-NAME,in-0,node-0")
        self.assertEqual(configs[0]["rules"][63], "IN-NAME,in-63,node-63")
        self.assertEqual(configs[1]["rules"][0], "IN-NAME,in-0,node-64")

    def test_occupied_listener_port_fails_before_starting_core(self):
        cfg = load_config(ROOT / "config.yaml")
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            cfg["mihomo"]["base_listen_port"] = occupied.getsockname()[1]
            with patch.object(mihomo, "Mihomo") as process, self.assertRaises(OSError):
                mihomo.test_connectivity(Path("unused"), [{"name": "a"}], cfg)
            process.assert_not_called()

    def test_controller_cannot_share_a_connectivity_listener_port(self):
        cfg = load_config(ROOT / "config.yaml")
        cfg["mihomo"]["controller"] = f"127.0.0.1:{cfg['mihomo']['base_listen_port']}"
        with patch.object(mihomo, "Mihomo") as process, self.assertRaises(ValueError):
            mihomo.test_connectivity(Path("unused"), [{"name": "a"}], cfg)
        process.assert_not_called()


class RealRequestTests(unittest.TestCase):
    def make_session(self, status=204):
        factory = patch.object(mihomo.requests, "Session")
        self.addCleanup(factory.stop)
        session = factory.start().return_value.__enter__.return_value
        response = session.get.return_value.__enter__.return_value
        response.status_code = status
        return session

    def test_https_checks_certificates_uses_only_node_proxy_and_measures_handshake(self):
        session = self.make_session()
        with patch.object(mihomo.time, "monotonic", side_effect=[10, 10.123]):
            self.assertEqual(mihomo._connectivity_get(23456, DEFAULT_TEST_URL, 5000, 204), 123)
        self.assertFalse(session.trust_env)
        self.assertEqual(session.proxies, {"http": "http://127.0.0.1:23456",
                                           "https": "http://127.0.0.1:23456"})
        session.get.assert_called_once_with(DEFAULT_TEST_URL, timeout=(5, 5),
                                            verify=True, allow_redirects=False, stream=True)

    def test_fake_success_redirect_and_tls_failures_cannot_pass(self):
        session = self.make_session()
        for status in (200, 301, 302, 403, 500):
            session.get.return_value.__enter__.return_value.status_code = status
            with self.subTest(status=status):
                self.assertIsNone(mihomo._connectivity_get(23456, DEFAULT_TEST_URL, 1000, 204))
        for error in (requests.exceptions.SSLError(), requests.Timeout(), requests.exceptions.ProxyError()):
            session.get.side_effect = error
            with self.subTest(error=type(error).__name__):
                self.assertIsNone(mihomo._connectivity_get(23456, DEFAULT_TEST_URL, 1000, 204))

    def test_custom_unspecified_status_accepts_only_success_and_never_redirects(self):
        session = self.make_session()
        for status, expected in ((200, True), (204, True), (302, False), (503, False)):
            session.get.return_value.__enter__.return_value.status_code = status
            with self.subTest(status=status):
                actual = mihomo._connectivity_get(23456, DEFAULT_TEST_URL, 1000, None)
                self.assertEqual(actual is not None, expected)


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

    def test_real_listeners_isolate_nodes_and_reject_error_pages_and_redirects(self):
        auth_headers = []
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.paths.append(self.path)
                time.sleep(0.02)
                status = 302 if self.path == "/redirect" else self.server.status
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/204")
                self.send_header("Content-Length", "0")
                self.end_headers()

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
                target.paths, target.status = [], status
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
            self.assertEqual(servers[0].paths, ["/204", "/204", "/redirect", "/redirect"])
            self.assertEqual(servers[1].paths, ["/204", "/204"])
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
