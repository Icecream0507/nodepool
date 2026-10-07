from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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

        def delay(name, url, timeout_ms, expected_status):
            calls.append((name, url, expected_status))
            return 20 if name == "both" or url == cfg["connectivity"]["test_url"] else None

        api = Mock()
        api.delay.side_effect = delay
        with patch.object(mihomo, "Mihomo") as process:
            process.return_value.__enter__.return_value = api
            results = mihomo.test_connectivity(Path("unused"), [{"name": "one"}, {"name": "both"}], cfg)
        self.assertEqual(results["one"], [20, None, 20, None])
        self.assertEqual(results["both"], [20, 20, 20, 20])
        self.assertLess(sum(d is not None for d in results["one"]), cfg["connectivity"]["min_pass"])
        self.assertEqual([url for name, url, status in calls if name == "both"],
                         [DEFAULT_TEST_URL, DEFAULT_VERIFICATION_URL] * 2)
        self.assertTrue(all(status == 204 for name, url, status in calls))


@unittest.skipUnless(EXE.exists(), "mihomo binary is not installed")
class NativeStatusTests(unittest.TestCase):
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
