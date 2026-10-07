from __future__ import annotations

from pathlib import Path
import os
import socket
import unittest
from urllib.parse import quote

import yaml

from nodepool import mihomo, output
from nodepool.config import load_config


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / ("mihomo.exe" if os.name == "nt" else "mihomo")


def subscription(expected_status=204):
    cfg = load_config(ROOT / "config.yaml")
    cfg["connectivity"]["expected_status"] = expected_status
    rec = {
        "proxy": {"name": "test", "type": "http", "server": "example.com", "port": 443},
        "purity": {"score": 5, "cc": "US"},
        "latency_ms": 20,
    }
    text = output.build_subscription([rec], cfg)[0]
    return yaml.safe_load(text), text, cfg


def route_for_cn_answer(rules, domain):
    """Simulate a public CN DNS answer to verify domain priority over GEOIP."""
    for rule in rules:
        parts = rule.split(",")
        if parts[0] == "DOMAIN-SUFFIX":
            if domain == parts[1] or domain.endswith("." + parts[1]):
                return parts[2]
        elif parts[:2] == ["GEOIP", "CN"]:
            return parts[2]
        elif parts[0] == "MATCH":
            return parts[1]
    raise AssertionError("No route matched")


class OutputDnsTests(unittest.TestCase):
    def test_foreign_dns_follows_selected_exit_with_independent_node_bootstrap(self):
        doc, _, cfg = subscription()
        dns = doc["dns"]
        group_select = cfg["output"]["group_select"]
        self.assertGreaterEqual(len(dns["nameserver"]), 2)
        for address in dns["nameserver"]:
            self.assertTrue(address.startswith("https://"))
            self.assertTrue(address.endswith("#" + group_select))
        # Node DNS must remain usable before any proxy is connected.
        self.assertNotIn("system", dns["proxy-server-nameserver"])
        self.assertIn("https://223.5.5.5/dns-query", dns["proxy-server-nameserver"])
        for address in dns["proxy-server-nameserver"]:
            self.assertTrue(address.startswith("https://"))
            self.assertNotIn("#", address)
        self.assertFalse(dns["ipv6"])

    def test_domestic_dns_can_work_without_a_proxy(self):
        dns = subscription()[0]["dns"]
        for address in dns["nameserver-policy"]["+.cn"] + dns["direct-nameserver"]:
            self.assertNotIn("#", address)
        self.assertEqual(route_for_cn_answer(subscription()[0]["rules"], "www.example.cn"), "DIRECT")

    def test_blocked_services_do_not_become_direct_on_poisoned_cn_answers(self):
        doc, _, cfg = subscription()
        for domain in (
            "chatgpt.com", "api.openai.com", "cdn.oaistatic.com", "files.oaiusercontent.com",
            "www.google.com", "www.google.com.hk", "www.gstatic.com", "www.googleapis.com",
            "github.com", "api.github.com", "raw.githubusercontent.com", "github.githubassets.com",
        ):
            with self.subTest(domain=domain):
                self.assertEqual(route_for_cn_answer(doc["rules"], domain), cfg["output"]["group_select"])

    def test_rule_entry_defaults_to_auto_and_has_direct_manual_node_choices(self):
        doc, _, cfg = subscription()
        self.assertEqual(doc["mode"], "rule")
        self.assertEqual(len(doc["proxy-groups"]), 2)
        entry, group = doc["proxy-groups"]
        names = [p["name"] for p in doc["proxies"]]
        self.assertEqual(entry["name"], cfg["output"]["group_select"])
        self.assertEqual(entry["type"], "select")
        self.assertEqual(entry["proxies"], [cfg["output"]["group_auto"], *names])
        self.assertNotIn("DIRECT", entry["proxies"])
        self.assertEqual(group["name"], cfg["output"]["group_auto"])
        self.assertEqual(group["type"], "url-test")
        self.assertEqual(group["proxies"], names)
        self.assertNotIn(group["name"], group["proxies"])
        self.assertNotIn("DIRECT", group["proxies"])
        self.assertFalse(group["lazy"])
        self.assertEqual(doc["rules"][-1], "MATCH," + entry["name"])
        self.assertEqual(route_for_cn_answer(doc["rules"], "example.org"), "DIRECT")

    def test_legacy_groups_migrate_without_changing_nodes_or_ports(self):
        doc, _, cfg = subscription()
        original_nodes = list(doc["proxies"])
        doc["mixed-port"] = 12345
        doc["proxy-groups"].insert(0, {"name": "legacy-manual", "type": "select",
                                      "proxies": [cfg["output"]["group_auto"], "DIRECT"]})
        doc["rules"][-1] = "MATCH,legacy-manual"
        doc["dns"]["nameserver"] = ["https://1.1.1.1/dns-query#legacy-manual"]
        migrated = yaml.safe_load(output.simplify_subscription(yaml.safe_dump(doc), cfg))
        self.assertEqual(migrated["proxies"], original_nodes)
        self.assertEqual(migrated["mixed-port"], 12345)
        self.assertEqual(len(migrated["proxy-groups"]), 2)
        self.assertEqual(migrated["rules"][-1], "MATCH," + cfg["output"]["group_select"])
        self.assertNotIn("legacy-manual", yaml.safe_dump(migrated))

    def test_auto_only_subscription_gains_manual_entry_and_migration_is_idempotent(self):
        doc, _, cfg = subscription()
        doc["proxy-groups"] = [doc["proxy-groups"][1]]
        doc["rules"][-1] = "MATCH," + cfg["output"]["group_auto"]
        migrated = output.simplify_subscription(yaml.safe_dump(doc), cfg)
        self.assertEqual(output.simplify_subscription(migrated, cfg), migrated)
        restored = yaml.safe_load(migrated)
        self.assertEqual(restored["proxy-groups"][0]["type"], "select")
        self.assertEqual(restored["proxy-groups"][0]["proxies"][1:], [p["name"] for p in doc["proxies"]])

    def test_simplification_rejects_empty_or_ambiguous_node_names(self):
        doc, _, cfg = subscription()
        for proxies in ([], [{"name": cfg["output"]["group_auto"]}],
                        [{"name": cfg["output"]["group_select"]}],
                        [doc["proxies"][0], doc["proxies"][0]]):
            with self.subTest(proxies=proxies), self.assertRaises(ValueError):
                output.simplify_subscription(yaml.safe_dump({"proxies": proxies}), cfg)

    def test_dns_avoids_geo_database_and_blocked_direct_fallback(self):
        dns = subscription()[0]["dns"]
        self.assertNotIn("fallback", dns)
        self.assertFalse(dns["fallback-filter"]["geoip"])
        self.assertFalse(any("geosite:" in policy for policy in dns["nameserver-policy"]))

    def test_health_checks_use_configured_status_and_omit_unspecified_status(self):
        for status in (204, None):
            doc, _, cfg = subscription(status)
            for group in doc["proxy-groups"]:
                if group["type"] == "url-test":
                    self.assertEqual(group["url"], cfg["connectivity"]["test_url"])
                    if status is None:
                        self.assertNotIn("expected-status", group)
                    else:
                        self.assertEqual(group["expected-status"], status)

    @unittest.skipUnless(EXE.exists(), "Local mihomo binary unavailable")
    def test_subscription_with_proxied_dns_passes_native_offline_validation(self):
        _, text, _ = subscription()
        mihomo.validate_subscription(EXE, text)

    @unittest.skipUnless(EXE.exists(), "Local mihomo binary unavailable")
    def test_native_rule_mode_manual_selection_and_return_to_auto(self):
        _, _, cfg = subscription()
        proxies = [{"name": name, "type": "http", "server": "127.0.0.1", "port": 9}
                   for name in ("local-one", "local-two")]
        text = output.simplify_subscription(yaml.safe_dump({"proxies": proxies}), cfg)
        doc = yaml.safe_load(text)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            controller = "127.0.0.1:" + str(sock.getsockname()[1])
        doc.update({"external-controller": controller, "mixed-port": 0,
                    "geodata-mode": False, "geo-auto-update": False, "dns": {"enable": False}})
        doc["rules"] = [r for r in doc["rules"] if not r.startswith("GEOIP,")]
        doc["proxy-groups"][1]["url"] = "http://127.0.0.1:9"
        with mihomo.Mihomo(EXE, yaml.safe_dump(doc, allow_unicode=True), controller, "unused") as core:
            path = core.base + "/proxies/" + quote(cfg["output"]["group_select"], safe="")
            self.assertEqual(core.sess.get(core.base + "/configs", timeout=3).json()["mode"], "rule")
            self.assertEqual(core.sess.get(path, timeout=3).json()["now"], cfg["output"]["group_auto"])
            for name in ("local-one", "local-two", cfg["output"]["group_auto"]):
                response = core.sess.put(path, json={"name": name}, timeout=3)
                self.assertEqual(response.status_code, 204)
                self.assertEqual(core.sess.get(path, timeout=3).json()["now"], name)
            self.assertEqual(core.sess.put(path, json={"name": "missing"}, timeout=3).status_code, 400)


if __name__ == "__main__":
    unittest.main()
