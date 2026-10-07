from __future__ import annotations

from pathlib import Path
import os
import unittest

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
    def test_foreign_dns_uses_auto_group_and_independent_node_bootstrap(self):
        doc, _, cfg = subscription()
        dns = doc["dns"]
        group_auto = cfg["output"]["group_auto"]
        group_select = cfg["output"]["group_select"]
        self.assertGreaterEqual(len(dns["nameserver"]), 2)
        for address in dns["nameserver"]:
            self.assertTrue(address.startswith("https://"))
            self.assertTrue(address.endswith("#" + group_auto))
            self.assertNotIn("#" + group_select, address)
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


if __name__ == "__main__":
    unittest.main()
