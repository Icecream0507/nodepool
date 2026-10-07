from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

import yaml

from nodepool import client_health, pool
from nodepool.util import node_id


NOW = 1_800_000_000
CONNECTIVITY = {"test_url": "https://example.com/204", "verification_url": "https://example.org/204",
                "expected_status": 204, "timeout_ms": 5000, "rounds": 4, "min_pass": 3}
POLICY = pool.connectivity_policy(CONNECTIVITY)


def proxy(name="good", server="1.1.1.1"):
    return {"name": name, "type": "http", "server": server, "port": 443}


def report():
    return {"schema": 1, "required": True, "tested_at": NOW, "policy": POLICY,
            "nodes": {node_id(proxy()): {"ok": True, "latency_ms": 20}}}


class ClientHealthReportTests(unittest.TestCase):
    def test_report_persistence_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "health.json"
            client_health.save_report(path, report(), now=NOW)
            self.assertEqual(client_health.load_report(path, now=NOW), report())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), report())

    def test_schema_and_timestamp_validation(self):
        changes = {"schema": (True, 2, "1"), "required": (1, "true", None),
                   "tested_at": (True, -1, "100", float("nan"), float("inf"), NOW + 301),
                   "policy": (None, "", 123), "nodes": ([], None)}
        for key, values in changes.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    client_health.validate_report({**report(), key: value}, now=NOW)
        accepted = report(); accepted["tested_at"] = NOW + 300
        self.assertIs(client_health.validate_report(accepted, now=NOW), accepted)

    def test_malformed_node_entries_rejected(self):
        cases = [
            {"short": {"ok": True, "latency_ms": 20}},
            {"z" * 16: {"ok": True, "latency_ms": 20}},
            {node_id(proxy()): {"ok": 1, "latency_ms": 20}},
            {node_id(proxy()): {"ok": True, "latency_ms": True}},
            {node_id(proxy()): {"ok": True, "latency_ms": 0}},
            {node_id(proxy()): {"ok": True, "latency_ms": 1.5}},
            {node_id(proxy()): {"ok": True}},
        ]
        for nodes in cases:
            with self.subTest(nodes=nodes), self.assertRaises(ValueError):
                client_health.validate_report({**report(), "nodes": nodes}, now=NOW)

    def test_missing_and_unexpected_fields_rejected(self):
        incomplete = report(); del incomplete["policy"]
        for value in (incomplete, {**report(), "polciy": POLICY}, [], None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                client_health.validate_report(value, now=NOW)

    def test_corrupt_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "health.json"
            path.write_text("broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                client_health.load_report(path, now=NOW)

    def test_build_report_requires_complete_rounds_and_positive_delays(self):
        proxies = [proxy("good"), proxy("partial", "8.8.8.8"), proxy("failed", "9.9.9.9")]
        results = {"good": [10, None, 20, 90], "partial": [10, 20, 30], "failed": [0, True, None, 10]}
        built = client_health.build_report(results, proxies, CONNECTIVITY, now=NOW)
        self.assertEqual(built["policy"], POLICY)
        self.assertEqual(built["nodes"][node_id(proxies[0])], {"ok": True, "latency_ms": 20})
        for p in proxies[1:]:
            self.assertEqual(built["nodes"][node_id(p)], {"ok": False, "latency_ms": None})

    def test_build_report_binds_connection_not_display_name(self):
        first = client_health.build_report({"good": [10] * 4}, [proxy()], CONNECTIVITY, now=NOW)
        renamed = client_health.build_report({"renamed": [10] * 4}, [proxy("renamed")], CONNECTIVITY, now=NOW)
        self.assertEqual(first["nodes"], renamed["nodes"])
        changed = proxy(); changed["port"] = 8443
        self.assertNotIn(node_id(changed), first["nodes"])

    def test_build_report_rejects_ambiguous_duplicates(self):
        for proxies in ([proxy(), proxy("renamed")], [proxy(), proxy(server="8.8.8.8")]):
            with self.subTest(proxies=proxies), self.assertRaises(ValueError):
                client_health.build_report({"good": [10] * 4}, proxies, CONNECTIVITY, now=NOW)


class ClientHealthFilterTests(unittest.TestCase):
    def records(self):
        records = {}
        pool.merge_collected(records, [proxy(), proxy("bad", "8.8.8.8")])
        return records

    def test_filter_does_not_mutate_pool_history(self):
        records = self.records(); before = copy.deepcopy(records)
        selected = client_health.filter_records(records, report(), POLICY, now=NOW)
        self.assertEqual(list(selected), [node_id(proxy())])
        self.assertEqual(records, before)
        self.assertIs(selected[node_id(proxy())], records[node_id(proxy())])
        selected_list = client_health.filter_records(list(records.values()), report(), POLICY, now=NOW)
        self.assertEqual(len(selected_list), 1)

    def test_disabled_or_absent_report_returns_original(self):
        records = self.records()
        disabled = {**report(), "required": False}
        for value in (None, disabled):
            self.assertIs(client_health.filter_records(records, value, POLICY, now=NOW), records)
            self.assertEqual(client_health.filter_subscription("unchanged text", value, POLICY, now=NOW), "unchanged text")

    def test_wrong_policy_and_expired_report_reject_all(self):
        records = self.records()
        self.assertEqual(client_health.filter_records(records, report(), "other", now=NOW), {})
        self.assertEqual(client_health.filter_records(records, report(), POLICY, now=NOW + 24 * 3600), {})
        self.assertEqual(len(client_health.filter_records(records, report(), POLICY, now=NOW + 24 * 3600, max_age_hours=168)), 1)

    def test_report_false_and_unknown_connections_rejected(self):
        records = self.records()
        failed = report(); failed["nodes"][node_id(proxy())]["ok"] = False
        self.assertEqual(client_health.filter_records(records, failed, POLICY, now=NOW), {})
        changed = proxy(); changed["password"] = "changed"
        self.assertEqual(client_health.filter_records([{"proxy": changed}], report(), POLICY, now=NOW), [])

    def subscription(self):
        return {
            "mode": "rule", "mixed-port": 7890,
            "dns": {"enable": True, "nameserver": ["https://1.1.1.1/dns-query#auto"],
                    "proxy-server-nameserver": ["https://223.5.5.5/dns-query"]},
            "proxies": [proxy(), proxy("bad", "8.8.8.8")],
            "proxy-groups": [
                {"name": "manual", "type": "select", "proxies": ["auto", "bad-only", "good", "bad", "DIRECT", "REJECT"]},
                {"name": "auto", "type": "url-test", "proxies": ["good", "bad"], "url": "https://example.com/204"},
                {"name": "bad-only", "type": "url-test", "proxies": ["bad"]},
                {"name": "nested-empty", "type": "url-test", "proxies": ["bad-only"]},
                {"name": "empty-manual", "type": "select", "proxies": ["nested-empty"]},
            ],
            "rules": ["IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "MATCH,manual"],
        }

    def filtered(self, doc):
        text = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
        return yaml.safe_load(client_health.filter_subscription(text, report(), POLICY, now=NOW))

    def test_subscription_repairs_nested_groups_and_preserves_dns_rules(self):
        original = self.subscription(); result = self.filtered(original)
        self.assertEqual([p["name"] for p in result["proxies"]], ["good"])
        groups = {g["name"]: g for g in result["proxy-groups"]}
        self.assertNotIn("bad-only", groups)
        self.assertNotIn("nested-empty", groups)
        self.assertEqual(groups["empty-manual"]["proxies"], ["DIRECT"])
        self.assertEqual(groups["auto"]["proxies"], ["good"])
        self.assertEqual(groups["manual"]["proxies"], ["auto", "good", "DIRECT", "REJECT"])
        self.assertEqual(result["dns"], original["dns"])
        self.assertEqual(result["rules"], original["rules"])
        self.assertEqual(result["mixed-port"], 7890)
        self.assertEqual(original["proxies"][1]["name"], "bad")

    def test_removed_group_dns_and_rule_references_fall_back_to_main_selector(self):
        original = self.subscription()
        original["dns"]["nameserver"].append("https://8.8.8.8/dns-query#bad-only&h3=true")
        original["rules"] += ["DOMAIN-SUFFIX,example.org,bad-only", "IP-CIDR,8.8.8.8/32,bad,no-resolve"]
        original["sub-rules"] = {"nested": ["MATCH,nested-empty"]}
        result = self.filtered(original)
        self.assertEqual(result["dns"]["nameserver"][-1], "https://8.8.8.8/dns-query#manual&h3=true")
        self.assertEqual(result["rules"][-2:], ["DOMAIN-SUFFIX,example.org,manual", "IP-CIDR,8.8.8.8/32,manual,no-resolve"])
        self.assertEqual(result["sub-rules"]["nested"], ["MATCH,manual"])

    def test_zero_passes_raises_without_modifying_input(self):
        original = self.subscription(); text = yaml.safe_dump(original)
        for current_report, policy in (({**report(), "nodes": {}}, POLICY), (report(), "wrong")):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                client_health.filter_subscription(text, current_report, policy, now=NOW)
        self.assertEqual(yaml.safe_load(text), original)

    def test_cyclic_groups_are_rejected(self):
        original = self.subscription()
        original["proxy-groups"].append({"name": "loop", "type": "select", "proxies": ["manual"]})
        original["proxy-groups"][0]["proxies"].append("loop")
        with self.assertRaises(ValueError):
            self.filtered(original)

    def test_duplicate_proxy_or_group_names_are_rejected(self):
        for duplicate in ("proxy", "group", "overlap"):
            original = self.subscription()
            if duplicate == "proxy":
                original["proxies"][1]["name"] = "good"
            elif duplicate == "group":
                original["proxy-groups"][1]["name"] = "manual"
            else:
                original["proxy-groups"][1]["name"] = "bad"
            with self.subTest(duplicate=duplicate), self.assertRaises(ValueError):
                self.filtered(original)


if __name__ == "__main__":
    unittest.main()
