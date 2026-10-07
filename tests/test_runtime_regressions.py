from __future__ import annotations

import contextlib
import copy
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml

import update
from nodepool import mihomo, pool, publish
from nodepool.config import load_config
from nodepool.util import log


ROOT = Path(__file__).resolve().parents[1]


def qualified(server="8.8.8.8", policy=None):
    records = {}
    pool.merge_collected(records, [{"name": "test", "type": "http", "server": server, "port": 443}])
    rec = next(iter(records.values()))
    pool.record_test(records, rec["id"], True, 25, policy=policy)
    pool.record_purity(records, rec["id"], {"fraudScore": 5, "countryCode": "US"})
    return rec


class ConnectivityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.connectivity = {"test_url": "https://example.com/204",
                             "verification_url": "https://example.org/204", "expected_status": 204,
                             "timeout_ms": 5000, "rounds": 4, "min_pass": 3, "concurrency": 8}
        self.policy = pool.connectivity_policy(self.connectivity)
        self.stable_cfg = {"stable_min_passes": 5, "stable_min_rate": .8}

    def test_each_requirement_changes_policy(self):
        changes = {"test_url": "http://example.com/204", "verification_url": None,
                   "expected_status": None, "timeout_ms": 6000, "rounds": 5, "min_pass": 4}
        for key, value in changes.items():
            with self.subTest(key=key):
                self.assertNotEqual(pool.connectivity_policy({**self.connectivity, key: value}), self.policy)

    def test_concurrency_does_not_invalidate_evidence(self):
        self.assertEqual(pool.connectivity_policy({**self.connectivity, "concurrency": 1}), self.policy)

    def test_legacy_result_requires_retest(self):
        rec = qualified()
        self.assertFalse(pool.tested_with_policy(rec, self.policy))
        records = {rec["id"]: rec}
        pool.record_test(records, rec["id"], True, 20, policy=self.policy)
        self.assertTrue(pool.tested_with_policy(rec, self.policy))
        self.assertEqual(len(rec["history"]), 2)
        self.assertNotIn("policy", rec["history"][0])
        self.assertEqual(rec["history"][1]["policy"], self.policy)

    def test_old_successes_cannot_promote_under_stricter_policy(self):
        rec = qualified(); records = {rec["id"]: rec}
        for _ in range(4):
            pool.record_test(records, rec["id"], True, 20)
        pool.record_test(records, rec["id"], True, 20, policy=self.policy)
        self.assertEqual(pool.promote_stable(records, self.stable_cfg, 24, 40, policy=self.policy), 0)
        for _ in range(4):
            pool.record_test(records, rec["id"], True, 20, policy=self.policy)
        self.assertEqual(pool.promote_stable(records, self.stable_cfg, 24, 40, policy=self.policy), 1)
        self.assertEqual(len(rec["history"]), 10)

    def test_policy_transition_retains_existing_stable_identity(self):
        rec = qualified(); rec.update(stable=True, stable_since=123)
        records = {rec["id"]: rec}
        pool.record_test(records, rec["id"], False, None, policy=self.policy)
        pool.promote_stable(records, self.stable_cfg, 24, 40, policy=self.policy)
        self.assertTrue(rec["stable"])
        self.assertEqual(rec["stable_since"], 123)
        self.assertEqual(rec["success_count"], 1)

    def test_failure_restarts_current_policy_streak(self):
        rec = qualified(policy=self.policy); records = {rec["id"]: rec}
        for _ in range(3):
            pool.record_test(records, rec["id"], True, 20, policy=self.policy)
        pool.record_test(records, rec["id"], False, None, policy=self.policy)
        pool.record_test(records, rec["id"], True, 20, policy=self.policy)
        self.assertEqual(pool.promote_stable(records, self.stable_cfg, 24, 40, policy=self.policy), 0)

    def test_dedup_migration_preserves_stable_identity_and_newest_health(self):
        old = qualified(); old.update(stable=True, stable_since=123, last_test=100, last_ok=100)
        latest = copy.deepcopy(old)
        latest.update(stable=False, stable_since=0, last_test=200, last_ok=200, latency_ms=50)
        latest["proxy"]["name"] = "renamed"
        for records in ({"old": old, "new": latest}, {"new": latest, "old": old}):
            result = pool._migrate(records)
            self.assertEqual(len(result), 1)
            migrated = next(iter(result.values()))
            self.assertTrue(migrated["stable"])
            self.assertEqual(migrated["stable_since"], 123)
            self.assertEqual(migrated["last_ok"], 200)
            self.assertEqual(migrated["latency_ms"], 50)

    def test_full_update_excludes_recent_unselected_legacy_evidence(self):
        cfg = load_config(ROOT / "config.yaml")
        current = qualified("1.1.1.1")
        legacy = qualified()
        records = {r["id"]: r for r in (current, legacy)}
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            root = Path(td)
            pool.save(root / "data/pool.json", records)
            stack.enter_context(patch.object(update, "ROOT", root))
            stack.enter_context(patch.object(update, "make_session", return_value=Mock()))
            stack.enter_context(patch.object(publish, "load_token", return_value=None))
            stack.enter_context(patch.object(pool, "select_candidates", side_effect=lambda pl, *a: [pl[current["id"]]]))
            stack.enter_context(patch.object(mihomo, "ensure_binary", return_value=Path("unused")))
            stack.enter_context(patch.object(mihomo, "prune_invalid", side_effect=lambda exe, ps, *a: ps))
            stack.enter_context(patch.object(mihomo, "test_connectivity", return_value={current["id"]: [20] * cfg["connectivity"]["rounds"]}))
            stack.enter_context(patch.object(mihomo, "validate_subscription"))
            stack.enter_context(patch.object(log, "disabled", True))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            status = update._run(cfg, SimpleNamespace(skip_collect=True, no_publish=True))
            self.assertEqual(status, 0)
            doc = yaml.safe_load((root / cfg["output"]["file"]).read_text(encoding="utf-8"))
            self.assertEqual(len(doc["proxies"]), 1)
            self.assertEqual(doc["proxies"][0]["server"], "1.1.1.1")
            saved = pool.load(root / "data/pool.json")
            self.assertIn(legacy["id"], saved)
            self.assertEqual(saved[legacy["id"]]["success_count"], 1)


if __name__ == "__main__":
    unittest.main()
