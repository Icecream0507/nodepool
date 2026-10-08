from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml

import update
import verify
from nodepool import client_health, mihomo, output, pool, publish
from nodepool.config import load_config
from nodepool.util import log, node_id

ROOT = Path(__file__).resolve().parents[1]


def config():
    cfg = load_config(ROOT / "config.yaml")
    cfg["publish"]["client_health_required"] = True
    return cfg


def proxy(name, server):
    return {"name": name, "type": "http", "server": server, "port": 443}


PROXIES = [proxy("good", "1.1.1.1"), proxy("bad", "8.8.8.8"), proxy("unknown", "9.9.9.9")]


def report(cfg, accepted=(0,), *, age=0):
    return {"schema": 1, "required": True, "tested_at": time.time() - age,
            "policy": pool.connectivity_policy(cfg["connectivity"]),
            "nodes": {node_id(p): {"ok": i in accepted, "latency_ms": 20 if i in accepted else None}
                      for i, p in enumerate(PROXIES[:2])}}


def response(data, status=200):
    return SimpleNamespace(status_code=status, json=lambda: data)


class CloudClientGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = config()
        self.records = {}
        pool.merge_collected(self.records, copy.deepcopy(PROXIES))
        for rec in self.records.values():
            pool.record_purity(self.records, rec["id"], {"fraudScore": 5, "countryCode": "US"})
        pool.save(self.root / "data/pool.json", self.records)
        self.out = self.root / self.cfg["output"]["file"]
        self.out.parent.mkdir(parents=True)
        self.out.write_text("existing subscription", encoding="utf-8")
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(update, "ROOT", self.root))
        self.stack.enter_context(patch.object(update, "make_session", return_value=Mock()))
        self.stack.enter_context(patch.object(publish, "load_token", return_value="test"))
        self.restore = self.stack.enter_context(patch.object(publish, "restore_client_health", return_value=report(self.cfg)))
        self.stack.enter_context(patch.object(publish, "restore_stable_pool", return_value={}))
        self.stack.enter_context(patch.object(mihomo, "ensure_binary", return_value=Path("unused")))
        self.stack.enter_context(patch.object(mihomo, "prune_invalid", side_effect=lambda exe, ps, *a: ps))
        self.stack.enter_context(patch.object(mihomo, "test_connectivity", side_effect=lambda exe, ps, cfg: {p["name"]: [20] * cfg["connectivity"]["rounds"] for p in ps}))
        self.stack.enter_context(patch.object(mihomo, "validate_subscription"))
        self.publisher = self.stack.enter_context(patch.object(publish, "publish", return_value="stub://published"))
        self.candidates = self.stack.enter_context(patch.object(publish, "publish_candidates", return_value=True))
        self.backup = self.stack.enter_context(patch.object(publish, "backup_stable_pool", return_value=True))
        self.stack.enter_context(patch.object(log, "disabled", True))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def run_update(self):
        return update._run(self.cfg, SimpleNamespace(skip_collect=True, no_publish=False))

    def test_cloud_cannot_restore_failed_or_unknown_client_nodes(self):
        self.assertEqual(self.run_update(), 0)
        args = self.publisher.call_args
        final = yaml.safe_load(args.args[3])
        self.assertEqual([p["server"] for p in final["proxies"]], ["1.1.1.1"])
        self.assertEqual(len(yaml.safe_load(args.kwargs["candidates"])["proxies"]), 3)
        self.assertEqual(len(pool.load(self.root / "data/pool.json")), 3)

    def test_cloud_mode_publishes_passed_nodes_without_reading_local_whitelist(self):
        self.cfg["publish"]["client_health_required"] = False
        self.restore.side_effect = RuntimeError("an old report must not block cloud publication")
        health_path = self.root / "data/client-health.json"
        health_path.write_text("expired or corrupt diagnostic report", encoding="utf-8")
        self.assertEqual(self.run_update(), 0)
        self.restore.assert_not_called()
        final = yaml.safe_load(self.publisher.call_args.args[3])
        self.assertEqual({p["server"] for p in final["proxies"]}, {p["server"] for p in PROXIES})
        self.assertEqual(health_path.read_text(encoding="utf-8"), "expired or corrupt diagnostic report")

    def test_expired_report_only_updates_candidates_and_preserves_subscription(self):
        self.restore.return_value = report(self.cfg, age=169 * 3600)
        self.assertEqual(self.run_update(), 4)
        self.publisher.assert_not_called()
        self.candidates.assert_called_once()
        self.backup.assert_called_once()
        self.assertEqual(len(yaml.safe_load(self.candidates.call_args.args[3])["proxies"]), 3)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "existing subscription")

    def test_remote_report_read_failure_does_not_disable_gate(self):
        self.restore.side_effect = RuntimeError("remote report unreadable")
        with self.assertRaises(RuntimeError):
            self.run_update()
        self.publisher.assert_not_called(); self.candidates.assert_not_called()
        self.assertEqual(self.out.read_text(encoding="utf-8"), "existing subscription")

    def test_missing_remote_report_cannot_disable_previously_required_gate(self):
        health_path = self.root / "data/client-health.json"
        client_health.save_report(health_path, report(self.cfg))
        original_health = health_path.read_text(encoding="utf-8")
        self.restore.return_value = None
        with self.assertRaises(RuntimeError):
            self.run_update()
        self.publisher.assert_not_called(); self.candidates.assert_not_called()
        self.assertEqual(self.out.read_text(encoding="utf-8"), "existing subscription")
        self.assertEqual(health_path.read_text(encoding="utf-8"), original_health)

    def test_preferred_known_nodes_remain_scheduled_without_losing_exploration(self):
        known = {f"known-{i}": {"id": f"known-{i}", "last_ok": 100, "last_test": 100}
                 for i in range(20)}
        preferred = {"id": "preferred", "last_ok": 1000, "last_test": 1000}
        known[preferred["id"]] = preferred
        new = {f"new-{i}": {"id": f"new-{i}", "last_ok": 0, "last_test": 0}
               for i in range(100)}
        records = {**known, **new}
        baseline = pool.select_candidates(records, 4, .25)
        self.assertNotIn("preferred", {rec["id"] for rec in baseline})
        selected = pool.select_candidates(records, 4, .25, preferred_ids={"preferred"})
        ids = {rec["id"] for rec in selected}
        self.assertEqual(len(selected), 4)
        self.assertIn("preferred", ids)
        self.assertEqual(len(ids & new.keys()), 1)
        self.assertEqual(len(ids & known.keys()), 3)


class PublishingClientGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = config()
        self.content = yaml.safe_dump({"proxies": copy.deepcopy(PROXIES)})
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(publish, "_fixed_id", return_value="fixed"))
        self.stack.enter_context(patch.dict("os.environ", {"NODEPOOL_GIST_ID": "fixed"}))
        self.stack.enter_context(patch.object(log, "disabled", True))
        self.request = self.stack.enter_context(patch.object(publish, "_request"))

    def configure(self, stored):
        files = {} if stored is None else {self.cfg["publish"]["client_health_filename"]: {"content": stored}}
        self.request.side_effect = [response({"public": False, "files": files}),
                                    response({"id": "fixed", "owner": {"login": "owner"}})]

    def test_publish_rereads_new_report_and_refilters_cloud_candidates(self):
        newer = report(self.cfg, accepted=(1,))
        self.configure(json.dumps(newer))
        initially_selected = yaml.safe_dump({"proxies": [copy.deepcopy(PROXIES[0])]})
        self.assertIsNotNone(publish.publish(self.root, Mock(), "test", initially_selected, self.cfg, candidates=self.content))
        self.assertEqual([c.args[1] for c in self.request.call_args_list], ["GET", "PATCH"])
        payload = self.request.call_args.args[4]
        final = yaml.safe_load(payload["files"][self.cfg["publish"]["gist_filename"]]["content"])
        self.assertEqual([p["server"] for p in final["proxies"]], ["8.8.8.8"])
        self.assertEqual(len(yaml.safe_load(payload["files"][self.cfg["publish"]["candidate_filename"]]["content"])["proxies"]), 3)

    def test_cloud_publication_ignores_old_required_failed_expired_and_corrupt_reports(self):
        self.cfg["publish"]["client_health_required"] = False
        for stored in (None, "broken", json.dumps(report(self.cfg, accepted=())),
                       json.dumps(report(self.cfg, age=169 * 3600))):
            with self.subTest(stored=stored):
                self.request.reset_mock()
                self.configure(stored)
                self.assertIsNotNone(publish.publish(self.root, Mock(), "test", self.content, self.cfg, candidates=self.content))
                files = self.request.call_args.args[4]["files"]
                self.assertEqual(len(yaml.safe_load(files[self.cfg["publish"]["gist_filename"]]["content"])["proxies"]), 3)
                self.assertNotIn(self.cfg["publish"]["client_health_filename"], files)

    def test_bad_expired_or_wrong_policy_report_never_patches_subscription(self):
        wrong = report(self.cfg); wrong["policy"] = "old-policy"
        for stored in ("broken", json.dumps(report(self.cfg, age=169 * 3600)), json.dumps(wrong)):
            with self.subTest(stored=stored):
                self.request.reset_mock(); self.configure(stored)
                self.assertIsNone(publish.publish(self.root, Mock(), "test", self.content, self.cfg, candidates=self.content))
                self.assertEqual([c.args[1] for c in self.request.call_args_list], ["GET"])

    def test_candidates_can_update_without_touching_subscription_or_report(self):
        self.configure("broken report must not affect candidate updates")
        self.assertTrue(publish.publish_candidates(self.root, Mock(), "test", self.content, self.cfg))
        payload = self.request.call_args.args[4]
        self.assertEqual(set(payload["files"]), {self.cfg["publish"]["candidate_filename"]})

    def test_final_missing_remote_report_cannot_bypass_local_required_gate(self):
        health_path = self.root / "data/client-health.json"
        client_health.save_report(health_path, report(self.cfg))
        original_health = health_path.read_text(encoding="utf-8")
        self.configure(None)
        self.assertIsNone(publish.publish(self.root, Mock(), "test", self.content, self.cfg, candidates=self.content))
        self.assertEqual([call.args[1] for call in self.request.call_args_list], ["GET"])
        self.assertEqual(health_path.read_text(encoding="utf-8"), original_health)

    def test_older_explicit_report_cannot_overwrite_newer_remote_decision(self):
        newer = report(self.cfg, accepted=(1,))
        older = report(self.cfg, accepted=(0,), age=60)
        self.configure(json.dumps(newer))
        result = publish.publish(self.root, Mock(), "test", self.content, self.cfg,
                                 candidates=self.content, client_report=older)
        if result is None:
            self.assertEqual([c.args[1] for c in self.request.call_args_list], ["GET"])
        else:
            payload = self.request.call_args.args[4]["files"]
            rewritten = payload.get(self.cfg["publish"]["client_health_filename"])
            if rewritten is not None:
                self.assertGreaterEqual(json.loads(rewritten["content"])["tested_at"], newer["tested_at"])
            final = yaml.safe_load(payload[self.cfg["publish"]["gist_filename"]]["content"])
            self.assertEqual([p["server"] for p in final["proxies"]], ["8.8.8.8"])


class LocalVerificationStagesTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.text = yaml.safe_dump({"proxies": copy.deepcopy(PROXIES[:2])})
        self.ids = [node_id(p) for p in PROXIES[:2]]
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(mihomo, "prune_invalid", side_effect=lambda exe, ps, *a: ps))
        self.check = self.stack.enter_context(patch.object(mihomo, "validate_subscription"))
        self.tests = self.stack.enter_context(patch.object(mihomo, "test_connectivity"))
        self.stack.enter_context(patch.object(log, "disabled", True))

    def test_service_failure_or_second_pass_failure_excludes_node(self):
        for failure_stage in ("service", "confirmation"):
            first = {nid: [20] * 4 for nid in self.ids}
            web = {nid: [20] * 2 for nid in self.ids}
            confirm = {nid: [20] * 4 for nid in self.ids}
            (web if failure_stage == "service" else confirm)[self.ids[1]][-1] = None
            self.tests.side_effect = [first, web, confirm]
            with self.subTest(stage=failure_stage):
                filtered, health = verify.verify_document(self.text, Path("unused"), self.cfg)
                self.assertTrue(health["nodes"][self.ids[0]]["ok"])
                self.assertFalse(health["nodes"][self.ids[1]]["ok"])
                self.assertEqual([p["server"] for p in yaml.safe_load(filtered)["proxies"]], ["1.1.1.1"])

    def test_incomplete_or_nonpositive_first_pass_cannot_enter_web_checks(self):
        for delays in ([], [20] * 3, [20, 20, 20, -1], [20, 20, 20, True]):
            self.tests.reset_mock()
            self.tests.side_effect = [{nid: delays for nid in self.ids}]
            with self.subTest(delays=delays):
                filtered, health = verify.verify_document(self.text, Path("unused"), self.cfg)
                self.assertIsNone(filtered)
                self.assertTrue(all(not item["ok"] for item in health["nodes"].values()))
                self.assertEqual(self.tests.call_count, 1)

    def test_missing_service_or_confirmation_results_fail_closed(self):
        for stage in ("service", "confirmation"):
            first = {nid: [20] * 4 for nid in self.ids}
            web = {} if stage == "service" else {nid: [20] * 2 for nid in self.ids}
            self.tests.side_effect = [first, web, {}]
            with self.subTest(stage=stage):
                filtered, health = verify.verify_document(self.text, Path("unused"), self.cfg)
                self.assertIsNone(filtered)
                self.assertTrue(all(not item["ok"] for item in health["nodes"].values()))

    def test_zero_passes_preserves_existing_subscription_and_published_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / self.cfg["output"]["file"]
            out.parent.mkdir(parents=True); out.write_text("existing subscription", encoding="utf-8")
            health_path = root / "data/client-health.json"
            client_health.save_report(health_path, report(self.cfg))
            original_health = health_path.read_text(encoding="utf-8")
            candidate_path = root / "candidate.yaml"; candidate_path.write_text(self.text, encoding="utf-8")
            failed_report = report(self.cfg, accepted=())
            with patch.object(verify, "ROOT", root), patch.object(verify, "load_config", return_value=self.cfg), \
                    patch.object(publish, "load_token", return_value="test"), \
                    patch.object(verify, "make_session", return_value=contextlib.nullcontext(Mock())), \
                    patch.object(verify, "verify_document", return_value=(None, failed_report)), \
                    patch.object(publish, "publish") as publisher, \
                    patch("sys.argv", ["verify.py", "--input", str(candidate_path), "--core", "unused"]):
                self.assertEqual(verify.main(), 4)
                publisher.assert_not_called()
            self.assertEqual(out.read_text(encoding="utf-8"), "existing subscription")
            self.assertEqual(health_path.read_text(encoding="utf-8"), original_health)


if __name__ == "__main__":
    unittest.main()
