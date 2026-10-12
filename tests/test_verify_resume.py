from __future__ import annotations

import contextlib
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import yaml

import verify
from nodepool import mihomo, pool, publish
from nodepool.config import load_config
from nodepool.util import log


ROOT = Path(__file__).resolve().parents[1]


class LocalVerificationResumeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkpoint = self.root / "data/local-verification-progress.json"
        self.cfg = load_config(ROOT / "config.yaml")
        self.proxies = [{"name": f"node-{i}", "type": "http", "server": "1.1.1.1", "port": 10000 + i}
                        for i in range(65)]
        self.text = yaml.safe_dump({"proxies": self.proxies})
        self.clock = time.time()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(log, "disabled", True))
        self.stack.enter_context(patch.object(time, "time", side_effect=lambda: self.clock))
        self.prune = self.stack.enter_context(patch.object(mihomo, "prune_invalid",
                                                          side_effect=lambda exe, proxies, *args: proxies))
        self.native = self.stack.enter_context(patch.object(mihomo, "test_connectivity",
                                                           side_effect=self.passing_native))
        self.web = self.stack.enter_context(patch.object(mihomo, "test_http_get",
                                                        side_effect=lambda exe, proxies, *args: {
                                                            proxy["name"]: True for proxy in proxies}))
        self.validate = self.stack.enter_context(patch.object(mihomo, "validate_subscription"))

    @staticmethod
    def passing_native(exe, proxies, cfg, **kwargs):
        return {proxy["name"]: [20] * cfg["connectivity"]["rounds"] for proxy in proxies}

    def interrupted_checkpoint(self):
        calls = 0

        def interrupted(exe, proxies, cfg, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("core could not start")
            return self.passing_native(exe, proxies, cfg, **kwargs)

        self.native.side_effect = interrupted
        with self.assertRaisesRegex(RuntimeError, "core could not start"):
            verify.verify_document(self.text, Path("unused"), self.cfg, checkpoint_path=self.checkpoint)
        self.assertEqual(self.web.call_count, 1)
        self.validate.assert_not_called()
        saved = json.loads(self.checkpoint.read_text(encoding="utf-8"))
        self.assertEqual(set(saved["batches"]), {"0"})
        self.assertEqual(len(saved["batches"]["0"]["results"]), 64)
        self.native.reset_mock()
        self.native.side_effect = self.passing_native
        self.web.reset_mock()
        self.prune.reset_mock()
        return saved

    def test_restart_only_probes_remaining_batch_and_keeps_earliest_evidence_time(self):
        original_time = self.clock
        self.interrupted_checkpoint()
        self.clock += 60
        filtered, report = verify.verify_document(self.text, Path("unused"), self.cfg,
                                                  checkpoint_path=self.checkpoint)
        self.assertEqual(len(report["nodes"]), 65)
        self.assertTrue(all(node["ok"] for node in report["nodes"].values()))
        self.assertEqual(len(yaml.safe_load(filtered)["proxies"]), 65)
        self.assertEqual(report["tested_at"], original_time)
        self.assertEqual(self.native.call_count, 2)
        self.assertEqual(self.web.call_count, 1)
        self.assertTrue(all(len(call.args[1]) == 1 for call in self.native.call_args_list))
        self.assertEqual(self.prune.call_count, 1)
        self.validate.assert_called_once()

    def test_stale_mismatched_or_incomplete_checkpoint_cannot_skip_checks(self):
        saved = self.interrupted_checkpoint()
        for problem in ("expired", "policy", "candidate", "stage", "incomplete", "partial", "future", "nonfinite", "corrupt"):
            with self.subTest(problem=problem):
                checkpoint = copy.deepcopy(saved)
                source = self.text
                if problem == "expired":
                    checkpoint["batches"]["0"]["tested_at"] = self.clock - 1801
                elif problem == "policy":
                    checkpoint["policy"] = "different policy"
                elif problem == "candidate":
                    candidates = copy.deepcopy(self.proxies)
                    candidates[-1]["port"] += 100
                    source = yaml.safe_dump({"proxies": candidates})
                elif problem == "stage":
                    checkpoint["stage"] += 1
                elif problem == "incomplete":
                    checkpoint["batches"]["0"]["results"].pop(next(iter(checkpoint["batches"]["0"]["results"])))
                elif problem == "partial":
                    checkpoint["batches"]["0"]["results"][next(iter(checkpoint["batches"]["0"]["results"]))] = [20, 20, 20, None]
                elif problem == "future":
                    checkpoint["batches"]["0"]["tested_at"] = self.clock + 1
                elif problem == "nonfinite":
                    checkpoint["batches"]["unused"] = {"tested_at": float("nan")}
                self.checkpoint.write_text("broken" if problem == "corrupt" else json.dumps(checkpoint), encoding="utf-8")
                self.native.reset_mock()
                self.web.reset_mock()
                filtered, report = verify.verify_document(source, Path("unused"), self.cfg,
                                                          checkpoint_path=self.checkpoint)
                self.assertIsNotNone(filtered)
                self.assertEqual(len(report["nodes"]), 65)
                self.assertEqual(self.native.call_count, 4)
                self.assertEqual(self.web.call_count, 2)

    def test_failure_inside_batch_does_not_checkpoint_partial_approvals(self):
        for stage in ("service", "confirmation"):
            with self.subTest(stage=stage):
                self.web.side_effect = (RuntimeError("HTTP core failed") if stage == "service"
                                        else lambda exe, proxies, *args: {p["name"]: True for p in proxies})
                self.native.side_effect = (self.passing_native if stage == "service"
                                          else [self.passing_native(None, [{"name": pool.node_id(p)} for p in self.proxies[:64]],
                                                                    self.cfg), RuntimeError("confirmation core failed")])
                with self.assertRaisesRegex(RuntimeError, "core failed"):
                    verify.verify_document(self.text, Path("unused"), self.cfg, checkpoint_path=self.checkpoint)
                self.assertFalse(self.checkpoint.exists())
                self.validate.assert_not_called()

    def test_main_uses_ignored_checkpoint_and_cleans_after_success(self):
        candidate = self.root / "candidate.yaml"
        candidate.write_text(self.text, encoding="utf-8")

        def verified(source, exe, cfg, *, checkpoint_path):
            self.assertEqual(checkpoint_path, self.checkpoint)
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            checkpoint_path.write_text("complete checkpoint", encoding="utf-8")
            report = {"schema": 1, "required": True, "tested_at": self.clock,
                      "policy": pool.connectivity_policy(cfg["connectivity"]),
                      "nodes": {pool.node_id(self.proxies[0]): {"ok": True, "latency_ms": 20}}}
            return self.text, report

        with patch.object(verify, "ROOT", self.root), patch.object(verify, "load_config", return_value=self.cfg), \
                patch.object(publish, "load_token", return_value=None), \
                patch.object(verify, "make_session", return_value=contextlib.nullcontext(Mock())), \
                patch.object(verify, "verify_document", side_effect=verified), \
                patch("sys.argv", ["verify.py", "--input", str(candidate), "--core", "unused", "--no-publish"]):
            self.assertEqual(verify.main(), 0)
        self.assertFalse(self.checkpoint.exists())

    def test_publish_failure_keeps_completed_checkpoint_for_retry(self):
        candidate = self.root / "candidate.yaml"
        candidate.write_text(self.text, encoding="utf-8")
        self.checkpoint.parent.mkdir(parents=True)
        self.checkpoint.write_text("complete checkpoint", encoding="utf-8")
        with patch.object(verify, "ROOT", self.root), patch.object(verify, "load_config", return_value=self.cfg), \
                patch.object(publish, "load_token", return_value="test"), \
                patch.object(verify, "make_session", return_value=contextlib.nullcontext(Mock())), \
                patch.object(verify, "verify_document", return_value=(self.text, {"nodes": {"test": {"ok": True}}})), \
                patch.object(publish, "publish", return_value=None), \
                patch("sys.argv", ["verify.py", "--input", str(candidate), "--core", "unused"]):
            self.assertEqual(verify.main(), 3)
        self.assertTrue(self.checkpoint.exists())
        self.assertFalse((self.root / self.cfg["output"]["file"]).exists())


if __name__ == "__main__":
    unittest.main()
