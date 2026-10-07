from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import requests
import yaml

import update
from nodepool import collect, mihomo, output, parse, pool, publish
from nodepool.config import load_config, validate_config
from nodepool.util import log, node_id, run_lock

ROOT = Path(__file__).resolve().parents[1]
_LOG_DISABLED = False


def setUpModule():
    global _LOG_DISABLED
    _LOG_DISABLED = log.disabled
    log.disabled = True


def tearDownModule():
    log.disabled = _LOG_DISABLED


def config():
    return load_config(ROOT / "config.yaml")


def record(server="8.8.8.8"):
    pl = {}
    pool.merge_collected(pl, [{"name": "demo", "type": "http", "server": server, "port": 443}])
    return next(iter(pl.values()))


def qualified(server="8.8.8.8"):
    r = record(server)
    pl = {r["id"]: r}
    pool.record_test(pl, r["id"], True, 20, policy=pool.connectivity_policy(config()["connectivity"]))
    pool.record_purity(pl, r["id"], {"fraudScore": 5, "countryCode": "US", "ip": "8.8.4.4"})
    return r


class PoolTests(unittest.TestCase):
    def test_stable_requires_five_passes_and_valid_purity(self):
        r = record(); pl = {r["id"]: r}; cfg = config()
        for _ in range(4):
            pool.record_test(pl, r["id"], True, 20)
        pool.record_purity(pl, r["id"], {"fraudScore": 5})
        self.assertEqual(pool.promote_stable(pl, cfg["pool"], 24, 40), 0)
        pool.record_test(pl, r["id"], True, 20)
        self.assertEqual(pool.promote_stable(pl, cfg["pool"], 24, 40), 1)
        self.assertTrue(r["stable"])

    def test_stable_retains_transient_failures_and_recovers(self):
        r = qualified(); r["stable"] = True; pl = {r["id"]: r}
        for _ in range(12):
            pool.record_test(pl, r["id"], False, None)
        self.assertEqual(pool.prune(pl, 3), 0)
        self.assertIn(r["id"], pl)
        pool.record_test(pl, r["id"], True, 30)
        self.assertTrue(r["stable"])
        self.assertEqual(r["fail_streak"], 0)

    def test_stable_cools_only_after_failures_and_grace(self):
        r = qualified(); r.update(stable=True, fail_streak=12, last_ok=int(time.time()) - 8 * 86400)
        pl = {r["id"]: r}
        self.assertEqual(pool.prune(pl, 3), 1)
        self.assertIn(r["id"], pl)
        self.assertEqual(pool.select_candidates(pl, 10), [])

    def test_cooldown_survives_rediscovery(self):
        r = record(); pl = {r["id"]: r}
        for _ in range(3): pool.record_test(pl, r["id"], False, None)
        pool.prune(pl, 3)
        until = r["retired_until"]
        pool.merge_collected(pl, [copy.deepcopy(r["proxy"])])
        self.assertEqual(r["retired_until"], until)
        self.assertEqual(r["fail_streak"], 3)

    def test_expired_cooldown_is_not_extended_without_a_test(self):
        r = record(); r.update(last_test=10, retired_at=10, retired_until=20, fail_streak=3)
        pl = {r["id"]: r}
        self.assertEqual(pool.prune(pl, 3), 0)
        self.assertEqual(len(pool.select_candidates(pl, 10)), 1)

    def test_capacity_is_enforced_with_only_previously_alive_nodes(self):
        rs = [qualified(f"8.8.8.{i}") for i in range(1, 6)]
        rs[0]["stable"] = True
        pl = {r["id"]: r for r in rs}
        self.assertEqual(pool.enforce_limits(pl, 2, 3), 3)
        self.assertIn(rs[0]["id"], pl)

    def test_recent_source_prevents_stale_deletion(self):
        r = record(); r["first_seen"] -= 10 * 86400
        pl = {r["id"]: r}
        self.assertEqual(pool.enforce_limits(pl, 20000, 3), 0)

    def test_exploration_survives_full_history_pool(self):
        pl = {str(i): {"id": str(i), "last_ok": 100, "last_test": 100} for i in range(600)}
        pl["new"] = {"id": "new", "last_ok": 0, "last_test": 0}
        selected = pool.select_candidates(pl, 600)
        self.assertEqual(len(selected), 600)
        self.assertIn("new", {r["id"] for r in selected})

    def test_rotation_includes_old_proven_nodes_among_stable_nodes(self):
        pl = {str(i): {"id": str(i), "stable": True, "last_ok": 100, "last_test": 100} for i in range(20)}
        pl["old"] = {"id": "old", "last_ok": 10, "last_test": 10}
        self.assertIn("old", {r["id"] for r in pool.select_candidates(pl, 5)})

    def test_invalid_candidate_limit_rejected(self):
        with self.assertRaises(ValueError): pool.select_candidates({}, -1)

    def test_null_or_out_of_range_scores_are_not_cached(self):
        r = qualified(); pl = {r["id"]: r}; previous = r["purity"].copy()
        for value in (None, True, -1, 101, "bad", 1.5):
            self.assertFalse(pool.record_purity(pl, r["id"], {"fraudScore": value}))
            self.assertEqual(r["purity"], previous)

    def test_freshness_checks_score_and_time(self):
        r = qualified()
        self.assertTrue(pool.fresh_purity(r, 24))
        r["purity"]["score"] = None
        self.assertFalse(pool.fresh_purity(r, 24))
        r["purity"].update(score=5, ts=int(time.time()) - 25 * 3600)
        self.assertFalse(pool.fresh_purity(r, 24))

    def test_history_is_bounded(self):
        r = record(); pl = {r["id"]: r}
        for _ in range(30): pool.record_test(pl, r["id"], True, 10, 20)
        self.assertEqual(len(r["history"]), 20)
        self.assertEqual(r["success_count"], 30)

    def test_fingerprint_includes_password_reality_and_transport(self):
        p = {"name": "a", "type": "tuic", "server": "8.8.8.8", "port": 443, "uuid": "u", "password": "a"}
        self.assertNotEqual(node_id(p), node_id({**p, "password": "b"}))
        p = {**p, "type": "vless", "reality-opts": {"public-key": "a"}}
        self.assertNotEqual(node_id(p), node_id({**p, "reality-opts": {"public-key": "b"}}))
        self.assertEqual(node_id(p), node_id({**p, "name": "renamed"}))

    def test_merge_does_not_mutate_input_and_refreshes_name(self):
        p = record()["proxy"]; raw = {**p, "_source": "test"}; pl = {}
        pool.merge_collected(pl, [raw])
        self.assertIn("_source", raw)
        pool.merge_collected(pl, [{**p, "name": "renamed"}])
        self.assertEqual(next(iter(pl.values()))["proxy"]["name"], "renamed")

    def test_legacy_migration_and_backup_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pool.json"
            r = qualified(); r["id"] = "legacy"
            path.write_text(json.dumps({"legacy": r}), encoding="utf-8")
            loaded = pool.load(path)
            self.assertIn(node_id(r["proxy"]), loaded)
            pool.save(path, loaded)
            path.write_text("broken", encoding="utf-8")
            self.assertEqual(len(pool.load(path)), 1)

    def test_corrupt_pool_without_backup_stops(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pool.json"; path.write_text("[]", encoding="utf-8")
            with self.assertRaises(RuntimeError): pool.load(path)

    def test_concurrent_lock_fails_and_unlocks(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "lock"
            with run_lock(path):
                with self.assertRaises(RuntimeError):
                    with run_lock(path): pass
            with run_lock(path): pass


class ParserTests(unittest.TestCase):
    def test_anytls_certificate_verification(self):
        uri = "anytls://pass@8.8.8.8:443?tls-verification="
        self.assertFalse(parse.parse_uri(uri + "true").get("skip-cert-verify", False))
        self.assertTrue(parse.parse_uri(uri + "false")["skip-cert-verify"])

    def test_malformed_yaml_proxy_does_not_abort_other_nodes(self):
        text = yaml.safe_dump({"proxies": [{"type": []}, record()["proxy"], {"type": "http", "server": None, "port": 80}]})
        self.assertEqual(len(parse.extract_from_text(text)), 1)

    def test_missing_uuid_and_empty_password_rejected(self):
        self.assertIsNone(parse.parse_uri("vless://@8.8.8.8:443"))
        self.assertFalse(parse.validate({"type": "ss", "server": "8.8.8.8", "port": 80, "password": ""}))

    def test_ws_path_is_decoded_once(self):
        uri = "vless://11111111-1111-1111-1111-111111111111@8.8.8.8:443?type=ws&path=%2Fa%252Fb"
        self.assertEqual(parse.parse_uri(uri)["ws-opts"]["path"], "/a%2Fb")

    def test_ss_percent_password_and_plugin(self):
        p = parse.parse_uri("ss://aes-128-gcm:p%40ss@8.8.8.8:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dtest.com")
        self.assertEqual(p["password"], "p@ss")
        self.assertEqual(p["plugin-opts"]["host"], "test.com")

    def test_ss_base64_password_preserves_literal_percent(self):
        auth = base64.b64encode(b"aes-128-gcm:p%40ss").decode().rstrip("=")
        p = parse.parse_uri(f"ss://{auth}@8.8.8.8:443")
        self.assertEqual(p["password"], "p%40ss")

    def test_ssr_and_hysteria_uris(self):
        body = "8.8.8.8:443:origin:aes-128-cfb:plain:" + base64.urlsafe_b64encode(b"pass").decode().rstrip("=")
        uri = "ssr://" + base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
        self.assertEqual(parse.parse_uri(uri)["password"], "pass")
        self.assertEqual(parse.parse_uri("hysteria://8.8.8.8:443?auth=pass")["type"], "hysteria")

    def test_base64_subscription(self):
        text = base64.b64encode(b"anytls://pass@8.8.8.8:443").decode()
        self.assertEqual(len(parse.extract_from_text(text)), 1)


class OutputAndConfigTests(unittest.TestCase):
    def test_offline_validation_disables_dns_geoip_download(self):
        text = output.build_subscription([qualified()], config())[0]
        with patch.object(mihomo, "check_config") as check:
            mihomo.validate_subscription(Path("unused"), text)
        checked = yaml.safe_load(check.call_args.args[1])
        self.assertFalse(checked["dns"]["fallback-filter"]["geoip"])
        self.assertFalse(any(r.startswith("GEOIP,") for r in checked["rules"]))

    def test_empty_subscription_is_rejected(self):
        with self.assertRaises(ValueError): output.build_subscription([], config())

    def test_stable_group_and_manual_individual_selection(self):
        r = qualified(); r["stable"] = True
        text, stats = output.build_subscription([r], config())
        doc = yaml.safe_load(text)
        self.assertIn(config()["output"]["group_stable"], [g["name"] for g in doc["proxy-groups"]])
        self.assertIn(doc["proxies"][0]["name"], doc["proxy-groups"][0]["proxies"])
        self.assertEqual(stats["total"], 1)

    def test_tier_boundaries(self):
        tiers = config()["purity"]["tiers"]
        self.assertEqual(output.tier_of(15, tiers)[0], 1)
        self.assertEqual(output.tier_of(25, tiers)[0], 2)
        self.assertEqual(output.tier_of(40, tiers)[0], 2)

    def test_invalid_config_rejected(self):
        for section, key, value in (("collect", "max_candidates", -1), ("connectivity", "min_pass", 10),
                                    ("pool", "exploration_ratio", 0), ("mihomo", "base_listen_port", 65535)):
            cfg = config(); cfg[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate_config(cfg)


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "data/pool.json"
        self.cfg = config()
        self.rec = qualified()
        self.pl = {self.rec["id"]: self.rec}
        self.out = self.root / self.cfg["output"]["file"]
        self.out.parent.mkdir(parents=True)
        self.out.write_text("previous subscription", encoding="utf-8")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(update, "ROOT", self.root))
        self.stack.enter_context(patch.object(update, "make_session", return_value=Mock()))
        self.stack.enter_context(patch.object(publish, "load_token", return_value="test"))
        self.stack.enter_context(patch.object(mihomo, "ensure_binary", return_value=Path("unused")))
        self.stack.enter_context(patch.object(mihomo, "prune_invalid", side_effect=lambda exe, ps, *args: ps))
        self.stack.enter_context(patch.object(mihomo, "test_connectivity", side_effect=lambda exe, ps, cfg: {p["name"]: [10, 20, 30, 40] for p in ps}))
        self.probe = self.stack.enter_context(patch.object(mihomo, "probe_purity", return_value={}))
        self.validate = self.stack.enter_context(patch.object(mihomo, "validate_subscription"))
        self.publisher = self.stack.enter_context(patch.object(publish, "publish", return_value="stub://subscription"))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def run_update(self):
        pool.save(self.path, self.pl)
        return update._run(self.cfg, SimpleNamespace(skip_collect=True, no_publish=False))

    def test_expired_score_failure_keeps_previous_subscription(self):
        self.rec["purity"]["ts"] -= 25 * 3600
        self.assertEqual(self.run_update(), 4)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "previous subscription")
        self.publisher.assert_not_called()

    def test_failed_publish_returns_failure_and_saves_state(self):
        self.publisher.return_value = None
        self.assertEqual(self.run_update(), 3)
        saved = pool.load(self.path)[self.rec["id"]]
        self.assertEqual(saved["latency_ms"], 25)

    def test_publish_exception_still_saves_state(self):
        self.publisher.side_effect = requests.Timeout("stub")
        with self.assertRaises(requests.Timeout): self.run_update()
        self.assertEqual(pool.load(self.path)[self.rec["id"]]["latency_ms"], 25)

    def test_recent_unselected_node_is_kept_in_subscription(self):
        other = qualified("1.1.1.1"); self.pl[other["id"]] = other
        self.stack.enter_context(patch.object(pool, "select_candidates", side_effect=lambda pl, *args: [pl[self.rec["id"]]]))
        self.assertEqual(self.run_update(), 0)
        self.assertEqual(len(yaml.safe_load(self.out.read_text(encoding="utf-8"))["proxies"]), 2)

    def test_validation_failure_preserves_previous_output(self):
        self.validate.side_effect = RuntimeError("invalid")
        with self.assertRaises(RuntimeError): self.run_update()
        self.assertEqual(self.out.read_text(encoding="utf-8"), "previous subscription")
        self.publisher.assert_not_called()

    def test_latency_uses_median(self):
        self.assertEqual(update._alive_and_latency([10, 200, 300, None], 3), (True, 200))

    def test_empty_cache_recovers_stable_history(self):
        recovered = qualified(); recovered.update(stable=True, success_streak=5)
        self.pl = {}
        self.stack.enter_context(patch.object(publish, "restore_stable_pool", return_value={recovered["id"]: recovered}))
        self.assertEqual(self.run_update(), 0)
        self.assertTrue(pool.load(self.path)[recovered["id"]]["stable"])

    def test_old_nonempty_cache_merges_remote_stable_identity(self):
        recovered = copy.deepcopy(self.rec); recovered.update(stable=True, stable_since=123)
        self.stack.enter_context(patch.object(publish, "restore_stable_pool", return_value={recovered["id"]: recovered}))
        self.assertEqual(self.run_update(), 0)
        self.assertTrue(pool.load(self.path)[recovered["id"]]["stable"])

    def test_empty_cache_with_unreadable_backup_does_not_publish(self):
        self.pl = {}
        self.stack.enter_context(patch.object(publish, "restore_stable_pool", side_effect=RuntimeError("unavailable")))
        with self.assertRaises(RuntimeError): self.run_update()
        self.publisher.assert_not_called()
        self.assertEqual(self.out.read_text(encoding="utf-8"), "previous subscription")

    def test_unreadable_backup_with_local_cache_is_not_overwritten(self):
        self.stack.enter_context(patch.object(publish, "restore_stable_pool", side_effect=RuntimeError("unavailable")))
        self.assertEqual(self.run_update(), 0)
        self.assertIsNone(self.publisher.call_args.kwargs["records"])


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = config()
        self.content = output.build_subscription([qualified()], self.cfg)[0]
        self.env = patch.dict(os.environ, {"NODEPOOL_GIST_ID": "fixed", "GITHUB_ACTIONS": "true"})
        self.env.start(); self.addCleanup(self.env.stop)
        self.session = Mock()

    def response(self, code, data):
        return SimpleNamespace(status_code=code, json=lambda: data)

    def test_fixed_gist_404_does_not_create_another(self):
        self.session.request.return_value = self.response(404, {})
        self.assertIsNone(publish.publish(self.root, self.session, "test", self.content, self.cfg))
        self.assertEqual(self.session.request.call_count, 1)

    def test_public_target_is_rejected(self):
        self.session.request.return_value = self.response(200, {"public": True})
        self.assertIsNone(publish.publish(self.root, self.session, "test", self.content, self.cfg))
        self.assertEqual(self.session.request.call_count, 1)

    def test_patch_timeout_retries_same_target(self):
        self.session.request.side_effect = [self.response(200, {"public": False}), requests.Timeout(),
            self.response(200, {"id": "fixed", "owner": {"login": "owner"}})]
        with patch.object(publish.time, "sleep"):
            link = publish.publish(self.root, self.session, "test", self.content, self.cfg)
        self.assertEqual(link, "https://gist.githubusercontent.com/owner/fixed/raw/clash.yaml")
        self.assertEqual([c.args[0] for c in self.session.request.call_args_list], ["GET", "PATCH", "PATCH"])

    def test_empty_payload_is_never_sent(self):
        with self.assertRaises(ValueError): publish.publish(self.root, self.session, "test", "proxies: []", self.cfg)
        self.session.request.assert_not_called()

    def test_exhausted_timeout_returns_failure(self):
        self.session.request.side_effect = requests.Timeout()
        with patch.object(publish.time, "sleep"):
            self.assertIsNone(publish.publish(self.root, self.session, "test", self.content, self.cfg))
        self.assertEqual(self.session.request.call_count, 3)

    def test_subscription_update_backs_up_stable_records_only(self):
        r = qualified(); r["stable"] = True
        other = qualified("1.1.1.1")
        self.session.request.side_effect = [self.response(200, {"public": False}),
            self.response(200, {"id": "fixed", "owner": {"login": "owner"}})]
        publish.publish(self.root, self.session, "test", self.content, self.cfg,
                        records={r["id"]: r, other["id"]: other})
        payload = self.session.request.call_args.kwargs["json"]["files"]
        backup = json.loads(payload[self.cfg["publish"]["pool_filename"]]["content"])
        self.assertEqual(list(backup), [r["id"]])
        self.assertIn(self.cfg["publish"]["gist_filename"], payload)

    def test_restore_stable_pool_from_secret_gist(self):
        r = qualified(); r.update(stable=True, success_streak=5)
        self.session.request.return_value = self.response(200, {"public": False, "files": {
            self.cfg["publish"]["pool_filename"]: {"content": json.dumps({r["id"]: r})}}})
        restored = publish.restore_stable_pool(self.root, self.session, "test", self.cfg)
        self.assertTrue(restored[r["id"]]["stable"])
        self.assertEqual(restored[r["id"]]["success_streak"], 5)

    def test_restore_truncated_backup_uses_raw_content(self):
        r = qualified(); r["stable"] = True
        raw = SimpleNamespace(status_code=200, content=json.dumps({r["id"]: r}).encode("utf-8"))
        self.session.request.side_effect = [self.response(200, {"public": False, "files": {
            self.cfg["publish"]["pool_filename"]: {"truncated": True, "raw_url": "https://gist.githubusercontent.com/example/raw"}}}), raw]
        self.assertEqual(len(publish.restore_stable_pool(self.root, self.session, "test", self.cfg)), 1)

    def test_corrupt_remote_backup_stops_empty_cache_rebuild(self):
        self.session.request.return_value = self.response(200, {"public": False, "files": {
            self.cfg["publish"]["pool_filename"]: {"content": "broken"}}})
        with self.assertRaises(RuntimeError): publish.restore_stable_pool(self.root, self.session, "test", self.cfg)

    def test_backup_only_does_not_change_subscription(self):
        r = qualified(); r["stable"] = True
        self.session.request.side_effect = [self.response(200, {"public": False}), self.response(200, {})]
        self.assertTrue(publish.backup_stable_pool(self.root, self.session, "test", {r["id"]: r}, self.cfg))
        files = self.session.request.call_args.kwargs["json"]["files"]
        self.assertNotIn(self.cfg["publish"]["gist_filename"], files)
        self.assertIn(self.cfg["publish"]["pool_filename"], files)


class PurityProbeTests(unittest.TestCase):
    def test_invalid_json_shapes_and_null_scores_do_not_reach_callback(self):
        cfg = config(); cfg["purity"].update(stagger=0, concurrency=1)
        engine = Mock()
        engine.__enter__ = Mock(return_value=engine)
        engine.__exit__ = Mock(return_value=False)
        session = Mock()
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=False)
        session.get.return_value = SimpleNamespace(status_code=200, json=lambda: {"fraudScore": None})
        callback = Mock()
        with patch.object(mihomo, "Mihomo", return_value=engine), patch.object(mihomo.requests, "Session", return_value=session), patch("nodepool.util.resolve_ipv4", return_value=["1.1.1.1"]):
            self.assertEqual(mihomo.probe_purity(Path("unused"), [{**record()["proxy"], "name": "test"}], cfg, callback), {})
            callback.assert_not_called()
            self.assertEqual(session.get.call_count, 2)
            session.get.return_value = SimpleNamespace(status_code=200, json=lambda: [])
            self.assertEqual(mihomo.probe_purity(Path("unused"), [{**record()["proxy"], "name": "test"}], cfg, callback), {})

    def test_batch_size_limits_listener_count(self):
        cfg = config(); cfg["purity"]["batch_size"] = 2
        ps = [{**record()["proxy"], "name": str(i)} for i in range(5)]
        with patch.object(mihomo, "_probe_batch", return_value={}) as probe:
            mihomo.probe_purity(Path("unused"), ps, cfg)
        self.assertEqual([len(call.args[1]) for call in probe.call_args_list], [2, 2, 1])


class ControllerPortTests(unittest.TestCase):
    def engine(self, address):
        controller = f"{address[0]}:{address[1]}"
        return mihomo.Mihomo(Path("unused"), mihomo.build_test_config([], controller, "test"),
                             controller, "test", 2)

    @unittest.skipIf(os.name == "nt", "Unix TIME_WAIT port reuse")
    def test_recently_closed_controller_can_restart(self):
        # Reproduce a server-initiated close so the controller port, rather
        # than the client's ephemeral port, remains in TIME_WAIT.
        with socket.socket() as listener, socket.socket() as client:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0)); listener.listen()
            address = listener.getsockname()
            client.settimeout(2)
            client.connect(address)
            connection, _ = listener.accept()
            connection.close()
            self.assertEqual(client.recv(1), b"")
        with socket.socket() as check:
            with self.assertRaises(OSError): check.bind(address)
        m = self.engine(address)
        proc = Mock(); proc.poll.return_value = None
        with patch.object(mihomo.subprocess, "Popen", return_value=proc), patch.object(m.sess, "get", return_value=SimpleNamespace(status_code=200, json=lambda: {"version": "test"})):
            with m: pass
        self.assertFalse(Path(m._dir).exists())

    def test_active_controller_is_rejected_even_if_reusable(self):
        with socket.socket() as listener:
            if os.name != "nt":
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0)); listener.listen()
            m = self.engine(listener.getsockname())
            with patch.object(mihomo.subprocess, "Popen") as start:
                with self.assertRaises(OSError):
                    with m: pass
                start.assert_not_called()
            self.assertFalse(Path(m._dir).exists())


EXE = ROOT / "bin" / ("mihomo.exe" if os.name == "nt" else "mihomo")


@unittest.skipUnless(EXE.exists(), "local mihomo binary unavailable")
class NativeMihomoTests(unittest.TestCase):
    def test_configs_and_generated_subscription(self):
        cfg = config(); ps = [{**qualified()["proxy"], "name": "demo"}]
        mihomo.check_config(EXE, mihomo.build_test_config(ps, "127.0.0.1:19090", "test"))
        text, ports = mihomo.build_purity_config(ps, "127.0.0.1:19090", "test", 20000)
        mihomo.check_config(EXE, text)
        text = output.build_subscription([qualified()], cfg)[0]
        mihomo.validate_subscription(EXE, text)

    def test_invalid_proxy_is_pruned(self):
        ps = [{"name": "bad", "type": "unsupported", "server": "8.8.8.8", "port": 443},
              {**qualified()["proxy"], "name": "good"}]
        valid = mihomo.prune_invalid(EXE, ps, "127.0.0.1:19090", "test", 10)
        self.assertEqual([p["name"] for p in valid], ["good"])

    def test_process_starts_stops_and_cleans_temporary_files(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        controller = f"127.0.0.1:{port}"
        for _ in range(3):
            m = mihomo.Mihomo(EXE, mihomo.build_test_config([], controller, "test"), controller, "test", 10)
            directory = Path(m._dir)
            with m: self.assertTrue(directory.exists())
            self.assertFalse(directory.exists())

    def test_occupied_controller_is_not_reused(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); sock.listen()
            controller = f"127.0.0.1:{sock.getsockname()[1]}"
            m = mihomo.Mihomo(EXE, mihomo.build_test_config([], controller, "test"), controller, "test", 2)
            with self.assertRaises(OSError):
                with m: pass
            self.assertFalse(Path(m._dir).exists())


if __name__ == "__main__":
    unittest.main()
