import unittest

import yaml

from chain_sub import GROUP_MAIN, GROUP_OUT, build_config, expiry_date, landing_name, parse_proxy


class ParseProxyTest(unittest.TestCase):
    def test_segment_format_defaults_to_socks5(self):
        p = parse_proxy("133.157.53.81:7077:user:pass")
        self.assertEqual(p, {"type": "socks5", "server": "133.157.53.81", "port": 7077,
                             "username": "user", "password": "pass", "udp": True})

    def test_segment_type_override(self):
        self.assertEqual(parse_proxy("1.2.3.4:80:u:p", "http")["type"], "http")

    def test_urls_keep_scheme(self):
        p = parse_proxy("http://u%40x:p@1.2.3.4:8080")
        self.assertEqual((p["type"], p["username"], p["port"]), ("http", "u@x", 8080))
        self.assertEqual(parse_proxy("socks5h://u:p@h:1")["type"], "socks5")

    def test_at_format_and_no_auth(self):
        self.assertEqual(parse_proxy("u:p@1.2.3.4:9")["username"], "u")
        self.assertNotIn("username", parse_proxy("1.2.3.4:9"))

    def test_rejects_bad_input(self):
        for bad in ("", "1.2.3.4", "1.2.3.4:x:u:p", "1.2.3.4:70000", "ftp://1.2.3.4:21", "a:b:c"):
            with self.assertRaises(ValueError, msg=bad):
                parse_proxy(bad)


class BuildConfigTest(unittest.TestCase):
    def test_chain_structure(self):
        cfg = yaml.safe_load(build_config(parse_proxy("1.2.3.4:9:u:p"), "JP-x", "https://e/x.yaml"))
        landing = cfg["proxies"][0]
        self.assertEqual(landing["dialer-proxy"], GROUP_OUT)
        self.assertFalse(cfg["ipv6"])
        self.assertEqual(cfg["proxy-providers"]["front"]["url"], "https://e/x.yaml")
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        self.assertEqual(groups[GROUP_OUT]["use"], ["front"])
        self.assertEqual(groups[GROUP_MAIN]["proxies"][0], "JP-x")

    def test_provider_download_bypasses_chain(self):
        rules = yaml.safe_load(build_config(parse_proxy("1.2.3.4:9"), "n", "https://e"))["rules"]
        self.assertTrue(rules[0].startswith("DOMAIN-SUFFIX,githubusercontent.com,DIRECT"))
        self.assertEqual(rules[-1], f"MATCH,{GROUP_MAIN}")

    def test_custom_front(self):
        cfg = yaml.safe_load(build_config(parse_proxy("1.2.3.4:9"), "n", "https://air.example/sub?t=1",
                                          front="良心云", exclude="剩余流量|套餐到期", include="新加坡"))
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        self.assertEqual(groups["出海(良心云)"]["exclude-filter"], "剩余流量|套餐到期")
        self.assertEqual(groups["出海(良心云)"]["filter"], "新加坡")
        self.assertEqual(cfg["proxies"][0]["dialer-proxy"], "出海(良心云)")
        self.assertIn("DOMAIN,air.example,DIRECT", cfg["rules"])

    def test_local_front_tests_whole_chain(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "air.yaml"
            src.write_text(yaml.safe_dump({"proxies": [
                {"name": "剩余流量：1G", "type": "socks5", "server": "x", "port": 1},
                {"name": "A", "type": "socks5", "server": "a", "port": 1}]}, allow_unicode=True),
                encoding="utf-8")
            cfg = yaml.safe_load(build_config(parse_proxy("1.2.3.4:9"), "JP", str(src),
                                              front="lxy", exclude="剩余流量"))
        self.assertNotIn("proxy-providers", cfg)
        by_name = {p["name"]: p for p in cfg["proxies"]}
        self.assertEqual(set(by_name), {"A", "JP ← A"})
        self.assertEqual(by_name["JP ← A"]["dialer-proxy"], "A")
        auto, main = cfg["proxy-groups"]
        self.assertEqual((auto["type"], auto["proxies"]), ("url-test", ["JP ← A"]))
        self.assertEqual((main["name"], main["proxies"][0]), (GROUP_MAIN, auto["name"]))


class ExpiryTest(unittest.TestCase):
    def test_iso_timestamp_in_beijing_time(self):
        self.assertEqual(expiry_date("2026-12-17T11:01:11.000Z"), "2026-12-17")
        self.assertEqual(expiry_date("2026-12-17T20:00:00Z"), "2026-12-18")

    def test_plain_and_missing(self):
        self.assertEqual(expiry_date("2026-12-17"), "2026-12-17")
        self.assertIsNone(expiry_date(None))
        self.assertEqual(expiry_date("下月"), "下月")

    def test_name(self):
        self.assertEqual(landing_name("JP-x", "2026-12-17"), "JP-x | 到期2026-12-17")
        self.assertEqual(landing_name("JP-x", None), "JP-x")


if __name__ == "__main__":
    unittest.main()
