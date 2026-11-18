import unittest

import yaml

from chain_sub import GROUP_MAIN, GROUP_OUT, build_config, parse_proxy


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
        self.assertEqual(cfg["proxy-providers"]["freenode"]["url"], "https://e/x.yaml")
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        self.assertEqual(groups[GROUP_OUT]["use"], ["freenode"])
        self.assertEqual(groups[GROUP_MAIN]["proxies"][0], "JP-x")

    def test_provider_download_bypasses_chain(self):
        rules = yaml.safe_load(build_config(parse_proxy("1.2.3.4:9"), "n", "https://e"))["rules"]
        self.assertTrue(rules[0].startswith("DOMAIN-SUFFIX,githubusercontent.com,DIRECT"))
        self.assertEqual(rules[-1], f"MATCH,{GROUP_MAIN}")


if __name__ == "__main__":
    unittest.main()
