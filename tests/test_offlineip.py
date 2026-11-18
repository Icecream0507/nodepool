import hashlib
import hmac
import unittest
from unittest import mock

from offlineip import Client, OfflineIPError, canonical_query, sign


class SigningTest(unittest.TestCase):
    def test_canonical_query_sorts_and_reencodes(self):
        self.assertEqual(canonical_query(""), "")
        self.assertEqual(canonical_query("b=2&a=x%20y&a=1"), "a=1&a=x%20y&b=2")
        self.assertEqual(canonical_query("q=a+b!"), "q=a%2Bb%21")
        self.assertEqual(canonical_query("flag"), "flag=")

    def test_signature_matches_documented_canonical_string(self):
        canonical = "\n".join(["GET", "www.offlineip.com", "/api/v1/proxies", "page_size=100",
                               "2026-08-17T12:00:00Z", "nce_1", hashlib.sha256(b"").hexdigest()])
        expected = hmac.new(b"sk_test", canonical.encode(), hashlib.sha256).hexdigest()
        got = sign("sk_test", "get", "https://WWW.offlineip.com:443/api/v1/proxies?page_size=100",
                   "2026-08-17T12:00:00Z", "nce_1")
        self.assertEqual(got, expected)


class ClientTest(unittest.TestCase):
    def _response(self, payload):
        r = mock.Mock(status_code=200)
        r.json.return_value = payload
        return r

    def test_proxies_follows_pages(self):
        session = mock.Mock()
        session.get.side_effect = [
            self._response({"success": True, "data": {"proxies": [{"host": "a"}], "has_more": True,
                                                       "next_page_token": "t1"}}),
            self._response({"success": True, "data": {"proxies": [{"host": "b"}], "has_more": False}}),
        ]
        items = Client("app", "sk", session=session).proxies()
        self.assertEqual([p["host"] for p in items], ["a", "b"])
        second_url = session.get.call_args_list[1].args[0]
        self.assertIn("page_token=t1", second_url)
        headers = session.get.call_args_list[0].kwargs["headers"]
        self.assertEqual(headers["X-API-AppId"], "app")
        self.assertRegex(headers["X-API-Signature"], "^[0-9a-f]{64}$")

    def test_error_envelope_raises(self):
        session = mock.Mock()
        session.get.return_value = self._response({"success": False, "code": "invalid_signature",
                                                   "message": "bad", "trace_id": "trc"})
        with self.assertRaisesRegex(OfflineIPError, "invalid_signature"):
            Client("app", "sk", session=session).account()


if __name__ == "__main__":
    unittest.main()
