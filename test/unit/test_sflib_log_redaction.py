# test_sflib_log_redaction.py
"""Secrets in URLs must never reach logs (AETHER doctrine section 7)."""
import time
import unittest
from unittest.mock import MagicMock, patch

import pytest
import requests

from sflib import SpiderFoot

SECRET = "S3CRET-value-123"


class TestRemoveUrlCreds(unittest.TestCase):

    def setUp(self):
        self.sf = SpiderFoot({'_debug': False, '__logging': False})

    def test_redacts_every_key_style_used_by_modules(self):
        for url in (
            f"http://api.nameapi.org/rest/v5.3/email/x?apiKey={SECRET}&emailAddress=a@b.com",
            f"https://x/?key={SECRET}&pass={SECRET}&user={SECRET}&password={SECRET}",
            f"https://x/api?access_key={SECRET}&q=1",
            f"https://x/?api_token={SECRET}",
            f"https://x/?a=1&KEY={SECRET}",
            f"https://x/?apikey={SECRET}",
            f"https://x/?auth={SECRET}#frag",
            f"https://x/?session_id={SECRET}&sig={SECRET}&X-Api-Key={SECRET}",
            f"https://user:{SECRET}@host/path",
            f"HTTPSConnectionPool(host='x', port=443): Max retries exceeded with url: /v1?apiKey={SECRET} (Caused by X)",
        ):
            with self.subTest(url=url):
                self.assertNotIn(SECRET, self.sf.removeUrlCreds(url))

    def test_non_secret_parameters_are_kept(self):
        url = "https://x/?q=example.com&page=2&keyword=abc&emailAddress=a@b.com"
        self.assertEqual(self.sf.removeUrlCreds(url), url)

    def test_non_string_input(self):
        self.assertEqual(self.sf.removeUrlCreds(ValueError(f"?key={SECRET}")), "?key=XXX")

    def test_linear_time_on_adversarial_input(self):
        for evil in ("a_" * 200000, "a=" * 200000, "x" * 400000 + "key", "h://" * 100000, "_a" * 200000 + "@"):
            start = time.monotonic()
            self.sf.removeUrlCreds(evil)
            self.assertLess(time.monotonic() - start, 2.0)


@pytest.mark.usefixtures
class TestFetchUrlErrorLogging(unittest.TestCase):

    def test_connection_error_does_not_log_secret(self):
        sf = SpiderFoot(dict(self.default_options, _debug=True, __logging=True))
        url = f"https://api.example.invalid/v1?apiKey={SECRET}&q=1"
        session = MagicMock()
        session.get.side_effect = requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='api.example.invalid', port=443): Max retries exceeded with url: /v1?apiKey={SECRET}&q=1")
        with patch.object(sf, 'getSession', return_value=session), \
                self.assertLogs(sf.log, level='DEBUG') as logs:
            res = sf.fetchUrl(url)
        self.assertIsNone(res['content'])
        joined = "\n".join(logs.output)
        self.assertIn("apiKey=XXX", joined)
        self.assertNotIn(SECRET, joined)

    def test_unexpected_error_does_not_log_secret_or_traceback(self):
        sf = SpiderFoot(dict(self.default_options, _debug=True, __logging=True))
        url = f"https://api.example.invalid/v1?key={SECRET}"
        session = MagicMock()
        session.get.side_effect = RuntimeError(f"boom while fetching {url}")
        with patch.object(sf, 'getSession', return_value=session), \
                self.assertLogs(sf.log, level='DEBUG') as logs:
            sf.fetchUrl(url)
        for record in logs.records:
            self.assertNotIn(SECRET, record.getMessage())
            self.assertIsNone(record.exc_info)
