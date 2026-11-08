import base64
import json
import pytest
import unittest
from unittest.mock import patch

from modules.sfp_chainabuse import sfp_chainabuse
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget

ADDR = "12QeMLzSrB8XH8FvEzPMVoRxVAzTr5XM2y"
KEY = "chainabuse-secret-key"


def report(rid="52907745-7672-470e-a803-a2f8feb52944", category="RUG_PULL", addr=ADDR, created="2022-09-09T04:53:16.591Z", **extra):
    r = {
        "id": rid, "trusted": True, "checked": False, "scamCategory": category, "createdAt": created,
        "description": "Victim Jane Doe jane@example.com lost money", "descriptionMarkdown": "x",
        "addresses": [{"address": addr, "chain": "BTC", "domain": None}],
        "losses": [{"amount": 1000, "asset": "USD"}], "ips": ["203.0.113.9"], "evidences": ["https://evidence"],
    }
    r.update(extra)
    return r


@pytest.mark.usefixtures
class TestModuleChainabuse(unittest.TestCase):

    def _module(self, **opts):
        base = {'api_key': KEY, 'max_queries': 5, '_fetchtimeout': 5}
        base.update(opts)
        module = sfp_chainabuse()
        module.setup(SpiderFoot(self.default_options), base)
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, response, etype='BITCOIN_ADDRESS'):
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent(etype, data, 'test', root)
        emitted = []
        with patch.object(module.sf, 'fetchUrl', return_value=response) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    @staticmethod
    def ok(reports):
        return {'code': '200', 'content': json.dumps({'reports': reports, 'count': len(reports)})}

    def test_opts(self):
        module = sfp_chainabuse()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sfp_chainabuse().setup(SpiderFoot(self.default_options), dict())

    def test_watched_and_produced_events(self):
        self.assertEqual(sorted(sfp_chainabuse().watchedEvents()), ["BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"])
        self.assertIsInstance(sfp_chainabuse().producedEvents(), list)

    def test_no_api_key_sets_errorState(self):
        module = self._module(api_key='')
        fetch, emitted = self._run(module, ADDR, self.ok([]))
        fetch.assert_not_called()
        self.assertTrue(module.errorState)

    def test_request_uses_basic_auth_header_and_no_key_in_url(self):
        module = self._module()
        fetch, emitted = self._run(module, ADDR, self.ok([report()]))
        args, kwargs = fetch.call_args
        self.assertEqual(args[0], f"https://api.chainabuse.com/v0/reports?address={ADDR}&perPage=50")
        self.assertNotIn(KEY, args[0])
        expected = base64.b64encode(f"{KEY}:{KEY}".encode()).decode()
        self.assertEqual(kwargs['headers']['Authorization'], f"Basic {expected}")

    def test_emits_minimal_summary_without_victim_data(self):
        reports = [report(), report(rid="a-1", category="PHISHING", created="2024-01-02T00:00:00Z", trusted=False, checked=True)]
        _, emitted = self._run(self._module(), ADDR, self.ok(reports))
        by_type = {e.eventType: e.data for e in emitted}
        self.assertEqual(by_type["MALICIOUS_BITCOIN_ADDRESS"],
                         f"Chainabuse [{ADDR}] (2 report(s): PHISHING, RUG_PULL)\n<SFURL>https://chainabuse.com/address/{ADDR}</SFURL>")
        summary = json.loads(by_type["RAW_RIR_DATA"])
        self.assertEqual(summary['reports'], 2)
        self.assertEqual(summary['trusted_reports'], 1)
        self.assertEqual(summary['checked_reports'], 1)
        self.assertEqual(summary['latest_report'], "2024-01-02")
        for e in emitted:
            for secret in ("Jane", "jane@example.com", "203.0.113.9", "evidence", "1000", KEY):
                self.assertNotIn(secret, e.data)

    def test_reports_not_listing_the_address_are_ignored(self):
        _, emitted = self._run(self._module(), ADDR, self.ok([report(addr="1OtherAddressXXXXXXXXXXXXXXXXXXX")]))
        self.assertEqual(emitted, [])

    def test_untrusted_fields_are_allow_listed(self):
        bad = report(rid="<script>", category="<b>PHISH</b>", created="garbage")
        _, emitted = self._run(self._module(), ADDR, self.ok([bad]))
        summary = json.loads([e.data for e in emitted if e.eventType == "RAW_RIR_DATA"][0])
        self.assertEqual(summary['categories'], [])
        self.assertEqual(summary['report_ids'], [])
        self.assertIsNone(summary['latest_report'])

    def test_malformed_address_is_not_queried(self):
        for data in ("short", "x" * 101, f"{ADDR}&perPage=1", f"{ADDR}/../x", "addr with spaces 12345678901"):
            with self.subTest(data=data):
                fetch, _ = self._run(self._module(), data, self.ok([]))
                fetch.assert_not_called()

    def test_per_scan_query_cap(self):
        module = self._module(max_queries=2)
        calls = 0
        for i in range(5):
            fetch, _ = self._run(module, f"1{'A' * 25}{i}", self.ok([]))
            calls += fetch.call_count
        self.assertEqual(calls, 2)

    def test_query_cap_is_clamped(self):
        self.assertEqual(self._module(max_queries=10 ** 9).queryLimit(), sfp_chainabuse.MAX_QUERIES_HARD)
        self.assertEqual(self._module(max_queries=-3).queryLimit(), 0)
        self.assertEqual(self._module(max_queries="x").queryLimit(), 0)

    def test_duplicate_address_queried_once(self):
        module = self._module()
        self._run(module, ADDR, self.ok([]))
        fetch, _ = self._run(module, ADDR, self.ok([]))
        fetch.assert_not_called()

    def test_quota_and_auth_errors_stop_module(self):
        for code in ('401', '403', '429', '500'):
            with self.subTest(code=code):
                module = self._module()
                _, emitted = self._run(module, ADDR, {'code': code, 'content': '{"reason": "x"}'})
                self.assertTrue(module.errorState)
                self.assertEqual(emitted, [])

    def test_bad_request_is_not_fatal(self):
        module = self._module()
        _, emitted = self._run(module, ADDR, {'code': '400', 'content': '{"reason": "bad address"}'})
        self.assertFalse(module.errorState)
        self.assertEqual(emitted, [])

    def test_bad_json_emits_nothing(self):
        for content in ('nope', '[]', '{"reports": "x"}', '{"reports": [1, "a"]}', ''):
            with self.subTest(content=content):
                _, emitted = self._run(self._module(), ADDR, {'code': '200', 'content': content})
                self.assertEqual(emitted, [])

    def test_ethereum_address_case_insensitive_match(self):
        eth = "0x52908400098527886E0F7030069857D2E4169EE7"
        rep = report(addr=eth.lower(), category="PHISHING")
        fetch, emitted = self._run(self._module(), eth, self.ok([rep]), etype='ETHEREUM_ADDRESS')
        self.assertIn(f"address={eth.lower()}", fetch.call_args[0][0])
        by_type = {e.eventType: e.data for e in emitted}
        self.assertIn("MALICIOUS_ETHEREUM_ADDRESS", by_type)
        self.assertNotIn("MALICIOUS_BITCOIN_ADDRESS", by_type)
        self.assertTrue(by_type["MALICIOUS_ETHEREUM_ADDRESS"].startswith(f"Chainabuse [{eth.lower()}] (1 report(s): PHISHING)"))

    def test_malformed_ethereum_address_not_queried(self):
        for data in ("0x123", "52908400098527886E0F7030069857D2E4169EE7", "0x" + "g" * 40, "0x" + "a" * 41):
            with self.subTest(data=data):
                fetch, _ = self._run(self._module(), data, self.ok([]), etype='ETHEREUM_ADDRESS')
                fetch.assert_not_called()
