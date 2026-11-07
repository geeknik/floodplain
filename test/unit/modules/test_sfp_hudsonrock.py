import json
import pytest
import unittest
from unittest.mock import patch

from modules.sfp_hudsonrock import sfp_hudsonrock
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


SECRET_PASSWORD = "Hunter2-SuperSecret!"
VICTIM_IP = "203.0.113.77"
VICTIM_HOST = "DESKTOP-VICTIM01"


def infection(family="Lumma", date="2025-01-25T12:03:26.000Z", creds=None):
    return {
        "_id": "abc123",
        "stealer": "x",
        "stealer_family": family,
        "date_compromised": date,
        "date_uploaded": "2025-02-03T09:30:52.468Z",
        "ip": VICTIM_IP,
        "computer_name": VICTIM_HOST,
        "operating_system": "Windows 10",
        "malware_path": "C:\\Users\\victim\\AppData\\evil.exe",
        "credentials": creds if creds is not None else [],
    }


def cred(url, username, ctype="employee", domain="example.com"):
    return {"url": url, "domain": domain, "username": username, "password": SECRET_PASSWORD, "type": ctype}


@pytest.mark.usefixtures
class TestModuleHudsonrock(unittest.TestCase):

    def _module(self, opts=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_hudsonrock()
        module.setup(sf, opts if opts is not None else {'api_key': 'test-key'})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _event(self, etype, data):
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        return SpiderFootEvent(etype, data, 'test', root)

    def _run(self, module, evt, responses):
        emitted = []
        if not isinstance(responses, list):
            responses = [responses]
        with patch.object(module.sf, 'fetchUrl', side_effect=responses) as fetch, \
             patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    def _ok(self, data, cursor=None):
        body = {"data": data}
        if cursor is not None:
            body["nextCursor"] = cursor
        return {'code': '200', 'content': json.dumps(body)}

    def assertNoSensitiveData(self, emitted):
        for e in emitted:
            for secret in (SECRET_PASSWORD, VICTIM_IP, VICTIM_HOST, "evil.exe"):
                self.assertNotIn(secret, e.data)

    def test_opts(self):
        module = sfp_hudsonrock()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_hudsonrock()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        self.assertIsInstance(sfp_hudsonrock().watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        self.assertIsInstance(sfp_hudsonrock().producedEvents(), list)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        module = self._module({'api_key': ''})
        fetch, emitted = self._run(module, self._event('DOMAIN_NAME', 'example.com'), [])
        fetch.assert_not_called()
        self.assertTrue(module.errorState)
        self.assertEqual(emitted, [])

    def test_email_lookup_should_emit_compromised_per_infection_and_send_key_in_header(self):
        module = self._module()
        data = [infection("Lumma", "2025-01-25T00:00:00Z"),
                infection("RedLine", "2024-06-01T00:00:00Z"),
                infection("Lumma", "2025-01-25T09:00:00Z")]  # same family+day: deduped
        fetch, emitted = self._run(module, self._event('EMAILADDR', 'Alice@Example.com'), self._ok(data))

        args, kwargs = fetch.call_args
        self.assertEqual(args[0], "https://api.hudsonrock.com/json/v3/search-by-login/emails")
        self.assertEqual(kwargs['headers']['api-key'], 'test-key')
        self.assertNotIn('test-key', args[0])
        self.assertEqual(json.loads(kwargs['postData'])['logins'], ['alice@example.com'])

        got = sorted(e.data for e in emitted)
        self.assertEqual(got, [
            "alice@example.com [Hudson Rock infostealer: Lumma, 2025-01-25]",
            "alice@example.com [Hudson Rock infostealer: RedLine, 2024-06-01]",
        ])
        self.assertTrue(all(e.eventType == "EMAILADDR_COMPROMISED" for e in emitted))
        self.assertNoSensitiveData(emitted)

    def test_domain_lookup_should_summarise_and_discover_target_hosts_only(self):
        module = self._module()
        data = [
            infection("Lumma", "2025-01-25T00:00:00Z", [
                cred("https://sso.example.com/adfs/ls", "bob@example.com", "employee"),
                cred("https://vpn.example.com/login", "\u2022\u2022\u2022@example.com", "employee"),
                cred("https://www.example.com/login", "someone@gmail.com", "user"),
                cred("https://ticketsatwork.com/tickets", "carol@example.com", "third_party", "ticketsatwork.com"),
            ]),
            infection("Vidar", "2024-03-02T00:00:00Z", [
                cred("https://evil.com/?r=sso.example.com", "dave@example.com", "employee"),
            ]),
        ]
        _, emitted = self._run(module, self._event('DOMAIN_NAME', 'example.com'), self._ok(data))

        by_type = {}
        for e in emitted:
            by_type.setdefault(e.eventType, []).append(e.data)

        summary = json.loads(by_type["RAW_RIR_DATA"][0])
        self.assertEqual(summary['infections'], 2)
        self.assertEqual(summary['credential_types'], {"employee": 3, "user": 1, "third_party": 1})
        self.assertEqual(summary['stealer_families'], ["Lumma", "Vidar"])
        self.assertEqual(summary['latest_compromise'], "2025-01-25")

        # Hostnames on the target only; never third-party or query-string hosts.
        self.assertEqual(sorted(by_type["INTERNET_NAME"]),
                         ["sso.example.com", "vpn.example.com", "www.example.com"])

        # Only uncensored addresses on the target domain.
        compromised = sorted(by_type["EMAILADDR_COMPROMISED"])
        self.assertEqual([c.split(' ')[0] for c in compromised],
                         ["bob@example.com", "carol@example.com", "dave@example.com"])
        self.assertNoSensitiveData(emitted)

    def test_pagination_should_follow_cursor_up_to_max_pages(self):
        module = self._module({'api_key': 'k', 'max_pages': 2})
        page1 = self._ok([infection("Lumma")], cursor="MjAyNC0xMS0xMg==")
        page2 = self._ok([infection("RedLine", "2024-01-01T00:00:00Z")], cursor="bmV4dA==")
        fetch, emitted = self._run(module, self._event('EMAILADDR', 'a@example.com'), [page1, page2])
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(json.loads(fetch.call_args_list[1][1]['postData'])['cursor'], "MjAyNC0xMS0xMg==")
        self.assertEqual(len(emitted), 2)

    def test_malformed_cursor_should_stop_pagination(self):
        module = self._module({'api_key': 'k', 'max_pages': 5})
        page1 = self._ok([infection("Lumma")], cursor="not a cursor; DROP")
        fetch, _ = self._run(module, self._event('EMAILADDR', 'a@example.com'), [page1])
        self.assertEqual(fetch.call_count, 1)

    def test_max_pages_should_be_hard_capped(self):
        module = self._module({'api_key': 'k', 'max_pages': 10 ** 6})
        pages = [self._ok([infection("Lumma")], cursor="Y3Vyc29y")] * 20
        fetch, _ = self._run(module, self._event('EMAILADDR', 'a@example.com'), pages)
        self.assertEqual(fetch.call_count, sfp_hudsonrock.MAX_PAGES_HARD)

    def test_auth_failure_should_set_errorState(self):
        for code in ("401", "403", "429"):
            with self.subTest(code=code):
                module = self._module()
                _, emitted = self._run(module, self._event('DOMAIN_NAME', 'example.com'),
                                       {'code': code, 'content': '{"error":"x"}'})
                self.assertTrue(module.errorState)
                self.assertEqual(emitted, [])

    def test_bad_responses_should_emit_nothing(self):
        for resp in ({'code': '200', 'content': 'not json'},
                     {'code': '200', 'content': '{"data": "nope"}'},
                     {'code': '200', 'content': '[1,2,3]'},
                     {'code': '500', 'content': ''},
                     {'code': '404', 'content': ''}):
            with self.subTest(resp=resp):
                module = self._module()
                _, emitted = self._run(module, self._event('DOMAIN_NAME', 'example.com'), resp)
                self.assertEqual(emitted, [])

    def test_invalid_input_should_not_query(self):
        module = self._module()
        for etype, value in (('EMAILADDR', 'not-an-email'), ('DOMAIN_NAME', 'bad domain!'),
                             ('DOMAIN_NAME', '-lead.example.com')):
            with self.subTest(value=value):
                fetch, emitted = self._run(module, self._event(etype, value), [])
                fetch.assert_not_called()
                self.assertEqual(emitted, [])

    def test_untrusted_family_and_date_are_sanitised(self):
        module = self._module()
        data = [infection("<script>alert(1)</script>", "garbage")]
        _, emitted = self._run(module, self._event('EMAILADDR', 'a@example.com'), self._ok(data))
        self.assertEqual(emitted[0].data,
                         "a@example.com [Hudson Rock infostealer: unknown family, unknown date]")
