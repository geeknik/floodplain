import pytest
import unittest

from modules.sfp_koodous import sfp_koodous
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleKoodous(unittest.TestCase):

    def test_opts(self):
        module = sfp_koodous()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_koodous()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_koodous()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_koodous()
        self.assertIsInstance(module.producedEvents(), list)

    def test_parseApiResponse_nonfatal_http_response_code_should_not_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        http_codes = ["200", "404"]
        for code in http_codes:
            with self.subTest(code=code):
                module = sfp_koodous()
                module.setup(sf, dict())
                result = module.parseApiResponse({"code": code, "content": None})
                self.assertEqual(result, {'results': []})
                self.assertFalse(module.errorState)

    def test_parseApiResponse_fatal_http_response_error_code_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        http_codes = ["401", "402", "403", "429", "500", "502", "503"]
        for code in http_codes:
            with self.subTest(code=code):
                module = sfp_koodous()
                module.setup(sf, dict())
                result = module.parseApiResponse({"code": code, "content": None})
                self.assertIsNone(result)
                self.assertTrue(module.errorState)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_koodous()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'EMAILADDR'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)


SHA = "ca9139a9978f306d07da26d6b299661af67f99e6b1e2f1c19f29b11fb44eb429"


@pytest.mark.usefixtures
class TestModuleKoodousBehaviour(unittest.TestCase):

    def _module(self, **opts):
        module = sfp_koodous()
        base = {'api_key': 'koodous-token', 'max_pages': 10, '_fetchtimeout': 5}
        base.update(opts)
        module.setup(SpiderFoot(self.default_options), base)
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, responses):
        from unittest.mock import patch
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('DOMAIN_NAME', data, 'test', root)
        emitted = []
        with patch.object(module.sf, 'fetchUrl', side_effect=responses) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append), \
                patch('modules.sfp_koodous.time.sleep'):
            module.handleEvent(evt)
        return fetch, emitted

    @staticmethod
    def page(results, next_url=None):
        import json
        return {'code': '200', 'content': json.dumps({'results': results, 'next': next_url})}

    def test_no_results_does_not_disable_module(self):
        module = self._module()
        self._run(module, 'example.com', [{'code': '404', 'content': ''}])
        self.assertFalse(module.errorState)
        fetch, _ = self._run(module, 'example.org', [self.page([])])
        fetch.assert_called_once()

    def test_matching_app_is_emitted_with_safe_markup(self):
        result = {'package_name': 'com.example.app', 'app': 'Evil<SFURL>x</SFURL>', 'version': '1.0<b>', 'sha256': SHA.upper()}
        _, emitted = self._run(self._module(), 'example.com', [self.page([result])])
        entries = [e.data for e in emitted if e.eventType == 'APPSTORE_ENTRY']
        self.assertEqual(entries, [f"EvilSFURLx/SFURL 1.0b (com.example.app)\n<SFURL>https://koodous.com/apks/{SHA}</SFURL>"])

    def test_invalid_records_are_skipped(self):
        bad = [
            "not-a-dict",
            {'package_name': 'com.example.app', 'app': 'A', 'sha256': 'not-a-hash'},
            {'package_name': 'com.example.app', 'app': 'A', 'sha256': SHA + "</SFURL>"},
            {'package_name': 'com example app', 'app': 'A', 'sha256': SHA},
            {'package_name': 'com.other.app', 'app': 'A', 'sha256': SHA},
            {'package_name': 'com.example.app', 'app': None, 'sha256': SHA},
        ]
        _, emitted = self._run(self._module(), 'example.com', [self.page(bad)])
        self.assertEqual(emitted, [])

    def test_pagination_follows_valid_cursor_and_is_hard_capped(self):
        nxt = "https://developer.koodous.com/apks/?cursor=cD0yMDIy&search=x"
        module = self._module(max_pages=10 ** 6)
        fetch, _ = self._run(module, 'example.com', [self.page([], nxt)] * 60)
        self.assertEqual(fetch.call_count, sfp_koodous.MAX_PAGES_HARD)
        self.assertIn("cursor=cD0yMDIy", fetch.call_args_list[1][0][0])

    def test_malformed_cursor_stops_pagination(self):
        nxt = "https://developer.koodous.com/apks/?cursor=%3Cscript%3E&search=x"
        fetch, _ = self._run(self._module(), 'example.com', [self.page([], nxt)] * 3)
        self.assertEqual(fetch.call_count, 1)

    def test_invalid_domain_is_not_queried(self):
        for data in ("not a domain", "example.com/../x", "-bad.example.com"):
            with self.subTest(data=data):
                fetch, _ = self._run(self._module(), data, [self.page([])])
                fetch.assert_not_called()

    def test_unexpected_structure_emits_nothing(self):
        for content in ('{"results": null}', '{"results": "x"}', '[]', 'nope'):
            with self.subTest(content=content):
                _, emitted = self._run(self._module(), 'example.com', [{'code': '200', 'content': content}])
                self.assertEqual(emitted, [])
