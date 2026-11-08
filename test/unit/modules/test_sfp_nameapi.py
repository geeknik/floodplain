import pytest
import unittest

from modules.sfp_nameapi import sfp_nameapi
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleNameapi(unittest.TestCase):

    def test_opts(self):
        module = sfp_nameapi()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_nameapi()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_nameapi()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_nameapi()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_nameapi()
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


SECRET_KEY = "nameapi-secret-key-1"


@pytest.mark.usefixtures
class TestModuleNameapiBehaviour(unittest.TestCase):

    def _module(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_nameapi()
        module.setup(sf, {'api_key': SECRET_KEY, '_fetchtimeout': 5})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, response):
        from unittest.mock import patch
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('EMAILADDR', data, 'test', root)
        emitted = []
        with patch.object(module.sf, 'fetchUrl', return_value=response) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    def test_uses_https_and_encodes_input(self):
        module = self._module()
        fetch, emitted = self._run(module, 'a.b+tag@mailinator.com', {'code': '200', 'content': '{"disposable": "YES"}'})
        url = fetch.call_args[0][0]
        self.assertTrue(url.startswith("https://api.nameapi.org/rest/v5.3/email/disposableemailaddressdetector?"))
        self.assertIn("emailAddress=a.b%2Btag%40mailinator.com", url)
        self.assertEqual({e.eventType for e in emitted}, {"RAW_RIR_DATA", "EMAILADDR_DISPOSABLE"})

    def test_query_string_injection_is_rejected(self):
        module = self._module()
        for data in ("x@example.com&apiKey=attacker", "x@example.com#frag", "not-an-email", "a b@example.com"):
            with self.subTest(data=data):
                fetch, emitted = self._run(module, data, {'code': '200', 'content': '{"disposable": "YES"}'})
                fetch.assert_not_called()
                self.assertEqual(emitted, [])

    def test_not_disposable_emits_nothing(self):
        for verdict in ("NO", "UNKNOWN", "yes", None, 1):
            with self.subTest(verdict=verdict):
                import json
                _, emitted = self._run(self._module(), 'x@example.com', {'code': '200', 'content': json.dumps({'disposable': verdict})})
                self.assertEqual(emitted, [])

    def test_auth_failure_and_rate_limit_set_errorState(self):
        for code in ('401', '403', '429'):
            with self.subTest(code=code):
                module = self._module()
                _, emitted = self._run(module, 'x@example.com', {'code': code, 'content': '{}'})
                self.assertTrue(module.errorState)
                self.assertEqual(emitted, [])

    def test_bad_responses_emit_nothing(self):
        for res in ({'code': '200', 'content': 'not json'}, {'code': '200', 'content': '[]'},
                    {'code': '500', 'content': ''}, {'code': None, 'content': None}):
            with self.subTest(res=res):
                _, emitted = self._run(self._module(), 'x@example.com', res)
                self.assertEqual(emitted, [])

    def test_duplicate_email_queried_once(self):
        module = self._module()
        self._run(module, 'X@Example.com', {'code': '200', 'content': '{"disposable": "NO"}'})
        fetch, _ = self._run(module, 'x@example.com', {'code': '200', 'content': '{"disposable": "NO"}'})
        fetch.assert_not_called()

    def test_raw_data_never_contains_api_key(self):
        _, emitted = self._run(self._module(), 'x@mailinator.com', {'code': '200', 'content': '{"disposable": "YES"}'})
        for e in emitted:
            self.assertNotIn(SECRET_KEY, e.data)

    def test_invalid_key_fault_400_sets_errorState(self):
        body = '{"faultCause":"BadRequest","blame":"CLIENT","message":"Invalid api-key provided (syntax): >>>nameapi-secret-key-1<<<!","applicationErrorCode":"1120"}'
        module = self._module()
        _, emitted = self._run(module, 'x@example.com', {'code': '400', 'content': body})
        self.assertTrue(module.errorState)
        self.assertEqual(emitted, [])

    def test_other_400_is_not_fatal(self):
        body = '{"faultCause":"BadRequest","blame":"CLIENT","message":"Invalid email address","applicationErrorCode":"2001"}'
        module = self._module()
        self._run(module, 'x@example.com', {'code': '400', 'content': body})
        self.assertFalse(module.errorState)
