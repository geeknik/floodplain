import pytest
import unittest

from modules.sfp_emailrep import sfp_emailrep
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleEmailrep(unittest.TestCase):

    def test_opts(self):
        module = sfp_emailrep()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_emailrep()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_emailrep()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_emailrep()
        self.assertIsInstance(module.producedEvents(), list)


@pytest.mark.usefixtures
class TestModuleEmailrepBehaviour(unittest.TestCase):

    def _module(self, key='emailrep-key'):
        from sflib import SpiderFoot
        from floodplain import SpiderFootTarget
        module = sfp_emailrep()
        module.setup(SpiderFoot(self.default_options), {'api_key': key, '_fetchtimeout': 5})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, response):
        from unittest.mock import patch
        from floodplain import SpiderFootEvent
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('EMAILADDR', data, 'test', root)
        emitted = []
        with patch.object(module.sf, 'fetchUrl', return_value=response) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append), \
                patch('modules.sfp_emailrep.time.sleep'):
            module.handleEvent(evt)
        return fetch, emitted

    def test_no_api_key_sets_errorState_without_querying(self):
        module = self._module(key='')
        fetch, emitted = self._run(module, 'a@example.com', {'code': '200', 'content': '{}'})
        fetch.assert_not_called()
        self.assertTrue(module.errorState)

    def test_key_sent_in_header_not_url(self):
        module = self._module()
        body = '{"details": {"credentials_leaked": true, "malicious_activity": true}}'
        fetch, emitted = self._run(module, 'A@Example.com', {'code': '200', 'content': body})
        args, kwargs = fetch.call_args
        self.assertEqual(args[0], "https://emailrep.io/a@example.com")
        self.assertEqual(kwargs['headers']['Key'], 'emailrep-key')
        self.assertEqual(sorted(e.eventType for e in emitted), ['EMAILADDR_COMPROMISED', 'MALICIOUS_EMAILADDR', 'RAW_RIR_DATA'])

    def test_path_injection_is_rejected(self):
        module = self._module()
        for data in ("../admin@example.com", "a@example.com/../../x", "a@example.com?x=1", "a@example.com#x", "nope"):
            with self.subTest(data=data):
                fetch, _ = self._run(module, data, {'code': '200', 'content': '{}'})
                fetch.assert_not_called()

    def test_truthy_non_boolean_flags_are_ignored(self):
        body = '{"details": {"credentials_leaked": "false", "malicious_activity": 1}}'
        _, emitted = self._run(self._module(), 'a@example.com', {'code': '200', 'content': body})
        self.assertEqual(emitted, [])

    def test_error_codes(self):
        for code, fatal in (('401', True), ('403', True), ('429', True), ('500', True), ('400', False), ('404', False)):
            with self.subTest(code=code):
                module = self._module()
                _, emitted = self._run(module, 'a@example.com', {'code': code, 'content': ''})
                self.assertEqual(module.errorState, fatal)
                self.assertEqual(emitted, [])
