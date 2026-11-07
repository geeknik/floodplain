import pytest
import unittest

from modules.sfp_pastebin import sfp_pastebin
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModulePastebin(unittest.TestCase):

    def test_opts(self):
        module = sfp_pastebin()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_pastebin()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_pastebin()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_pastebin()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_pastebin()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
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


@pytest.mark.usefixtures
class TestModulePastebinBehaviour(unittest.TestCase):

    def _module(self, **opts):
        from spiderfoot import SpiderFootTarget
        base = {'brave_api_key': 'brave-key', 'api_key': '', 'cse_id': '', 'max_results': 20, '_fetchtimeout': 5}
        base.update(opts)
        module = sfp_pastebin()
        module.setup(SpiderFoot(self.default_options), base)
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, responses):
        from unittest.mock import patch
        from spiderfoot import SpiderFootEvent
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('EMAILADDR', data, 'test', root)
        emitted = []
        with patch.object(module.sf, 'fetchUrl', side_effect=responses) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    @staticmethod
    def page(urls):
        import json
        return {'code': '200', 'content': json.dumps({'query': {}, 'web': {'results': [{'url': u} for u in urls]}})}

    def test_no_key_sets_errorState(self):
        module = self._module(brave_api_key='')
        fetch, _ = self._run(module, 'a@example.com', [])
        fetch.assert_not_called()
        self.assertTrue(module.errorState)

    def test_only_real_pastebin_hosts_are_fetched(self):
        search = self.page(["https://pastebin.com/abc", "https://evilpastebin.com/x", "https://pastebin.com.evil.net/y"])
        paste = {'code': '200', 'content': 'leak: a@example.com here'}
        fetch, emitted = self._run(self._module(), 'a@example.com', [search, paste])
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(fetch.call_args_list[1][0][0], "https://pastebin.com/abc")
        self.assertEqual([e.eventType for e in emitted], ["LEAKSITE_URL", "LEAKSITE_CONTENT"])
        self.assertIn("X-Subscription-Token", fetch.call_args_list[0][1]['headers'])

    def test_legacy_google_key_still_works(self):
        import json
        g = {'code': '200', 'content': json.dumps({'items': [{'link': 'https://pastebin.com/abc'}]})}
        paste = {'code': '200', 'content': 'nothing relevant'}
        fetch, emitted = self._run(self._module(brave_api_key='', api_key='gkey', cse_id='cse'), 'a@example.com', [g, paste])
        self.assertTrue(fetch.call_args_list[0][0][0].startswith("https://www.googleapis.com/customsearch/v1?"))
        self.assertEqual(emitted, [])

    def test_fatal_search_error_stops_module(self):
        module = self._module()
        self._run(module, 'a@example.com', [{'code': '401', 'content': ''}])
        self.assertTrue(module.errorState)
