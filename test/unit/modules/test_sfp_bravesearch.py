import json
import pytest
import unittest
from unittest.mock import patch

from modules.sfp_bravesearch import sfp_bravesearch
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


def brave_page(urls, more=False):
    return {'code': '200', 'content': json.dumps({
        'query': {'more_results_available': more},
        'web': {'results': [{'url': u} for u in urls]},
    })}


@pytest.mark.usefixtures
class TestModuleBravesearch(unittest.TestCase):

    def _module(self, **opts):
        base = {'brave_api_key': 'brave-key', 'max_results': 20, '_fetchtimeout': 5}
        base.update(opts)
        module = sfp_bravesearch()
        module.setup(SpiderFoot(self.default_options), base)
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, responses):
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('INTERNET_NAME', data, 'test', root)
        emitted = []
        side = responses if isinstance(responses, list) else [responses]
        with patch.object(module.sf, 'fetchUrl', side_effect=side) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    def test_opts(self):
        module = sfp_bravesearch()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sfp_bravesearch().setup(SpiderFoot(self.default_options), dict())

    def test_watched_and_produced(self):
        self.assertEqual(sfp_bravesearch().watchedEvents(), ["INTERNET_NAME"])
        self.assertIsInstance(sfp_bravesearch().producedEvents(), list)

    def test_no_api_key_sets_errorState(self):
        module = self._module(brave_api_key='')
        fetch, _ = self._run(module, 'example.com', [])
        fetch.assert_not_called()
        self.assertTrue(module.errorState)

    def test_emits_only_real_subdomain_links(self):
        urls = ["https://www.example.com/a", "https://example.com/b", "https://evilexample.com/c",
                "https://example.com.evil.net/d", "https://other.net/?q=example.com"]
        fetch, emitted = self._run(self._module(), 'example.com', brave_page(urls))
        links = [e.data for e in emitted if e.eventType == "LINKED_URL_INTERNAL"]
        self.assertEqual(links, ["https://www.example.com/a", "https://example.com/b"])
        raw = json.loads([e.data for e in emitted if e.eventType == "RAW_RIR_DATA"][0])
        self.assertEqual(raw['provider'], 'Brave')
        self.assertNotIn('brave-key', json.dumps(raw))
        self.assertIn("q=site%3Aexample.com", fetch.call_args[0][0])

    def test_no_internal_links_emits_nothing(self):
        _, emitted = self._run(self._module(), 'example.com', brave_page(["https://other.net/"]))
        self.assertEqual(emitted, [])

    def test_fatal_error_stops_module(self):
        module = self._module()
        self._run(module, 'example.com', {'code': '429', 'content': ''})
        self.assertTrue(module.errorState)
        fetch, _ = self._run(module, 'www.example.com', [brave_page([])])
        fetch.assert_not_called()

    def test_duplicate_host_searched_once(self):
        module = self._module()
        self._run(module, 'Example.com', brave_page([]))
        fetch, _ = self._run(module, 'example.com.', [brave_page([])])
        fetch.assert_not_called()

    def test_malformed_host_not_searched(self):
        for data in ('a b.example.com', 'example.com" OR "x', 'x' * 254):
            with self.subTest(data=data):
                fetch, _ = self._run(self._module(), data, [brave_page([])])
                fetch.assert_not_called()
