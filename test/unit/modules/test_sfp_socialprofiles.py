import pytest
import unittest

from modules.sfp_socialprofiles import sfp_socialprofiles
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleSocialprofiles(unittest.TestCase):

    def test_opts(self):
        module = sfp_socialprofiles()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_socialprofiles()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_socialprofiles()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_socialprofiles()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_socialprofiles()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'HUMAN_NAME'
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
class TestModuleSocialprofilesBehaviour(unittest.TestCase):

    def _module(self, **opts):
        base = {'method': 'brave', 'brave_api_key': 'brave-key', 'google_api_key': '', 'google_cse_id': '',
                'max_results': 20, 'tighten': False, '_fetchtimeout': 5, '_internettlds': ''}
        base.update(opts)
        module = sfp_socialprofiles()
        module.setup(SpiderFoot(self.default_options), base)
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, data, responses):
        from unittest.mock import patch
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('HUMAN_NAME', data, 'test', root)
        emitted = []
        with patch.object(module.sf, 'fetchUrl', side_effect=responses) as fetch, \
                patch.object(module.sf, 'domainKeywords', return_value=['example']), \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    @staticmethod
    def page(urls):
        import json
        return {'code': '200', 'content': json.dumps({'query': {}, 'web': {'results': [{'url': u} for u in urls]}})}

    def test_profiles_found_on_real_domains_only(self):
        fb = self.page(["https://www.facebook.com/jane.doe", "https://facebookZevil.com/jane", "https://evil.net/facebook.com/x"])
        li = self.page(["https://www.linkedin.com/in/janedoe", "https://www.linkedin.com/company/acme"])
        fetch, emitted = self._run(self._module(), 'Jane Doe', [fb, li])
        social = [e.data for e in emitted if e.eventType == "SOCIAL_MEDIA"]
        self.assertEqual(social, ["Facebook: <SFURL>https://www.facebook.com/jane.doe</SFURL>",
                                  "LinkedIn: <SFURL>https://www.linkedin.com/in/janedoe</SFURL>"])
        import urllib.parse
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(fetch.call_args_list[0][0][0]).query)['q'][0]
        self.assertEqual(q, '"Jane Doe" site:facebook.com')

    def test_tighten_fetches_profile_with_tls_verification(self):
        fb = self.page(["https://www.facebook.com/jane.doe"])
        profile = {'code': '200', 'content': '<p> works at example corp </p>'}
        li = self.page([])
        fetch, emitted = self._run(self._module(tighten=True), 'Jane Doe', [fb, profile, li])
        profile_call = fetch.call_args_list[1]
        self.assertEqual(profile_call[0][0], "https://www.facebook.com/jane.doe")
        self.assertNotIn('verify', profile_call[1])
        self.assertEqual(len([e for e in emitted if e.eventType == "SOCIAL_MEDIA"]), 1)

    def test_no_key_for_method_sets_errorState(self):
        for opts in ({'brave_api_key': ''}, {'method': 'google'}, {'method': 'bing'}):
            with self.subTest(opts=opts):
                module = self._module(**opts)
                fetch, _ = self._run(module, 'Jane Doe', [])
                fetch.assert_not_called()
                self.assertTrue(module.errorState)

    def test_malformed_name_not_searched(self):
        for name in ('Jane" OR "x', 'x' * 101):
            with self.subTest(name=name):
                fetch, _ = self._run(self._module(), name, [])
                fetch.assert_not_called()
