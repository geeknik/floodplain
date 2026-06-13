import pytest
import unittest
from unittest.mock import patch

from modules.sfp_tool_trufflehog import sfp_tool_trufflehog
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleToolTrufflehog(unittest.TestCase):

    def test_opts(self):
        module = sfp_tool_trufflehog()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_trufflehog()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_trufflehog()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_trufflehog()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_tool_path_configured_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_trufflehog()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example value'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)

    def test_handleEvent_malicious_repo_url_should_not_invoke_subprocess(self):
        """A crafted event whose extracted repository URL begins with '-' (or
        contains whitespace) must be refused and never reach the subprocess,
        preventing command-line argument injection into trufflehog."""
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_trufflehog()
        module.setup(sf, {'trufflehog_path': '/usr/bin/trufflehog'})

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        # Contains "github.com/" so extraction is attempted, but the extracted
        # value starts with '-' and contains a space, so it must be refused.
        malicious = 'Github: --proxy=http://evil https://github.com/x'
        evt = SpiderFootEvent('SOCIAL_MEDIA', malicious, 'test', root)

        with patch('modules.sfp_tool_trufflehog.os.path.isfile', return_value=True), \
             patch('modules.sfp_tool_trufflehog.Popen') as mock_popen:
            module.handleEvent(evt)

        mock_popen.assert_not_called()

    def test_handleEvent_host_confusion_url_should_not_invoke_subprocess(self):
        """A URL whose authority is not an allowlisted code host must be refused,
        even when the raw event data contains an allowlisted host as a substring
        (e.g. https://evil.com/?x=github.com/repo or https://github.com.evil.com).

        Guards against the incomplete URL substring sanitization class (CWE-20):
        the trust decision must be made on the parsed hostname, never on a
        substring match of the raw event data."""
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_trufflehog()
        module.setup(sf, {'trufflehog_path': '/usr/bin/trufflehog'})

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        root = SpiderFootEvent('ROOT', 'example.com', '', '')

        for confusing in (
            # allowlisted host appears only in the query string; real host is evil.com
            'Github: https://evil.com/?x=github.com/repo',
            # allowlisted host is only a left-hand label of a different domain
            'Github: https://github.com.evil.com/repo',
        ):
            with self.subTest(url=confusing):
                evt = SpiderFootEvent('SOCIAL_MEDIA', confusing, 'test', root)
                with patch('modules.sfp_tool_trufflehog.os.path.isfile', return_value=True), \
                     patch('modules.sfp_tool_trufflehog.Popen') as mock_popen:
                    module.handleEvent(evt)
                mock_popen.assert_not_called()
