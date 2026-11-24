import pytest
import unittest
from unittest.mock import patch

from modules.sfp_dnsresolve import sfp_dnsresolve
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleDnsResolve(unittest.TestCase):

    def test_opts(self):
        module = sfp_dnsresolve()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnsresolve()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsresolve()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsresolve()
        self.assertIsInstance(module.producedEvents(), list)

    def _module(self, opts=None):
        module = sfp_dnsresolve()
        module.setup(SpiderFoot(self.default_options), opts or {})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _raw_event(self, data):
        root = SpiderFootEvent('ROOT', 'example.com', '', None)
        return SpiderFootEvent('TARGET_WEB_CONTENT', data, 'sfp_spider', root)

    def test_raw_content_should_preserve_hostnames_within_limits(self):
        module = self._module({
            'maxhostnamesperinput': 3,
            'maxhostnamesperscan': 3,
        })
        event = self._raw_event('content first.example.com second.example.com')

        with patch.object(module, 'processHost') as process_host, \
             patch.object(module, 'info') as info:
            module.handleEvent(event)

        self.assertEqual(
            ['first.example.com', 'second.example.com'],
            [call.args[0] for call in process_host.call_args_list]
        )
        info.assert_not_called()

    def test_raw_content_should_cap_unique_hostnames_per_input(self):
        module = self._module({
            'maxhostnamesperinput': 2,
            'maxhostnamesperscan': 10,
        })
        event = self._raw_event(
            'content first.example.com first.example.com second.example.com third%2Eexample%2Ecom'
        )

        with patch.object(module, 'processHost') as process_host, \
             patch.object(module, 'info') as info:
            module.handleEvent(event)

        self.assertEqual(
            ['first.example.com', 'second.example.com'],
            [call.args[0] for call in process_host.call_args_list]
        )
        info.assert_called_once()

    def test_raw_content_should_cap_hostnames_across_scan(self):
        module = self._module({
            'maxhostnamesperinput': 10,
            'maxhostnamesperscan': 2,
        })
        first_event = self._raw_event('content first.example.com second.example.com')
        second_event = self._raw_event('content third.example.com fourth.example.com')
        third_event = self._raw_event('content fifth.example.com sixth.example.com')

        with patch.object(module, 'processHost') as process_host, \
             patch.object(module, 'info') as info:
            module.handleEvent(first_event)
            module.handleEvent(second_event)
            module.handleEvent(third_event)

        self.assertEqual(
            ['first.example.com', 'second.example.com'],
            [call.args[0] for call in process_host.call_args_list]
        )
        info.assert_called_once()

    def test_raw_content_should_share_input_cap_across_target_aliases(self):
        module = self._module({
            'maxhostnamesperinput': 2,
            'maxhostnamesperscan': 10,
        })
        module.getTarget().setAlias('example.net', 'INTERNET_NAME')
        event = self._raw_event(
            'content first.example.com second.example.net third.example.com'
        )

        with patch.object(module, 'processHost') as process_host, \
             patch.object(module, 'info') as info:
            module.handleEvent(event)

        self.assertEqual(2, process_host.call_count)
        self.assertEqual(
            {'first.example.com', 'second.example.net'},
            {call.args[0] for call in process_host.call_args_list}
        )
        info.assert_called_once()

    def test_hostname_limits_should_reject_unbounded_configuration(self):
        module = self._module({
            'maxhostnamesperinput': sfp_dnsresolve.MAX_HOSTNAMES_PER_INPUT + 1,
            'maxhostnamesperscan': 'invalid',
        })

        self.assertEqual(
            sfp_dnsresolve.MAX_HOSTNAMES_PER_INPUT,
            module.hostnameLimit('maxhostnamesperinput', sfp_dnsresolve.MAX_HOSTNAMES_PER_INPUT)
        )
        self.assertEqual(
            0,
            module.hostnameLimit('maxhostnamesperscan', sfp_dnsresolve.MAX_HOSTNAMES_PER_SCAN)
        )
