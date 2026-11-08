import os
import pytest
import unittest

from modules.sfp_tool_whatweb import sfp_tool_whatweb
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleToolWhatweb(unittest.TestCase):

    def test_opts(self):
        module = sfp_tool_whatweb()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_whatweb()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_whatweb()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_whatweb()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_tool_path_configured_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_whatweb()
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

    def test_handleEvent_passes_timeout_to_communicate_not_popen(self):
        import tempfile
        from unittest.mock import MagicMock, patch
        exe = tempfile.NamedTemporaryFile(delete=False)
        exe.close()
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_whatweb()
        module.setup(sf, {'whatweb_path': exe.name, 'ruby_path': 'ruby', 'aggression': 1})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        evt = SpiderFootEvent('INTERNET_NAME', 'www.example.com', 'test', SpiderFootEvent('ROOT', 'example.com', '', ''))
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate.return_value = (b"", b"")
        with patch('modules.sfp_tool_whatweb.Popen', return_value=proc) as popen:
            module.handleEvent(evt)
        self.assertNotIn('timeout', popen.call_args[1])
        self.assertEqual(proc.communicate.call_args[1].get('timeout'), 300)

        # A failing WhatWeb run (bytes output, non-zero exit) must not crash the module.
        module.results = dict()
        proc.returncode = 1
        proc.communicate.return_value = (b"partial", b"ruby: some error")
        with patch('modules.sfp_tool_whatweb.Popen', return_value=proc):
            module.handleEvent(evt)
        os.unlink(exe.name)
