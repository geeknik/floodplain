import pytest
import unittest
from subprocess import TimeoutExpired
from unittest.mock import MagicMock, mock_open, patch

from modules.sfp_tool_testsslsh import sfp_tool_testsslsh
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleToolTestsslsh(unittest.TestCase):

    def _configured_module(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_testsslsh()
        module.setup(sf, {'testsslsh_path': '/usr/bin/testssl.sh'})

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        event = SpiderFootEvent('INTERNET_NAME', 'example.com', 'test', root)
        return module, event

    def test_opts(self):
        module = sfp_tool_testsslsh()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_testsslsh()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_testsslsh()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_testsslsh()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_tool_path_configured_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_testsslsh()
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

    def test_handleEvent_timeout_should_close_and_remove_temporary_file(self):
        module, event = self._configured_module()
        process = MagicMock()
        process.communicate.side_effect = [
            TimeoutExpired('testssl.sh', 300),
            (b'', b'')
        ]

        with patch('modules.sfp_tool_testsslsh.os.path.isfile', return_value=True), \
             patch('modules.sfp_tool_testsslsh.tempfile.mkstemp', return_value=(41, '/tmp/testssl.json')), \
             patch('modules.sfp_tool_testsslsh.os.close') as close, \
             patch('modules.sfp_tool_testsslsh.os.unlink') as unlink, \
             patch('modules.sfp_tool_testsslsh.Popen', return_value=process):
            module.handleEvent(event)

        close.assert_called_once_with(41)
        process.kill.assert_called_once_with()
        unlink.assert_called_once_with('/tmp/testssl.json')

    def test_handleEvent_parse_error_should_remove_temporary_file(self):
        module, event = self._configured_module()
        process = MagicMock(returncode=0)
        process.communicate.return_value = (b'completed', b'invalid output')

        with patch('modules.sfp_tool_testsslsh.os.path.isfile', return_value=True), \
             patch('modules.sfp_tool_testsslsh.tempfile.mkstemp', return_value=(42, '/tmp/testssl.json')), \
             patch('modules.sfp_tool_testsslsh.os.close'), \
             patch('modules.sfp_tool_testsslsh.os.path.getsize', return_value=1), \
             patch('builtins.open', mock_open(read_data='{')), \
             patch('modules.sfp_tool_testsslsh.os.unlink') as unlink, \
             patch('modules.sfp_tool_testsslsh.Popen', return_value=process):
            module.handleEvent(event)

        unlink.assert_called_once_with('/tmp/testssl.json')

    def test_handleEvent_oversized_output_should_not_be_read(self):
        module, event = self._configured_module()
        process = MagicMock(returncode=0)
        process.communicate.return_value = (b'completed', b'')
        output_file = mock_open()

        with patch('modules.sfp_tool_testsslsh.os.path.isfile', return_value=True), \
             patch('modules.sfp_tool_testsslsh.tempfile.mkstemp', return_value=(43, '/tmp/testssl.json')), \
             patch('modules.sfp_tool_testsslsh.os.close'), \
             patch('modules.sfp_tool_testsslsh.os.path.getsize', return_value=module.MAX_OUTPUT_BYTES + 1), \
             patch('builtins.open', output_file), \
             patch('modules.sfp_tool_testsslsh.os.unlink') as unlink, \
             patch('modules.sfp_tool_testsslsh.Popen', return_value=process), \
             patch.object(module, 'notifyListeners') as notify:
            module.handleEvent(event)

        output_file.assert_not_called()
        notify.assert_not_called()
        unlink.assert_called_once_with('/tmp/testssl.json')

    def test_handleEvent_valid_output_should_emit_finding_and_remove_temporary_file(self):
        module, event = self._configured_module()
        process = MagicMock(returncode=0)
        process.communicate.return_value = (b'completed', b'')
        output = '[{"finding": "weak protocol", "severity": "LOW", "id": "TLS1"}]'

        with patch('modules.sfp_tool_testsslsh.os.path.isfile', return_value=True), \
             patch('modules.sfp_tool_testsslsh.tempfile.mkstemp', return_value=(44, '/tmp/testssl.json')), \
             patch('modules.sfp_tool_testsslsh.os.close') as close, \
             patch('modules.sfp_tool_testsslsh.os.path.getsize', return_value=len(output)), \
             patch('builtins.open', mock_open(read_data=output)), \
             patch('modules.sfp_tool_testsslsh.os.unlink') as unlink, \
             patch('modules.sfp_tool_testsslsh.Popen', return_value=process), \
             patch.object(module, 'notifyListeners') as notify:
            module.handleEvent(event)

        close.assert_called_once_with(44)
        unlink.assert_called_once_with('/tmp/testssl.json')
        notify.assert_called_once()
        finding = notify.call_args.args[0]
        self.assertEqual(finding.eventType, 'VULNERABILITY_GENERAL')
        self.assertEqual(finding.data, 'TLS1 (weak protocol)')
