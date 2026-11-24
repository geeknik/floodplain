import json
import subprocess
import sys
import pytest
import unittest
from unittest import mock

from modules.sfp_filemeta import _parse_office_metadata, sfp_filemeta
from floodplain import SpiderFootEvent
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleFilemeta(unittest.TestCase):

    def test_opts(self):
        module = sfp_filemeta()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_filemeta()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_filemeta()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_filemeta()
        self.assertIsInstance(module.producedEvents(), list)

    def test_parse_office_metadata_uses_isolated_helper(self):
        process = mock.Mock()
        process.communicate.return_value = (
            json.dumps({"status": "ok", "metadata": ["Alice", "Reviewed"]}).encode("ascii"),
            None,
        )
        process.returncode = 0

        with mock.patch("modules.sfp_filemeta.subprocess.Popen", return_value=process) as popen:
            metadata = _parse_office_metadata(b"office content", "docx")

        self.assertEqual(metadata, ["Alice", "Reviewed"])
        command = popen.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[-1], "docx")
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_parse_office_metadata_kills_timed_out_helper(self):
        process = mock.Mock()
        process.communicate.side_effect = [
            subprocess.TimeoutExpired([sys.executable], 15),
            (b"", None),
        ]

        with mock.patch("modules.sfp_filemeta.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "wall-time limit"):
                _parse_office_metadata(b"office content", "pptx")

        process.kill.assert_called_once_with()

    def test_handleEvent_preserves_office_metadata_results(self):
        sf = mock.Mock()
        sf.fetchUrl.return_value = {"content": b"x" * 512}
        module = sfp_filemeta()
        module.setup(sf, {"_useragent": "unit-test"})
        module.notifyListeners = mock.Mock()
        event = SpiderFootEvent("LINKED_URL_INTERNAL", "https://example.test/report.docx", "source", None)

        with mock.patch("modules.sfp_filemeta._parse_office_metadata", return_value=["Alice", "Reviewed"]):
            module.handleEvent(event)

        output_event = module.notifyListeners.call_args.args[0]
        self.assertEqual(output_event.eventType, "RAW_FILE_META_DATA")
        self.assertEqual(output_event.data, "Alice, Reviewed")
