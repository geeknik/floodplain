import io
import json
import subprocess
import sys
import unittest
from unittest import mock

import docx
import pptx
import pytest

from floodplain import SpiderFootEvent, office_parser
from modules.sfp_filemeta import _parse_office_metadata, sfp_filemeta
from sflib import SpiderFoot


def _make_office_document(file_ext):
    output = io.BytesIO()
    if file_ext == "docx":
        document = docx.Document()
    else:
        document = pptx.Presentation()
    document.core_properties.author = "Alice"
    document.save(output)
    return output.getvalue()


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
        process.stdout.read.return_value = json.dumps(
            {"status": "ok", "metadata": ["Alice", "Reviewed"]},
        ).encode("ascii")
        process.poll.return_value = 0
        process.wait.return_value = 0
        process.returncode = 0

        with mock.patch("modules.sfp_filemeta.subprocess.Popen", return_value=process) as popen:
            metadata = _parse_office_metadata(b"office content", "docx")

        self.assertEqual(metadata, ["Alice", "Reviewed"])
        command = popen.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[-1], "docx")
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        process.stdin.write.assert_called_once_with(b"office content")
        process.stdout.read.assert_called_once_with(office_parser.MAX_OFFICE_OUTPUT_SIZE + 1)

    def test_parse_office_metadata_kills_timed_out_helper(self):
        process = mock.Mock()
        process.stdout.read.return_value = b""
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired([sys.executable], 15), None,
        ]

        with mock.patch("modules.sfp_filemeta.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "wall-time limit"):
                _parse_office_metadata(b"office content", "pptx")

        process.kill.assert_called_once_with()

    def test_parse_office_metadata_bounds_helper_output(self):
        process = mock.Mock()
        process.stdout.read.return_value = b"x" * (office_parser.MAX_OFFICE_OUTPUT_SIZE + 1)
        process.poll.return_value = None
        process.wait.return_value = 0

        with mock.patch("modules.sfp_filemeta.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "too much metadata"):
                _parse_office_metadata(b"office content", "docx")

        process.stdout.read.assert_called_once_with(office_parser.MAX_OFFICE_OUTPUT_SIZE + 1)
        process.kill.assert_called_once_with()

    @unittest.skipUnless(sys.platform.startswith(("linux", "darwin")), "requires POSIX resource limits")
    def test_parse_office_metadata_accepts_real_docx_and_pptx(self):
        for file_ext in ("docx", "pptx"):
            with self.subTest(file_ext=file_ext):
                metadata = _parse_office_metadata(_make_office_document(file_ext), file_ext)

                self.assertEqual(metadata, ["Alice"])

    def test_handleEvent_preserves_office_metadata_results(self):
        sf = mock.Mock()
        sf.fetchUrl.return_value = {"content": b"x" * 512}
        module = sfp_filemeta()
        module.setup(sf, {"_useragent": "unit-test"})
        module.notifyListeners = mock.Mock()
        source_event = SpiderFootEvent("ROOT", "example.test", "source", None)
        event = SpiderFootEvent(
            "LINKED_URL_INTERNAL", "https://example.test/report.docx", "source", source_event,
        )

        with mock.patch("modules.sfp_filemeta._parse_office_metadata", return_value=["Alice", "Reviewed"]):
            module.handleEvent(event)

        output_event = module.notifyListeners.call_args.args[0]
        self.assertEqual(output_event.eventType, "RAW_FILE_META_DATA")
        self.assertEqual(output_event.data, "Alice, Reviewed")
