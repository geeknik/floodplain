import io
import sys
import unittest
from unittest import mock
import zipfile

from floodplain import office_parser


_CONTENT_TYPES = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}
_MAIN_PARTS = {"docx": "word/document.xml", "pptx": "ppt/presentation.xml"}


def _make_office_archive(file_ext, extra_entries=None):
    output = io.BytesIO()
    part_name = _MAIN_PARTS[file_ext]
    content_type = _CONTENT_TYPES[file_ext]
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Override PartName="/{part_name}" ContentType="{content_type}"/>'
        '</Types>'
    )
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", manifest)
        archive.writestr(part_name, "<document/>")
        for name, content in extra_entries or []:
            archive.writestr(name, content)
    return output.getvalue()


class TestOfficeParser(unittest.TestCase):

    def test_validate_office_archive_accepts_docx_and_pptx(self):
        for file_ext in ("docx", "pptx"):
            with self.subTest(file_ext=file_ext):
                office_parser.validate_office_archive(_make_office_archive(file_ext), file_ext)

    def test_validate_office_archive_rejects_mismatched_type(self):
        with self.assertRaisesRegex(ValueError, "content type"):
            office_parser.validate_office_archive(_make_office_archive("pptx"), "docx")

    def test_validate_office_archive_rejects_invalid_magic(self):
        with self.assertRaisesRegex(ValueError, "ZIP file magic"):
            office_parser.validate_office_archive(b"not an office archive", "docx")

    def test_validate_office_archive_rejects_excessive_expansion(self):
        content = _make_office_archive("docx", [("word/large.xml", "A" * 4096)])

        with mock.patch.object(office_parser, "_MAX_TOTAL_SIZE", 1024):
            with self.assertRaisesRegex(ValueError, "total expansion limit"):
                office_parser.validate_office_archive(content, "docx")

    def test_validate_office_archive_rejects_excessive_entry_count(self):
        content = _make_office_archive("docx", [("word/extra.xml", "<extra/>")])

        with mock.patch.object(office_parser, "_MAX_ARCHIVE_ENTRIES", 2):
            with self.assertRaisesRegex(ValueError, "number of entries"):
                office_parser.validate_office_archive(content, "docx")

    def test_validate_office_archive_rejects_excessive_compression_ratio(self):
        content = _make_office_archive("docx", [("word/repeated.xml", "A" * 4096)])

        with mock.patch.object(office_parser, "_MAX_COMPRESSION_RATIO", 2):
            with self.assertRaisesRegex(ValueError, "compression-ratio limit"):
                office_parser.validate_office_archive(content, "docx")

    def test_extract_office_metadata_validates_before_parser(self):
        order = []
        document = mock.Mock()
        document.core_properties.author = "Alice"
        document.core_properties.comments = "Reviewed"

        with mock.patch.object(office_parser, "validate_office_archive",
                               side_effect=lambda content, file_ext: order.append("validate")):
            with mock.patch("docx.Document", side_effect=lambda content: order.append("parse") or document):
                metadata = office_parser.extract_office_metadata(b"content", "docx")

        self.assertEqual(order, ["validate", "parse"])
        self.assertEqual(metadata, ["Alice", "Reviewed"])

    def test_apply_resource_limits_sets_memory_cpu_and_core_caps(self):
        resource = mock.Mock()
        resource.RLIMIT_AS = 1
        resource.RLIMIT_CPU = 2
        resource.RLIMIT_CORE = 3
        resource.RLIM_INFINITY = -1
        resource.getrlimit.return_value = (-1, -1)

        with mock.patch.dict(sys.modules, {"resource": resource}):
            office_parser.apply_resource_limits()

        self.assertEqual(
            resource.setrlimit.call_args_list,
            [
                mock.call(resource.RLIMIT_AS,
                          (office_parser._PARSER_MEMORY_BYTES, office_parser._PARSER_MEMORY_BYTES)),
                mock.call(resource.RLIMIT_CPU,
                          (office_parser._PARSER_CPU_SECONDS, office_parser._PARSER_CPU_SECONDS)),
                mock.call(resource.RLIMIT_CORE, (0, 0)),
            ],
        )

    def test_main_limits_resources_before_reading_and_parsing(self):
        order = []
        input_buffer = mock.Mock()
        input_buffer.read.side_effect = lambda size: order.append("read") or b"office content"
        output_buffer = io.BytesIO()

        with mock.patch.object(office_parser, "apply_resource_limits",
                               side_effect=lambda: order.append("limits")):
            with mock.patch.object(office_parser, "extract_office_metadata",
                                   side_effect=lambda content, file_ext: order.append("parse") or []):
                with mock.patch.object(office_parser.sys, "stdin", mock.Mock(buffer=input_buffer)):
                    with mock.patch.object(office_parser.sys, "stdout", mock.Mock(buffer=output_buffer)):
                        result = office_parser.main(["docx"])

        self.assertEqual(result, 0)
        self.assertEqual(order, ["limits", "read", "parse"])
