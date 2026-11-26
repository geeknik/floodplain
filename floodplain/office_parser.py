import io
import json
from pathlib import PurePosixPath
import sys
import zipfile

from lxml import etree  # noqa: DUO107 -- parsed only with the hardened XMLParser below


MAX_OFFICE_INPUT_SIZE = 10000000
MAX_OFFICE_OUTPUT_SIZE = 16384

_MAX_ARCHIVE_ENTRIES = 1000
_MAX_ENTRY_SIZE = 32 * 1024 * 1024
_MAX_TOTAL_SIZE = 64 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1000
_MAX_CONTENT_TYPES_SIZE = 1024 * 1024
_MAX_METADATA_LENGTH = 4096
_PARSER_CPU_SECONDS = 10
_PARSER_MEMORY_BYTES = 512 * 1024 * 1024

_CONTENT_TYPES_PATH = "[Content_Types].xml"
_CONTENT_TYPES_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/content-types"
_OFFICE_TYPES = {
    "docx": (
        "word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    ),
    "pptx": (
        "ppt/presentation.xml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    ),
}
_SUPPORTED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


def _set_resource_limit(resource_module, limit_name, requested_limit):
    limit_id = getattr(resource_module, limit_name, None)
    if limit_id is None:
        raise RuntimeError(f"Required resource limit {limit_name} is unavailable")

    soft_limit, hard_limit = resource_module.getrlimit(limit_id)
    selected_limit = requested_limit
    if soft_limit != resource_module.RLIM_INFINITY:
        selected_limit = min(selected_limit, soft_limit)
    if hard_limit != resource_module.RLIM_INFINITY:
        selected_limit = min(selected_limit, hard_limit)

    # Some kernels reject lowering the hard limit below the current soft limit,
    # even when both values are reduced by the same setrlimit call.
    if soft_limit != selected_limit:
        resource_module.setrlimit(limit_id, (selected_limit, hard_limit))
    resource_module.setrlimit(limit_id, (selected_limit, selected_limit))


def apply_resource_limits():
    try:
        import resource
    except ImportError as error:
        raise RuntimeError("Office parsing requires operating-system resource limits") from error

    # Darwin reserves a large virtual address range before this helper starts,
    # so applying RLIMIT_AS after interpreter startup fails before parsing. Its
    # RLIMIT_DATA instead enforces a cap on heap/data growth used by the parsers.
    memory_limit = "RLIMIT_DATA" if sys.platform == "darwin" else "RLIMIT_AS"
    _set_resource_limit(resource, memory_limit, _PARSER_MEMORY_BYTES)
    _set_resource_limit(resource, "RLIMIT_CPU", _PARSER_CPU_SECONDS)
    _set_resource_limit(resource, "RLIMIT_CORE", 0)


def _validate_content_types(archive, expected_part, expected_content_type):
    content_types_info = archive.getinfo(_CONTENT_TYPES_PATH)
    if content_types_info.file_size > _MAX_CONTENT_TYPES_SIZE:
        raise ValueError("Office content-type manifest exceeds its size limit")

    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                                 dtd_validation=False, huge_tree=False, recover=False)
        root = etree.fromstring(archive.read(content_types_info), parser=parser)
        if root.getroottree().docinfo.doctype:
            raise ValueError("Office content-type manifest must not contain a document type")
    except etree.XMLSyntaxError as error:
        raise ValueError("Office content-type manifest is malformed") from error

    override_tag = f"{{{_CONTENT_TYPES_NAMESPACE}}}Override"
    for element in root.iter(override_tag):
        if (
            element.attrib.get("PartName") == f"/{expected_part}"
            and element.attrib.get("ContentType") == expected_content_type
        ):
            return
    raise ValueError("Office package content type does not match the requested format")


def validate_office_archive(content, file_ext):
    office_type = _OFFICE_TYPES.get(file_ext)
    if office_type is None:
        raise ValueError("Unsupported Office document type")
    if not content.startswith(b"PK\x03\x04"):
        raise ValueError("Office document does not have ZIP file magic")

    expected_part, expected_content_type = office_type
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > _MAX_ARCHIVE_ENTRIES:
                raise ValueError("Office archive has an invalid number of entries")

            names = set()
            total_size = 0
            for entry in entries:
                name = entry.filename
                path_parts = PurePosixPath(name).parts
                normalized_name = name.casefold()
                if (
                    not name or len(name) > 512 or name.startswith(("/", "\\"))
                    or "\\" in name or ".." in path_parts
                ):
                    raise ValueError("Office archive contains an unsafe entry name")
                if normalized_name in names:
                    raise ValueError("Office archive contains duplicate entry names")
                names.add(normalized_name)

                if entry.flag_bits & 0x1:
                    raise ValueError("Encrypted Office archive entries are not supported")
                if entry.compress_type not in _SUPPORTED_COMPRESSION:
                    raise ValueError("Office archive uses an unsupported compression method")
                if entry.file_size > _MAX_ENTRY_SIZE:
                    raise ValueError("Office archive entry exceeds its expansion limit")

                total_size += entry.file_size
                if total_size > _MAX_TOTAL_SIZE:
                    raise ValueError("Office archive exceeds its total expansion limit")
                if entry.file_size and (
                    entry.compress_size == 0
                    or entry.file_size > entry.compress_size * _MAX_COMPRESSION_RATIO
                ):
                    raise ValueError("Office archive entry exceeds its compression-ratio limit")

            if _CONTENT_TYPES_PATH.casefold() not in names:
                raise ValueError("Office archive is missing required package parts")
            _validate_content_types(archive, expected_part, expected_content_type)
            if expected_part.casefold() not in names:
                raise ValueError("Office archive is missing required package parts")
    except (EOFError, OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ValueError("Office archive is malformed") from error


def extract_office_metadata(content, file_ext):
    validate_office_archive(content, file_ext)

    if file_ext == "docx":
        import docx
        document = docx.Document(io.BytesIO(content))
    elif file_ext == "pptx":
        import pptx
        document = pptx.Presentation(io.BytesIO(content))
    else:
        raise ValueError("Unsupported Office document type")

    metadata = []
    for value in (document.core_properties.author, document.core_properties.comments):
        if not value:
            continue
        if not isinstance(value, str) or len(value) > _MAX_METADATA_LENGTH:
            raise ValueError("Office metadata exceeds its output limit")
        metadata.append(value)
    return metadata


def _write_response(response):
    encoded = json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > MAX_OFFICE_OUTPUT_SIZE:
        raise ValueError("Office metadata exceeds its encoded output limit")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if len(args) != 1 or args[0] not in _OFFICE_TYPES:
            raise ValueError("A supported Office document type is required")

        apply_resource_limits()
        content = sys.stdin.buffer.read(MAX_OFFICE_INPUT_SIZE + 1)
        if len(content) > MAX_OFFICE_INPUT_SIZE:
            raise ValueError("Office document exceeds its compressed-size limit")
        metadata = extract_office_metadata(content, args[0])
        _write_response({"status": "ok", "metadata": metadata})
        return 0
    except Exception as error:
        detail = str(error).replace("\r", " ").replace("\n", " ")[:200]
        _write_response({"status": "error", "error": f"{type(error).__name__}: {detail}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
