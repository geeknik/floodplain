# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_filemeta
# Purpose:      From Spidering and from searching search engines, extracts file
#               meta data from files matching certain file extensions.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     MIT
# -------------------------------------------------------------------------------

import concurrent.futures
from contextlib import suppress
import io
import json
import mimetypes
import subprocess
import sys
import time

import pypdf

import exifread

from floodplain import SpiderFootEvent, SpiderFootPlugin
from floodplain import office_parser


_OFFICE_PARSER_TIMEOUT_SECONDS = 15


def _write_office_parser_input(stream, content):
    try:
        with suppress(BrokenPipeError):
            stream.write(content)
            stream.flush()
    finally:
        with suppress(BrokenPipeError):
            stream.close()


def _remaining_parser_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise concurrent.futures.TimeoutError
    return remaining


def _stop_office_parser(process):
    if process.poll() is None:
        with suppress(ProcessLookupError):
            process.kill()
        process.wait()


def _exchange_office_parser(process, content):
    deadline = time.monotonic() + _OFFICE_PARSER_TIMEOUT_SECONDS
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        input_future = executor.submit(_write_office_parser_input, process.stdin, content)
        output_future = executor.submit(
            process.stdout.read, office_parser.MAX_OFFICE_OUTPUT_SIZE + 1,
        )
        try:
            output = output_future.result(timeout=_remaining_parser_time(deadline))
            if len(output) > office_parser.MAX_OFFICE_OUTPUT_SIZE:
                raise ValueError("Office parser returned too much metadata")
            input_future.result(timeout=_remaining_parser_time(deadline))
            process.wait(timeout=_remaining_parser_time(deadline))
        except (concurrent.futures.TimeoutError, subprocess.TimeoutExpired) as error:
            _stop_office_parser(process)
            raise ValueError("Office parser exceeded its wall-time limit") from error
        except Exception:
            _stop_office_parser(process)
            raise
    return output


def _parse_office_metadata(content, file_ext):
    if len(content) > office_parser.MAX_OFFICE_INPUT_SIZE:
        raise ValueError("Office document exceeds its compressed-size limit")

    command = [sys.executable, office_parser.__file__, file_ext]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    output = _exchange_office_parser(process, content)

    try:
        response = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Office parser returned an invalid response") from error

    if not isinstance(response, dict):
        raise ValueError("Office parser returned an invalid response")
    if process.returncode != 0 or response.get("status") != "ok":
        detail = response.get("error", "Office parser stopped without a result")
        raise ValueError(detail)
    metadata = response.get("metadata")
    if not isinstance(metadata, list) or any(not isinstance(value, str) for value in metadata):
        raise ValueError("Office parser returned invalid metadata")
    return metadata


class sfp_filemeta(SpiderFootPlugin):

    meta = {
        'name': "File Metadata Extractor",
        'summary': "Extracts meta data from documents and images.",
        'flags': [],
        'useCases': ["Footprint"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
        'fileexts': ["docx", "pptx", 'pdf', 'jpg', 'jpeg', 'tiff', 'tif'],
        'timeout': 300
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions of files you want to analyze the meta data of (only PDF, DOCX, XLSX and PPTX are supported.)",
        'timeout': "Download timeout for files, in seconds."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        self.opts = dict(self.opts)
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "INTERESTING_FILE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_FILE_META_DATA", "SOFTWARE_USED"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        for fileExt in self.opts['fileexts']:
            if self.checkForStop():
                return

            if "." + fileExt.lower() in eventData.lower():
                # Fetch the file, allow much more time given that these files are
                # typically large.
                ret = self.sf.fetchUrl(eventData, timeout=self.opts['timeout'],
                                       useragent=self.opts['_useragent'], disableContentEncoding=True,
                                       sizeLimit=office_parser.MAX_OFFICE_INPUT_SIZE,
                                       verify=False)
                if ret['content'] is None:
                    self.error(f"Unable to fetch file for meta analysis: {eventData}")
                    return

                if len(ret['content']) < 512:
                    self.error(f"Strange content encountered, size of {len(ret['content'])}")
                    return

                meta = None
                data = None
                # Based on the file extension, handle it
                if fileExt.lower() == "pdf":
                    try:
                        raw = io.BytesIO(ret['content'])
                        # data = metapdf.MetaPdfReader().read_metadata(raw)
                        pdf = pypdf.PdfReader(raw, strict=False)
                        data = pdf.metadata
                        meta = str(data)
                        self.debug("Obtained meta data from " + eventData)
                    except Exception as e:
                        self.error(f"Unable to parse meta data from: {eventData} ({e})")
                        return

                if fileExt.lower() in ["docx", "pptx"]:
                    try:
                        data = _parse_office_metadata(ret['content'], fileExt.lower())
                        mtype = mimetypes.guess_type(eventData)[0]
                        self.debug("Office type: " + str(mtype))
                        meta = ", ".join(data)
                    except Exception as e:
                        self.error(f"Unable to process file: {eventData} ({e})")
                        return

                if fileExt.lower() in ["jpg", "jpeg", "tiff"]:
                    try:
                        raw = io.BytesIO(ret['content'])
                        data = exifread.process_file(raw)
                        if data is None or len(data) == 0:
                            continue
                        meta = str(data)
                    except Exception as e:
                        self.error(f"Unable to parse meta data from: {eventData} ({e})")
                        return

                if meta is not None and data is not None:
                    rawevt = SpiderFootEvent("RAW_FILE_META_DATA", meta,
                                             self.__name__, event)
                    self.notifyListeners(rawevt)

                    val = list()
                    try:
                        if "/Producer" in data:
                            val.append(str(data['/Producer']))

                        if "/Creator" in data:
                            val.append(str(data['/Creator']))

                        if "Application" in data:
                            val.append(str(data['Application']))

                        if "Image Software" in data:
                            val.append(str(data['Image Software']))
                    except Exception as e:
                        self.error("Failed to parse PDF, " + eventData + ": " + str(e))
                        return

                    for v in val:
                        if v and not isinstance(v, pypdf.generic.NullObject):
                            self.debug("VAL: " + str(val))
                            # Strip non-ASCII
                            v = ''.join([i if ord(i) < 128 else ' ' for i in v])
                            evt = SpiderFootEvent("SOFTWARE_USED", v, self.__name__, rawevt)
                            self.notifyListeners(evt)
