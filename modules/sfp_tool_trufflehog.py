# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_trufflehog
# Purpose:     Floodplain module for using the trufflehog tool.
#              Tool: https://github.com/trufflesecurity/truffleHog
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import os
import selectors
import time
from contextlib import suppress
from subprocess import DEVNULL, PIPE, Popen, TimeoutExpired
from urllib.parse import urlparse

from floodplain import SpiderFootPlugin, SpiderFootEvent


class sfp_tool_trufflehog(SpiderFootPlugin):

    meta = {
        'name': "Tool - TruffleHog",
        'summary': "Searches through git repositories for high entropy strings and secrets, digging deep into commit history.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "TruffleHog",
            'description': "TruffleHog searches through git repositories for secrets, "
                "digging deep into commit history and branches. This is effective at "
                "finding secrets accidentally committed.",
            'website': "https://github.com/trufflesecurity/trufflehog",
            'repository': "https://github.com/trufflesecurity/trufflehog",
        },
    }

    # Requires TruffleHog v3 (Go). The legacy Python v2 CLI is unmaintained and
    # pins a vulnerable GitPython; it is no longer supported.
    opts = {
        'allrepos': False,
        'trufflehog_path': ''
    }

    optdescs = {
        'trufflehog_path': "Path to your TruffleHog v3 binary. Must be set.",
        'allrepos': "Search all code repositories found. By default TruffleHog only searches those linked from the target website."
    }

    # Bounds on untrusted tool output.
    MAX_FINDINGS = 500
    MAX_OUTPUT_BYTES = 20 * 1024 * 1024
    READ_CHUNK_BYTES = 64 * 1024
    PROCESS_TIMEOUT_SECONDS = 600

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        # Per-instance copy: never mutate the class-level defaults.
        self.opts = dict(self.opts)
        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['SOCIAL_MEDIA', 'PUBLIC_CODE_REPO']

    def producedEvents(self):
        return ['PASSWORD_COMPROMISED']

    @staticmethod
    def _kill_and_reap(process):
        """Stop a child process and release its process-table entry.

        Args:
            process: subprocess to stop
        """
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        process.wait()

    def _emit_output_row(self, row: bytes, url: str, event) -> bool:
        """Parse and emit one complete TruffleHog JSONL record.

        Args:
            row (bytes): one complete output record
            url (str): repository URL that was scanned
            event: source SpiderFoot event

        Returns:
            bool: whether the record produced a finding
        """
        descr = self.describeFinding(row.decode('utf-8', errors='replace'), url)
        if descr is None:
            return False
        evt = SpiderFootEvent('PASSWORD_COMPROMISED', descr, self.__name__, event)
        self.notifyListeners(evt)
        return True

    def _stream_process_output(self, process, url: str, event):
        """Read bounded JSONL output while enforcing the process deadline.

        Args:
            process: running TruffleHog subprocess
            url (str): repository URL that was scanned
            event: source SpiderFoot event
        """
        deadline = time.monotonic() + self.PROCESS_TIMEOUT_SECONDS
        buffered = bytearray()
        output_bytes = 0
        findings = 0

        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while output_bytes < self.MAX_OUTPUT_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self._kill_and_reap(process)
                    self.debug(f"Timed out waiting for trufflehog to finish on {url}")
                    return

                read_size = min(self.READ_CHUNK_BYTES, self.MAX_OUTPUT_BYTES - output_bytes)
                chunk = os.read(process.stdout.fileno(), read_size)
                if not chunk:
                    if buffered and self._emit_output_row(bytes(buffered), url, event):
                        findings += 1
                    if findings >= self.MAX_FINDINGS:
                        self._kill_and_reap(process)
                        self.info(f"Stopping after {self.MAX_FINDINGS} trufflehog findings for {url}")
                        return

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._kill_and_reap(process)
                        self.debug(f"Timed out waiting for trufflehog to finish on {url}")
                        return
                    try:
                        process.wait(timeout=remaining)
                    except TimeoutExpired:
                        self._kill_and_reap(process)
                        self.debug(f"Timed out waiting for trufflehog to finish on {url}")
                        return
                    if output_bytes == 0:
                        self.debug(f"trufflehog returned no output for {url}")
                    return

                output_bytes += len(chunk)
                search_from = len(buffered)
                buffered.extend(chunk)
                newline = buffered.find(b"\n", search_from)
                while newline >= 0:
                    row = bytes(buffered[:newline])
                    del buffered[:newline + 1]
                    if self._emit_output_row(row, url, event):
                        findings += 1
                        if findings >= self.MAX_FINDINGS:
                            self._kill_and_reap(process)
                            self.info(f"Stopping after {self.MAX_FINDINGS} trufflehog findings for {url}")
                            return
                    newline = buffered.find(b"\n")

        self._kill_and_reap(process)
        self.info(f"Stopping after {self.MAX_OUTPUT_BYTES} bytes of trufflehog output for {url}")

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        url = None

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if not self.opts['trufflehog_path']:
            self.error("You enabled sfp_tool_trufflehog but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['trufflehog_path']
        if self.opts['trufflehog_path'].endswith('/'):
            exe = f"{exe}trufflehog"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        # Extract the candidate repository URL from the event data. We deliberately
        # do NOT pre-filter on a raw substring such as `"github.com/" in eventData`:
        # that check is satisfied by hostile values like
        # https://evil.com/?x=github.com/ or https://github.com.evil.com/, so it is
        # not a sound trust boundary (CWE-20, incomplete URL substring sanitization).
        # The parsed-hostname allowlist below is the single authoritative gate.
        extraction_failed = object()
        if eventName == "SOCIAL_MEDIA":
            url = extraction_failed
            with suppress(BaseException):
                url = eventData.split(": ")[1].replace("<SFURL>", "").replace("</SFURL>", "")
        elif eventName == "PUBLIC_CODE_REPO" and self.opts['allrepos']:
            url = extraction_failed
            with suppress(BaseException):
                url = eventData.split("\n")[1].replace("URL: ", "")

        if url is extraction_failed:
            self.debug("Unable to extract repository URL, skipping.")
            return

        if not url:
            return

        # Defense-in-depth (AETHER doctrine §2): the repository URL is extracted
        # from event data by string-splitting, so without validation a crafted
        # value could begin with '-' and be parsed by trufflehog as a command-line
        # flag (argument injection). Require a well-formed http(s) URL with no
        # embedded whitespace before handing it to the subprocess.
        url = url.strip()
        if " " in url or not url.lower().startswith(("http://", "https://")):
            self.debug(f"Refusing to scan malformed repository URL: {url}")
            return

        # Validate the parsed hostname against an allowlist rather than relying on
        # a substring match of the raw event data, which would also accept hosts
        # like github.com.evil.com or evil.com/github.com.
        host = (urlparse(url).hostname or "").lower()
        allowed_domains = ("github.com", "gitlab.com", "bitbucket.org")
        if host not in allowed_domains and not any(host.endswith("." + d) for d in allowed_domains):
            self.debug(f"Refusing to scan non-allowlisted repository host: {host}")
            return

        if url in self.results:
            self.debug(f"Skipping {url} as already scanned.")
            return

        self.results[url] = True

        # --no-verification: never try discovered credentials against live
        # third-party services. --no-update: never self-update a pinned binary.
        # "--" marks end-of-options so the URL is always a positional argument.
        args = [exe, 'git', '--json', '--no-update', '--no-verification', '--', url]
        p = None
        try:
            # stderr is intentionally discarded so diagnostics cannot fill a
            # second in-memory buffer or block the child while stdout is read.
            p = Popen(args, stdout=PIPE, stderr=DEVNULL)
            self._stream_process_output(p, url, event)
        except Exception as e:
            if p is not None:
                try:
                    self._kill_and_reap(p)
                except Exception:
                    pass
            self.error(f"Unable to run trufflehog: {e}")
            return
        finally:
            if p is not None and p.stdout is not None:
                p.stdout.close()

    @staticmethod
    def maskSecret(secret) -> str:
        """Mask a secret, keeping only enough to recognise it.

        Args:
            secret (str): raw secret

        Returns:
            str: e.g. ``sk_l… [102 chars]``
        """
        if not isinstance(secret, str) or not secret:
            return "[unknown]"
        return f"{secret[:4]}\u2026 [{len(secret)} chars]"

    @staticmethod
    def _clean(value, limit: int = 300) -> str:
        """Single-line, length-bounded text from untrusted tool output.

        Args:
            value: untrusted value
            limit (int): maximum length

        Returns:
            str: cleaned text
        """
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return ""
        text = str(value).replace("\r", " ").replace("\n", " ").replace("<", "").replace(">", "")
        return text[:limit]

    def describeFinding(self, row: str, url: str):
        """Turn one TruffleHog v3 JSON result line into event data.

        Only structured location fields and a masked secret are kept. The raw
        secret (Raw/RawV2/SecretParts), ExtraData (may embed credentials), the
        commit author's email and local paths are deliberately discarded.

        Args:
            row (str): one line of trufflehog stdout
            url (str): repository URL that was scanned

        Returns:
            str: event data, or None if the line is not a finding
        """
        row = row.strip()
        if not row.startswith("{"):
            return None
        invalid_json = object()
        rowjson = invalid_json
        with suppress(ValueError):
            rowjson = json.loads(row)
        if rowjson is invalid_json:
            self.debug("Skipping non-JSON trufflehog output line.")
            return None
        if not isinstance(rowjson, dict) or "DetectorName" not in rowjson:
            return None  # log lines and other non-finding records

        git = {}
        meta = rowjson.get("SourceMetadata")
        if isinstance(meta, dict) and isinstance(meta.get("Data"), dict) and isinstance(meta["Data"].get("Git"), dict):
            git = meta["Data"]["Git"]

        detector = self._clean(rowjson.get("DetectorName"), 80) or "Unknown"
        verified = "verified" if rowjson.get("Verified") is True else "unverified"
        lines = [
            f"TruffleHog: {detector} secret ({verified})",
            f"Repository: {url}",
        ]
        location = self._clean(git.get("file"))
        if location:
            line_no = git.get("line")
            if isinstance(line_no, int) and not isinstance(line_no, bool):
                location += f":{line_no}"
            lines.append(f"File: {location}")
        commit = self._clean(git.get("commit"), 64)
        if commit:
            lines.append(f"Commit: {commit}")
        lines.append(f"Secret: {self.maskSecret(rowjson.get('Raw'))}")
        return "\n".join(lines)

# End of sfp_tool_trufflehog class
