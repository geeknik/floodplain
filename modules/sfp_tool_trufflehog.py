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
from subprocess import PIPE, Popen, TimeoutExpired
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
        if eventName == "SOCIAL_MEDIA":
            try:
                url = eventData.split(": ")[1].replace("<SFURL>", "").replace("</SFURL>", "")
            except BaseException:
                self.debug("Unable to extract repository URL, skipping.")
                return
        elif eventName == "PUBLIC_CODE_REPO" and self.opts['allrepos']:
            try:
                url = eventData.split("\n")[1].replace("URL: ", "")
            except BaseException:
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
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, _ = p.communicate(input=None, timeout=600)
        except TimeoutExpired:
            p.kill()
            p.communicate()
            self.debug(f"Timed out waiting for trufflehog to finish on {url}")
            return
        except Exception as e:
            self.error(f"Unable to run trufflehog: {e}")
            return

        if not out:
            self.debug(f"trufflehog returned no output for {url}")
            return

        stdout = out[:self.MAX_OUTPUT_BYTES].decode('utf-8', errors='replace')
        findings = 0
        for row in stdout.split("\n"):
            descr = self.describeFinding(row, url)
            if descr is None:
                continue
            evt = SpiderFootEvent('PASSWORD_COMPROMISED', descr, self.__name__, event)
            self.notifyListeners(evt)
            findings += 1
            if findings >= self.MAX_FINDINGS:
                self.info(f"Stopping after {self.MAX_FINDINGS} trufflehog findings for {url}")
                break

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
        try:
            rowjson = json.loads(row)
        except ValueError:
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
