# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_trufflehog
# Purpose:     SpiderFoot plug-in for using the trufflehog tool.
#              Tool: https://github.com/trufflesecurity/truffleHog
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import sys
import json
import os
from subprocess import PIPE, Popen, TimeoutExpired
from urllib.parse import urlparse

from spiderfoot import SpiderFootPlugin, SpiderFootEvent


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
            'website': "https://github.com/trufflesecurity/truffleHog",
            'repository': "https://github.com/trufflesecurity/truffleHog",
        },
    }

    opts = {
        'entropy': False,
        'allrepos': False,
        'trufflehog_path': ''
    }

    optdescs = {
        'trufflehog_path': "Path to your trufflehog binary. Must be set.",
        'entropy': "Enable entropy checks? If disabled, TruffleHog will solely rely on high-signal regular expressions to identify secrets.",
        'allrepos': "Search all code repositories found. By default TruffleHog only searches those linked from the target website."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "Target Website"

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

        args = [
            exe,
            '--json',
            '--regex',
        ]

        if not self.opts['entropy']:
            args.append("--entropy=False")
        else:
            args.append("--entropy=True")

        # "--" marks end-of-options so the URL is always treated as a positional
        # argument and never as a flag, even if validation above is ever loosened.
        args.append("--")
        args.append(url)
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, _ = p.communicate(input=None, timeout=600)
            stdout = out.decode(sys.stdin.encoding)
        except TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            self.debug(f"Timed out waiting for trufflehog to finish on {url}")
            return
        except Exception as e:
            self.error(f"Unable to run trufflehog: {e}")
            return

        if not stdout:
            self.debug(f"trufflehog returned no output for {url}")
            return

        for row in stdout.split("\n"):
            row = row.strip()
            if len(row) == 0:
                continue
            try:
                rowjson = json.loads(row)
            except BaseException as e:
                self.error(f"Could not parse trufflehog output as JSON: {row}\nException: {e}")
                continue

            descr = "\n".join(
                f"{k}: {rowjson[k]}"
                for k in rowjson
                if k not in ["diff", "printDiff"]
            )
            evt = SpiderFootEvent('PASSWORD_COMPROMISED', descr, self.__name__, event)
            self.notifyListeners(evt)

        return

# End of sfp_tool_trufflehog class
