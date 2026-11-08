# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_nuclei
# Purpose:      Floodplain module for using the 'Nuclei' tool.
#               Tool: https://github.com/EnableSecurity/nuclei
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import os
import re
import sys
import json
from netaddr import IPNetwork
from subprocess import Popen, PIPE, TimeoutExpired
from urllib.parse import urlparse

from floodplain import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_nuclei(SpiderFootPlugin):

    meta = {
        "name": "Tool - Nuclei",
        "summary": "Fast and customisable vulnerability scanner.",
        "flags": [
            "tool",
            "slow",
            "invasive"
        ],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "Nuclei",
            "description": "Fast and customisable vulnerability scanner based on simple YAML based DSL.",
            "website": "https://nuclei.projectdiscovery.io/",
            "repository": "https://github.com/projectdiscovery/nuclei"
        }
    }

    # Default options
    opts = {
        "nuclei_path": "",
        "template_path": "",
        'netblockscan': True,
        'netblockscanmax': 24
    }

    # Option descriptions
    optdescs = {
        'nuclei_path': "The path to your nuclei binary. Must be set.",
        'template_path': "The path to your nuclei templates. Must be set.",
        'netblockscan': "Check all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    # Target
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "IP_ADDRESS",
            "VULNERABILITY_GENERAL",
            "WEBSERVER_TECHNOLOGY"
        ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_nuclei":
            return

        if not self.opts['nuclei_path'] or not self.opts['template_path']:
            self.error("You enabled sfp_tool_nuclei but did not set a path to the tool and/or templates!")
            self.errorState = True
            return

        exe = self.opts['nuclei_path']
        if self.opts['nuclei_path'].endswith('/'):
            exe = f"{exe}nuclei"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData, extra=['/']):
            self.debug("Invalid input, skipping.")
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        if eventName != "INTERNET_NAME":
            # Might be a subnet within a subnet or IP within a subnet
            for addr in self.results:
                try:
                    if IPNetwork(eventData) in IPNetwork(addr):
                        self.debug(f"Skipping {eventData} as already within a scanned range.")
                        return
                except BaseException:
                    # self.results will also contain hostnames
                    continue

        self.results[eventData] = True

        timeout = 240
        try:
            target = eventData
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                target = ""
                net = IPNetwork(eventData)
                if not SpiderFootHelpers.netblockWithinLimit(net, self.opts['netblockscanmax']):
                    self.debug(f"Skipping scanning of {eventData}, too big.")
                    return

                # Nuclei doesn't support targeting subnets directly,
                # so for now work around that by listing each IP.
                for addr in IPNetwork(eventData).iter_hosts():
                    target += str(addr) + "\n"
                    timeout += 240
        except BaseException as e:
            self.error(f"Strange netblock identified, unable to parse: {eventData} ({e})")
            return

        try:
            args = [
                exe,
                "-silent",
                "-jsonl",
                "-omit-raw",
                "-disable-update-check",
                "-no-color",
                "-concurrency",
                "100",
                "-retries",
                "1",
                "-t",
                self.opts["template_path"],
                "-no-interactsh",
                "-etags",
                "dos,fuzz,misc",
            ]
            p = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(input=target.encode(sys.stdin.encoding), timeout=timeout)
                if p.returncode == 0:
                    content = stdout.decode(sys.stdout.encoding)
                else:
                    self.error("Unable to read Nuclei content.")
                    self.debug(f"Error running Nuclei: {stderr.decode('utf-8', errors='replace')[:2000]}")
                    return
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("Timed out waiting for Nuclei to finish")
                return
        except BaseException as e:
            self.error(f"Unable to run Nuclei: {e}")
            return

        if not content:
            return

        findings = 0
        for line in content.split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except ValueError:
                self.debug("Skipping non-JSON line in Nuclei output.")
                continue
            if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
                continue

            findings += 1
            if findings > self.MAX_FINDINGS:
                self.info(f"Stopping after {self.MAX_FINDINGS} Nuclei findings for {eventData}")
                break

            srcevent = event
            host = self.findingHost(data)
            if host and host != eventData:
                srctype = "IP_ADDRESS" if self.sf.validIP(host) else "INTERNET_NAME"
                srcevent = SpiderFootEvent(srctype, host, self.__name__, event)
                self.notifyListeners(srcevent)

            # CVEs come only from the template's own classification. The old
            # regex over the whole output line also matched the scanned
            # target's HTTP response, so a hostile target could inject fake
            # CVE findings.
            cves = self.templateCves(data["info"])
            for cve in cves:
                etype, cvetext = self.sf.cveInfo(cve)
                self.notifyListeners(SpiderFootEvent(etype, cvetext, self.__name__, srcevent))
            if cves:
                continue

            etype = "WEBSERVER_TECHNOLOGY" if data["info"].get("severity") == "info" else "VULNERABILITY_GENERAL"
            name = self._clean(data["info"].get("name"))
            template_id = self._clean(data.get("template-id"))
            datatext = f"Template: {name}({template_id})\n"
            matcher = self._clean(data.get("matcher-name"))
            if matcher:
                datatext += f"Matcher: {matcher}\n"
            datatext += f"Matched at: {self._clean(data.get('matched-at'), 500)}\n"
            reference = data["info"].get("reference")
            if isinstance(reference, list) and reference and isinstance(reference[0], str) \
                    and reference[0].startswith(("http://", "https://")):
                datatext += f"Reference: <SFURL>{self._clean(reference[0], 500)}</SFURL>"

            self.notifyListeners(SpiderFootEvent(etype, datatext, self.__name__, srcevent))

    MAX_FINDINGS = 1000

    @staticmethod
    def _clean(value, limit: int = 200) -> str:
        """Single-line, markup-free, length-bounded text from tool output.

        Args:
            value: untrusted value
            limit (int): maximum length

        Returns:
            str: cleaned text
        """
        if not isinstance(value, str):
            return ""
        return value.replace("\r", " ").replace("\n", " ").replace("<", "").replace(">", "")[:limit]

    @staticmethod
    def templateCves(info: dict) -> list:
        """CVE IDs declared by the matching template.

        Args:
            info (dict): the finding's ``info`` block

        Returns:
            list: upper-cased, de-duplicated CVE IDs
        """
        classification = info.get("classification")
        if not isinstance(classification, dict):
            return []
        ids = classification.get("cve-id")
        if isinstance(ids, str):
            ids = [ids]
        if not isinstance(ids, list):
            return []
        out = []
        for cve in ids:
            if isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve.upper()) and cve.upper() not in out:
                out.append(cve.upper())
        return out

    def findingHost(self, data: dict):
        """Host a finding was matched on, validated.

        Args:
            data (dict): Nuclei v3 JSONL finding

        Returns:
            str: hostname or IP address, or None
        """
        host = data.get("host")
        if not isinstance(host, str) or not host:
            host = data.get("matched-at") if isinstance(data.get("matched-at"), str) else ""
        if "://" in host:
            host = urlparse(host).hostname or ""
        elif host.count(":") == 1:
            host = host.split(":")[0]
        host = host.strip("[]").lower().rstrip(".")
        if self.sf.validIP(host) or self.sf.validIP6(host):
            return host
        if SpiderFootHelpers.sanitiseInput(host):
            return host
        return None


# End of sfp_tool_nuclei class
