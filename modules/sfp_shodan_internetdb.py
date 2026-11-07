# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_shodan_internetdb
# Purpose:     Query Shodan's free InternetDB for open ports, vulnerabilities,
#              CPEs and hostnames associated with an IP address. No API key.
#
# Author:      Floodplain contributors
#
# Created:     2026-11-07
# Licence:     MIT
# -------------------------------------------------------------------------------

import ipaddress
import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_shodan_internetdb(SpiderFootPlugin):

    meta = {
        'name': "Shodan InternetDB",
        'summary': "Obtain open ports, vulnerabilities, CPEs and hostnames for IP addresses "
        "from Shodan's free InternetDB. No API key required.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://internetdb.shodan.io/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://internetdb.shodan.io/",
                "https://internetdb.shodan.io/docs"
            ],
            'favIcon': "https://static.shodan.io/shodan/img/favicon.png",
            'logo': "https://static.shodan.io/developer/img/logo.png",
            'description': "InternetDB provides a fast, free, keyless view of the open ports, "
            "vulnerabilities, CPEs, hostnames and tags Shodan has observed for an IP address. "
            "Data is refreshed weekly. Free for non-commercial use; commercial use requires "
            "an enterprise license from Shodan.",
        }
    }

    opts = {
        'cvelookup': True,
        'skip_nonglobal': True,
    }

    optdescs = {
        'cvelookup': "Look up the severity of reported CVEs (NIST/CIRCL) to classify them. "
        "If disabled, vulnerabilities are reported as VULNERABILITY_GENERAL.",
        'skip_nonglobal': "Do not send private, reserved, loopback or other non-global IP "
        "addresses to the third-party service (recommended).",
    }

    # Upper bounds on what we accept from the remote service (fail closed on
    # anything larger or malformed rather than flooding the event pipeline).
    MAX_ITEMS = 1000
    MAX_STR_LEN = 255

    CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
    # Applied per DNS label (no nested quantifiers, so no ReDoS risk).
    LABEL_RE = re.compile(r'^[a-z0-9-]{1,63}$')

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS"]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "TCP_PORT_OPEN",
            "SOFTWARE_USED",
            "INTERNET_NAME",
            "CO_HOSTED_SITE",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
        ]

    def query(self, ip: str):
        """Query InternetDB for an IP address.

        Args:
            ip (str): validated IPv4 or IPv6 address

        Returns:
            dict: parsed response, or None if no data / on error
        """
        res = self.sf.fetchUrl(
            f"https://internetdb.shodan.io/{ip}",
            timeout=self.opts.get('_fetchtimeout', 15),
            useragent=self.opts.get('_useragent', "Floodplain")
        )

        if not res:
            return None

        code = str(res.get('code'))

        if code == "404":
            self.debug(f"No InternetDB data for {ip}")
            return None

        if code == "429":
            self.error("Shodan InternetDB rate limit exceeded; disabling module for this scan.")
            self.errorState = True
            return None

        if code != "200":
            self.error(f"Unexpected HTTP response code {code} from Shodan InternetDB.")
            return None

        if not res.get('content'):
            return None

        try:
            data = json.loads(res['content'])
        except (ValueError, TypeError) as e:
            self.debug(f"Error processing JSON response from Shodan InternetDB: {e}")
            return None

        return self.validateResponse(data, ip)

    def validHostname(self, hostname: str) -> bool:
        """Validate a DNS hostname label-by-label (RFC 1123), in linear time.

        Args:
            hostname (str): lower-cased hostname without a trailing dot

        Returns:
            bool: hostname is syntactically valid
        """
        if not hostname or len(hostname) > 253:
            return False

        labels = hostname.split('.')
        if len(labels) < 2:
            return False

        for label in labels:
            if not self.LABEL_RE.match(label):
                return False
            if label.startswith('-') or label.endswith('-'):
                return False

        return True

    def validateResponse(self, data, ip: str):
        """Validate an untrusted InternetDB response and return a sanitized copy.

        Fails closed: anything that does not match the documented schema is
        dropped rather than passed into the event pipeline.

        Args:
            data: decoded JSON from the service
            ip (str): the IP address that was queried

        Returns:
            dict: sanitized response, or None if the response is unusable
        """
        if not isinstance(data, dict):
            return None

        # The response must describe the IP we asked about.
        try:
            if ipaddress.ip_address(str(data.get('ip'))) != ipaddress.ip_address(ip):
                self.debug(f"InternetDB response IP mismatch for {ip}")
                return None
        except ValueError:
            return None

        clean = {'ip': ip, 'ports': [], 'cpes': [], 'hostnames': [], 'vulns': [], 'tags': []}

        for field in ('ports', 'cpes', 'hostnames', 'vulns', 'tags'):
            values = data.get(field, [])
            if not isinstance(values, list):
                return None
            if len(values) > self.MAX_ITEMS:
                self.debug(f"InternetDB '{field}' list for {ip} exceeds bound; truncating.")
                values = values[:self.MAX_ITEMS]
            for v in values:
                if field == 'ports':
                    # bool is a subclass of int; reject it explicitly.
                    if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 65535:
                        clean['ports'].append(v)
                    continue
                if not isinstance(v, str) or not v or len(v) > self.MAX_STR_LEN:
                    continue
                if field == 'cpes' and not v.startswith('cpe:'):
                    continue
                if field == 'vulns' and not self.CVE_RE.match(v):
                    continue
                if field == 'hostnames':
                    v = v.lower().rstrip('.')
                    if not self.validHostname(v):
                        continue
                clean[field].append(v)

        return clean

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        try:
            addr = ipaddress.ip_address(eventData)
        except ValueError:
            self.debug(f"Skipping invalid IP address: {eventData}")
            return

        if self.opts['skip_nonglobal'] and not addr.is_global:
            self.debug(f"Skipping non-global IP address {eventData} (not sent to third party).")
            return

        ip = str(addr)
        data = self.query(ip)

        if not data:
            return

        if self.checkForStop():
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data, sort_keys=True), self.__name__, event)
        self.notifyListeners(evt)

        for port in sorted(set(data['ports'])):
            # IPv6 addresses are bracketed so "addr:port" stays unambiguous.
            host = f"[{ip}]" if addr.version == 6 else ip
            evt = SpiderFootEvent("TCP_PORT_OPEN", f"{host}:{port}", self.__name__, event)
            self.notifyListeners(evt)

        for cpe in sorted(set(data['cpes'])):
            evt = SpiderFootEvent("SOFTWARE_USED", cpe, self.__name__, event)
            self.notifyListeners(evt)

        for hostname in sorted(set(data['hostnames'])):
            if self.getTarget().matches(hostname, includeParents=True):
                evt = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
            else:
                evt = SpiderFootEvent("CO_HOSTED_SITE", hostname, self.__name__, event)
            self.notifyListeners(evt)

        for cve in sorted(set(data['vulns'])):
            if self.checkForStop():
                return

            if self.opts['cvelookup']:
                etype, cvetext = self.sf.cveInfo(cve)
            else:
                etype, cvetext = "VULNERABILITY_GENERAL", cve

            evt = SpiderFootEvent(etype, cvetext, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_shodan_internetdb class
