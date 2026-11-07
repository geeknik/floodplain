# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_phishstats
# Purpose:     Floodplain module to search PhishStats API
#              to determine if an IP is malicious.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     18/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_phishstats(SpiderFootPlugin):

    meta = {
        'name': "PhishStats",
        'summary': "Check if a netblock or IP address is malicious according to PhishStats.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://phishstats.info/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://phishstats.info/api-docs",
                "https://phishstats.info/faq"
            ],
            'apiKeyInstructions': [
                "Optional: without a key PhishStats allows 50 requests/day per IP",
                "Visit https://phishstats.info and register a free account",
                "Go to Settings > API keys and create a key (150 requests/day free)"
            ],
            'favIcon': "https://phishstats.info/phish.ico",
            'description': "PhishStats is a real time Phishing database that gathers phishing URLs from several sources.",
        }
    }

    opts = {
        'api_key': '',
        'checkaffiliates': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
    }

    optdescs = {
        'api_key': "PhishStats API key (optional; raises the daily request limit).",
        'checkaffiliates': "Apply checks to affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Per-instance copy: never mutate the class-level defaults.
        self.opts = dict(self.opts)
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "RAW_RIR_DATA",
        ]

    API_URL = "https://api.phishstats.info/api/phishing"
    MAX_RESPONSE_BYTES = 256 * 1024
    # Published limit: 20 requests/minute.
    QUERY_INTERVAL = 3.1

    # Check whether the IP address is malicious using PhishStats API
    # https://phishstats.info/api-docs
    def queryIPAddress(self, qry):
        """Look up an IP address in PhishStats.

        Args:
            qry (str): IP address

        Returns:
            list: matching records, or None
        """
        # The address is interpolated into PhishStats' filter syntax, so only
        # a canonical IP may reach it (no ',', ')' or '~or' injection).
        try:
            ip = str(IPAddress(qry))
        except Exception:
            self.debug("Skipping invalid IP address.")
            return None

        params = {
            '_where': f"(ip,eq,{ip})",
            '_size': 1
        }

        headers = {
            'Accept': "application/json",
        }
        if self.opts.get('api_key'):
            headers['X-API-Key'] = self.opts['api_key']

        res = self.sf.fetchUrl(
            f"{self.API_URL}?{urllib.parse.urlencode(params)}",
            headers=headers,
            timeout=15,
            useragent=self.opts.get('_useragent', "Floodplain"),
            sizeLimit=self.MAX_RESPONSE_BYTES
        )

        code = str(res.get('code'))
        if code in ('401', '403'):
            self.error("PhishStats rejected the API key.")
            self.errorState = True
            return None
        if code == '429':
            self.error("PhishStats request limit reached; set an API key to raise it.")
            self.errorState = True
            return None
        if code != "200" or not res.get('content'):
            self.debug(f"No information found from PhishStats for {ip}.")
            return None

        try:
            data = json.loads(res['content'])
        except (ValueError, TypeError) as e:
            self.error(f"Error processing JSON response: {e}")
            return None

        if not isinstance(data, list):
            return None
        return [r for r in data if isinstance(r, dict)]

    def netblockAllowed(self, netblock, max_prefix):
        """Check a netblock is IPv4 and no larger than the configured maximum.

        Bounds the number of lookups regardless of the event's claimed type,
        so a mislabelled or hostile IPv6 prefix can never expand to 2^64 hosts.

        Args:
            netblock (str): CIDR netblock
            max_prefix (int): smallest allowed IPv4 prefix length

        Returns:
            bool: netblock may be expanded
        """
        try:
            net = IPNetwork(netblock)
            max_prefix = int(max_prefix)
        except Exception:
            self.debug("Skipping invalid netblock.")
            return False

        if net.version != 4 or not 0 <= max_prefix <= 32:
            self.debug(f"Skipping non-IPv4 or out-of-range netblock {netblock}.")
            return False

        if net.prefixlen < max_prefix:
            self.debug(f"Network size bigger than permitted: {net.prefixlen} < {max_prefix}")
            return False

        return True

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'IP_ADDRESS':
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            if not self.netblockAllowed(eventData, self.opts['maxsubnet']):
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            if not self.netblockAllowed(eventData, self.opts['maxnetblock']):
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            try:
                qrylist.append(str(IPAddress(eventData)))
            except Exception:
                self.debug("Skipping invalid IP address.")
                return

        for i, addr in enumerate(qrylist):
            if self.checkForStop() or self.errorState:
                return

            if i:
                time.sleep(self.QUERY_INTERVAL)

            data = self.queryIPAddress(addr)

            if not data:
                continue

            # TODO: iterate through hosts and extract co-hosts
            maliciousIP = data[0].get('ip')

            if not maliciousIP:
                continue

            if addr != maliciousIP:
                self.error(f"Reported address {maliciousIP} doesn't match queried IP address {addr}, skipping")
                continue

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCK_MEMBER':
                pevent = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, pevent)
            self.notifyListeners(evt)

            text = f"PhishStats [{addr}]"

            evt = SpiderFootEvent(blacklist_type, text, self.__name__, pevent)
            self.notifyListeners(evt)

            evt = SpiderFootEvent(malicious_type, text, self.__name__, pevent)
            self.notifyListeners(evt)

# End of sfp_phishstats class
