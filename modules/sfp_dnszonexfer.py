# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnszonexfer
# Purpose:      Floodplain module for attempting a DNS zone transfer.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/08/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     MIT
# -------------------------------------------------------------------------------

import re
import time

import dns.query

from floodplain import SpiderFootEvent, SpiderFootPlugin


class _ZoneTransferLimitExceeded(Exception):
    pass


class sfp_dnszonexfer(SpiderFootPlugin):

    meta = {
        'name': "DNS Zone Transfer",
        'summary': "Attempts to perform a full DNS zone transfer.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"]
    }

    opts = {
        "timeout": 30
    }

    optdescs = {
        "timeout": "Timeout in seconds"
    }

    events = None

    # AXFR data is controlled by the remote nameserver. Keep every retained
    # representation and downstream event fan-out within a finite budget.
    MAX_RECORDS = 10000
    MAX_WIRE_BYTES = 10 * 1024 * 1024
    MAX_DECODED_BYTES = 1024 * 1024
    MAX_EVENT_BYTES = 1024 * 1024
    MAX_NAME_EVENTS = 1000

    INTERNET_NAME_PATTERN = re.compile(r"^(\S+)\.?\s+\d+\s+IN\s+[AC].*", re.IGNORECASE | re.DOTALL)

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['PROVIDER_DNS']

    def producedEvents(self):
        return ["RAW_DNS_RECORDS", "INTERNET_NAME"]

    def _consumeZoneTransfer(self, transfer, name, deadline):
        records = list()
        seenRecords = set()
        internetNames = list()
        seenInternetNames = set()
        recordCount = 0
        wireBytes = 0
        decodedBytes = 0
        eventBytes = 0

        for response in transfer:
            if time.monotonic() > deadline:
                raise _ZoneTransferLimitExceeded("total time limit exceeded")

            # Include the two-byte TCP DNS message length prefix in the wire budget.
            wireBytes += len(response.to_wire()) + 2
            if wireBytes > self.MAX_WIRE_BYTES:
                raise _ZoneTransferLimitExceeded("wire byte limit exceeded")

            for rrset in response.answer:
                if time.monotonic() > deadline:
                    raise _ZoneTransferLimitExceeded("total time limit exceeded")

                recordCount += len(rrset)
                if recordCount > self.MAX_RECORDS:
                    raise _ZoneTransferLimitExceeded("record limit exceeded")

                row = rrset.to_text()
                rowBytes = len(row.encode("utf-8"))
                decodedBytes += rowBytes
                if decodedBytes > self.MAX_DECODED_BYTES:
                    raise _ZoneTransferLimitExceeded("decoded byte limit exceeded")

                # dns.zone.from_xfr() deduplicated records, including the closing
                # SOA. Preserve that behavior without materializing a zone.
                if row in seenRecords:
                    continue

                separatorBytes = 1 if records else 0
                if eventBytes + separatorBytes + rowBytes > self.MAX_EVENT_BYTES:
                    raise _ZoneTransferLimitExceeded("raw event byte limit exceeded")

                seenRecords.add(row)
                records.append(row)
                eventBytes += separatorBytes + rowBytes

                for strdata in self.INTERNET_NAME_PATTERN.findall(row):
                    if strdata.endswith("."):
                        strdata = strdata[:-1]
                    else:
                        strdata = strdata + "." + name

                    if strdata in seenInternetNames:
                        continue

                    if len(internetNames) >= self.MAX_NAME_EVENTS:
                        raise _ZoneTransferLimitExceeded("internet name event limit exceeded")

                    seenInternetNames.add(strdata)
                    internetNames.append(strdata)

        return records, internetNames

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        parentEvent = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == "sfp_dnszonexfer":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventDataHash in self.events:
            self.debug("Skipping duplicate event for " + eventData)
            return

        self.events[eventDataHash] = True

        res = dns.resolver.Resolver()
        if self.opts.get('_dnsserver', "") != "":
            res.nameservers = [self.opts['_dnsserver']]

        # Get the name server's IP. This is to avoid DNS leaks
        # when attempting to resolve the name server during
        # the zone transfer.
        if not self.sf.validIP(eventData) and not self.sf.validIP6(eventData):
            nsips = self.sf.resolveHost(eventData)
            if not nsips:
                return

            if not nsips:
                self.error("Couldn't resolve the name server, so not attempting zone transfer.")
                return

            for n in nsips:
                if self.sf.validIP(n):
                    nsip = n
                    break
        else:
            nsip = eventData

        for name in self.getTarget().getNames():
            self.debug("Trying for name: " + name)
            try:
                timeout = int(self.opts["timeout"])
                deadline = time.monotonic() + timeout
                transfer = dns.query.xfr(nsip, name, timeout=timeout, lifetime=timeout)
                records, internetNames = self._consumeZoneTransfer(transfer, name, deadline)

                evt = SpiderFootEvent("RAW_DNS_RECORDS", "\n".join(records), self.__name__, parentEvent)
                self.notifyListeners(evt)

                # Try and pull out individual records
                for strdata in internetNames:
                    self.debug("Matched: " + strdata)
                    evt = SpiderFootEvent("INTERNET_NAME", strdata, self.__name__, parentEvent)
                    self.notifyListeners(evt)

            except _ZoneTransferLimitExceeded as e:
                self.info(f"Rejected DNS zone transfer for {eventData} ({name}): {e}")

            except Exception as e:
                self.info(f"Unable to perform DNS zone transfer for {eventData} ({name}): {e}")

# End of sfp_dnszonexfer class
