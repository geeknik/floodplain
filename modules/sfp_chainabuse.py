# -------------------------------------------------------------------------------
# Name:         sfp_chainabuse
# Purpose:      Check cryptocurrency addresses against Chainabuse scam reports.
#
# Author:       geeknik
#
# Created:      2026-11-07
# Licence:      MIT
# -------------------------------------------------------------------------------
#
# Replaces sfp_bitcoinabuse: BitcoinAbuse merged into Chainabuse (TRM Labs) and
# its API no longer exists.
#
# Threat model
#   * Trust boundary: Chainabuse API responses are untrusted. Every field used
#     is type-checked and allow-listed before it reaches an event.
#   * Secret: the API key is sent only as an HTTP Basic Authorization header
#     (never in the URL) and never logged or emitted.
#   * Privacy: reports contain free-text written by victims. Only structured
#     fields (count, categories, flags, date, IDs) are emitted; descriptions,
#     losses, evidence and IPs are discarded.
#   * Quota: free keys get 10 calls/month, so lookups are de-duplicated,
#     capped per scan, and the module stops on 403/429.

import base64
import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

ADDRESS_RE = re.compile(r'^[A-Za-z0-9]{20,100}$')
CATEGORY_RE = re.compile(r'^[A-Z][A-Z_]{0,39}$')
REPORT_ID_RE = re.compile(r'^[0-9a-fA-F-]{1,64}$')
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}')


class sfp_chainabuse(SpiderFootPlugin):

    meta = {
        'name': "Chainabuse",
        'summary': "Check Bitcoin addresses against Chainabuse (formerly BitcoinAbuse) scam reports.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.chainabuse.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.trmlabs.com/guides/chainabuse/welcome-to-chainabuse-api",
                "https://docs.trmlabs.com/api/chainabuse/reports/get-reports",
                "https://docs.trmlabs.com/guides/chainabuse/getting-started-2-1"
            ],
            'apiKeyInstructions': [
                "Visit https://www.chainabuse.com and create a free account",
                "Open your profile (top right) > View Profile > Settings > API key",
                "Generate an API key (free keys allow 10 calls per month)"
            ],
            'favIcon': "https://www.chainabuse.com/images/favicon/favicon-32x32.png",
            'description': "Chainabuse is a multi-chain scam reporting platform run by TRM Labs. "
            "It absorbed BitcoinAbuse and lets anyone report and screen crypto addresses "
            "and domains linked to scams, ransomware, phishing and other fraud.",
        }
    }

    opts = {
        'api_key': '',
        'max_queries': 5,
    }

    optdescs = {
        'api_key': "Chainabuse API key.",
        'max_queries': "Maximum addresses to look up per scan (free keys allow only 10 calls per month).",
    }

    results = None
    errorState = False
    queries = 0

    API_URL = "https://api.chainabuse.com/v0/reports"
    MAX_QUERIES_HARD = 100
    MAX_RESPONSE_BYTES = 1024 * 1024

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.queries = 0

        # Per-instance copy: never mutate the class-level defaults.
        self.opts = dict(self.opts)
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["BITCOIN_ADDRESS"]

    def producedEvents(self):
        return ["MALICIOUS_BITCOIN_ADDRESS", "RAW_RIR_DATA"]

    def queryLimit(self) -> int:
        """Per-scan lookup limit, clamped to a sane range.

        Returns:
            int: maximum number of API calls for this scan
        """
        try:
            return min(max(int(self.opts['max_queries']), 0), self.MAX_QUERIES_HARD)
        except (TypeError, ValueError):
            return 0

    def queryAddress(self, address: str):
        """Fetch reports for an address.

        Args:
            address (str): validated address

        Returns:
            list: report dicts, or None on error
        """
        token = base64.b64encode(f"{self.opts['api_key']}:{self.opts['api_key']}".encode()).decode()
        res = self.sf.fetchUrl(
            f"{self.API_URL}?address={address}&perPage=50",
            headers={'Accept': "application/json", 'Authorization': f"Basic {token}"},
            timeout=self.opts.get('_fetchtimeout', 15),
            useragent=self.opts.get('_useragent', "Floodplain"),
            sizeLimit=self.MAX_RESPONSE_BYTES
        )
        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        """Validate a Chainabuse response.

        Args:
            res (dict): fetchUrl result

        Returns:
            list: report dicts (possibly empty), or None on error
        """
        if not res:
            self.error("No response from Chainabuse.")
            return None

        code = str(res.get('code'))

        if code in ('401', '403'):
            self.error("Chainabuse rejected the API key or the monthly quota is used up.")
            self.errorState = True
            return None

        if code == '429':
            self.error("You are being rate-limited by Chainabuse.")
            self.errorState = True
            return None

        if code in ('400', '404'):
            self.debug(f"Chainabuse returned HTTP {code}; treating as no reports.")
            return []

        if code != '200':
            self.error(f"Unexpected reply from Chainabuse: HTTP {code}")
            self.errorState = True
            return None

        try:
            data = json.loads(res.get('content') or '')
        except (ValueError, TypeError) as e:
            self.debug(f"Error processing JSON response from Chainabuse: {e}")
            return None

        if not isinstance(data, dict) or not isinstance(data.get('reports'), list):
            self.debug("Unexpected JSON structure from Chainabuse.")
            return None

        return [r for r in data['reports'] if isinstance(r, dict)]

    @staticmethod
    def reportMentions(report: dict, address: str) -> bool:
        """Check that a report actually lists the queried address.

        Args:
            report (dict): report
            address (str): queried address

        Returns:
            bool: the address appears in the report's address list
        """
        addresses = report.get('addresses')
        if not isinstance(addresses, list):
            return False
        return any(isinstance(a, dict) and a.get('address') == address for a in addresses)

    @staticmethod
    def summarise(address: str, reports: list) -> dict:
        """Build a minimal, privacy-preserving summary of reports.

        Args:
            address (str): queried address
            reports (list): validated reports that mention the address

        Returns:
            dict: summary
        """
        categories = sorted({r['scamCategory'] for r in reports
                             if isinstance(r.get('scamCategory'), str) and CATEGORY_RE.match(r['scamCategory'])})
        dates = sorted(r['createdAt'][:10] for r in reports
                       if isinstance(r.get('createdAt'), str) and DATE_RE.match(r['createdAt']))
        ids = [r['id'] for r in reports if isinstance(r.get('id'), str) and REPORT_ID_RE.match(r['id'])]
        return {
            'address': address,
            'reports': len(reports),
            'trusted_reports': sum(1 for r in reports if r.get('trusted') is True),
            'checked_reports': sum(1 for r in reports if r.get('checked') is True),
            'categories': categories,
            'latest_report': dates[-1] if dates else None,
            'report_ids': ids[:50],
        }

    def handleEvent(self, event):
        if self.errorState:
            return

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if not self.opts['api_key']:
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        address = event.data
        if not isinstance(address, str) or not ADDRESS_RE.match(address):
            self.debug("Skipping malformed address.")
            return

        if address in self.results:
            self.debug(f"Skipping {address}, already checked.")
            return

        if self.queries >= self.queryLimit():
            self.debug("Chainabuse per-scan query limit reached; skipping.")
            return

        self.results[address] = True
        self.queries += 1

        reports = self.queryAddress(address)
        if not reports:
            return

        reports = [r for r in reports if self.reportMentions(r, address)]
        if not reports:
            return

        summary = self.summarise(address, reports)
        detail = f"{summary['reports']} report(s)"
        if summary['categories']:
            detail += ": " + ", ".join(summary['categories'])

        evt = SpiderFootEvent(
            "MALICIOUS_BITCOIN_ADDRESS",
            f"Chainabuse [{address}] ({detail})\n<SFURL>https://chainabuse.com/address/{address}</SFURL>",
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(summary), self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_chainabuse class
