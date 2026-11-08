# -------------------------------------------------------------------------------
# Name:         sfp_bravesearch
# Purpose:      Find pages hosted on the target via the Brave Search API.
#
# Author:       geeknik
#
# Created:      2026-11-07
# Licence:      MIT
# -------------------------------------------------------------------------------
#
# Successor to sfp_googlesearch (Google Custom Search JSON API is discontinued
# on 2027-01-01). Uses the shared spiderfoot.websearch interface.

import json

from floodplain import SpiderFootEvent, SpiderFootPlugin
from floodplain.websearch import BraveSearch, WebSearchFatal, hostMatches


class sfp_bravesearch(SpiderFootPlugin):

    meta = {
        'name': "Brave Search",
        'summary': "Search the Brave Search API for pages hosted on the target to identify sub-domains and links.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://brave.com/search/api/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api-dashboard.search.brave.com/documentation/services/web-search",
                "https://api-dashboard.search.brave.com/documentation/resources/search-operators",
                "https://api-dashboard.search.brave.com/documentation/pricing"
            ],
            'apiKeyInstructions': [
                "Visit https://api-dashboard.search.brave.com and create an account",
                "Subscribe to the Search plan (includes $5 of free credit each month, about 1,000 requests)",
                "Open 'API Keys' and create a key"
            ],
            'favIcon': "https://brave.com/static-assets/images/brave-favicon.png",
            'description': "Brave Search runs its own independent web index. "
            "The Brave Search API returns web results for queries including operators such as site:.",
        }
    }

    opts = {
        'brave_api_key': '',
        'max_results': 20,
    }

    optdescs = {
        'brave_api_key': "Brave Search API key.",
        'max_results': "Maximum results per hostname (20 per billed request, up to 100).",
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
        return ["INTERNET_NAME"]

    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        if self.errorState:
            return

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if not self.opts['brave_api_key']:
            self.error(f"You enabled {self.__class__.__name__} but did not set a Brave Search API key!")
            self.errorState = True
            return

        host = event.data
        if not isinstance(host, str) or not host or len(host) > 253 or any(c in host for c in ' "\'\t\r\n'):
            self.debug("Skipping malformed hostname.")
            return
        host = host.lower().rstrip('.')

        if host in self.results:
            self.debug(f"Already searched for {host}, skipping.")
            return
        self.results[host] = True

        provider = BraveSearch(self.sf, self.opts['brave_api_key'],
                               self.opts.get('_fetchtimeout', 15), self.opts.get('_useragent', "Floodplain"))
        try:
            res = provider.search(f"site:{host}", self.opts['max_results'])
        except WebSearchFatal as e:
            self.error(str(e))
            self.errorState = True
            return

        if not res:
            return

        internal = []
        for link in res['urls']:
            if link in self.results or not hostMatches(link, host):
                continue
            self.results[link] = True
            internal.append(link)

        for link in internal:
            self.notifyListeners(SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__, event))

        if internal:
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps(res), self.__name__, event))

# End of sfp_bravesearch class
