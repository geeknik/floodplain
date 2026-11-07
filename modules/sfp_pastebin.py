# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pastebin
# Purpose:      Searches Google for PasteBin content related to the domain in
#               question.
#
# Author:      Steve Micallef <steve@binarypool.com> and ShellCodeNoobx
#
# Created:     20/03/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from spiderfoot.websearch import WebSearchFatal, hostMatches, providerFromOpts


class sfp_pastebin(SpiderFootPlugin):

    meta = {
        'name': "PasteBin",
        'summary': "PasteBin search (via the Brave Search API, or Google Custom Search until 2027-01-01) to identify related content.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://pastebin.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://pastebin.com/doc_api",
                "https://pastebin.com/faq"
            ],
            'apiKeyInstructions': [
                "Recommended: Brave Search API",
                "Visit https://api-dashboard.search.brave.com and create an account",
                "Subscribe to the Search plan (includes $5 of free credit each month, about 1,000 requests)",
                "Open 'API Keys', create a key and set it as brave_api_key",
                "Legacy (until 2027-01-01): an existing Google Custom Search API key and engine ID"
            ],
            'favIcon': "https://pastebin.com/favicon.ico",
            'logo': "https://pastebin.com/favicon.ico",
            'description': "Pastebin is a website where you can store any text online for easy sharing. "
            "The website is mainly used by programmers to store pieces of source code or "
            "configuration information, but anyone is more than welcome to paste any type of text. "
            "The idea behind the site is to make it more convenient for people to share large amounts of text online.",
        }
    }

    # Default options
    opts = {
        "brave_api_key": "",
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp",
        "max_results": 20,
    }

    # Option descriptions
    optdescs = {
        "brave_api_key": "Brave Search API key (preferred).",
        "api_key": "Google API Key (legacy; Google Custom Search is discontinued on 2027-01-01).",
        "cse_id": "Google Custom Search Engine ID (legacy).",
        "max_results": "Maximum search results to check per item (20 per billed Brave request, up to 100).",
    }

    MAX_PASTE_BYTES = 1024 * 1024

    domains = {
        'pastebin': "pastebin.com"
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

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LEAKSITE_CONTENT", "LEAKSITE_URL"]

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        provider = providerFromOpts(self.sf, self.opts, google_key_opt='api_key', google_cse_opt='cse_id')
        if provider is None:
            self.error(f"You enabled {self.__class__.__name__} but did not set a Brave Search (or Google) API key!")
            self.errorState = True
            return

        if not isinstance(eventData, str) or not eventData or len(eventData) > 254 or any(c in eventData for c in '"\t\r\n'):
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        for dom in list(self.domains.keys()):
            target = self.domains[dom]
            try:
                res = provider.search(f'site:{target} "{eventData}"', self.opts['max_results'])
            except WebSearchFatal as e:
                self.error(str(e))
                self.errorState = True
                return

            if res is None:
                # No results returned
                continue

            new_links = [link for link in res["urls"] if link not in self.results]

            # Add new links to results
            for link in new_links:
                self.results[link] = True

            relevant_links = [link for link in new_links if hostMatches(link, target)]

            for link in relevant_links:
                self.debug("Found a link: " + link)

                if self.checkForStop():
                    return

                res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts.get('_useragent', "Floodplain"),
                                       sizeLimit=self.MAX_PASTE_BYTES)

                if res['content'] is None:
                    self.debug(f"Ignoring {link} as no data returned")
                    continue

                if re.search(
                    r"[^a-zA-Z\-\_0-9]" + re.escape(eventData) + r"[^a-zA-Z\-\_0-9]",
                    res['content'],
                    re.IGNORECASE
                ) is None:
                    continue

                evt1 = SpiderFootEvent("LEAKSITE_URL", link, self.__name__, event)
                self.notifyListeners(evt1)

                evt2 = SpiderFootEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt1)
                self.notifyListeners(evt2)

# End of sfp_pastebin class
