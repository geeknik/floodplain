# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googlesearch
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from floodplain import SpiderFootEvent, SpiderFootPlugin
from floodplain.websearch import GoogleCustomSearch, WebSearchFatal, hostMatches


class sfp_googlesearch(SpiderFootPlugin):

    meta = {
        'name': "Google",
        'summary': "Obtain information from the Google Custom Search API to identify sub-domains and links (API discontinued by Google on 2027-01-01; use Brave Search).",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://developers.google.com/custom-search",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.google.com/custom-search/v1",
                "https://developers.google.com/custom-search/docs/overview",
                "https://cse.google.com/cse"
            ],
            'apiKeyInstructions': [
                "Visit https://developers.google.com/custom-search/v1/introduction",
                "Register a free Google account",
                "Click on 'Get A Key'",
                "Connect a Project",
                "The API Key will be listed under 'YOUR API KEY'"
            ],
            'favIcon': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/developers/images/favicon.png",
            'logo': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/developers/images/favicon.png",
            'description': "Google Custom Search enables you to create a search engine for your website, your blog, or a collection of websites. "
            "You can configure your engine to search both web pages and images. "
            "You can fine-tune the ranking, add your own promotions and customize the look and feel of the search results. "
            "You can monetize the search by connecting your engine to your Google AdSense account.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp"
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API Key for Google search.",
        "cse_id": "Google Custom Search Engine ID."
    }

    # Target
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
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_googlesearch but did not set a Google API key!")
            self.errorState = True
            return

        if not isinstance(eventData, str) or any(c in eventData for c in ' "\'\t\r\n'):
            return
        host = eventData.lower().rstrip('.')

        if host in self.results:
            self.debug("Already did a search for " + host + ", skipping.")
            return

        self.results[host] = True

        provider = GoogleCustomSearch(self.sf, self.opts['api_key'], self.opts['cse_id'],
                                      self.opts.get('_fetchtimeout', 15), self.opts.get('_useragent', "Floodplain"))
        try:
            res = provider.search(f"site:{host}", 10)
        except WebSearchFatal as e:
            self.error(str(e))
            self.errorState = True
            return

        if res is None:
            # Failed to talk to the Google API or no results returned
            return

        internal_links = []
        for link in res["urls"]:
            if link in self.results or not hostMatches(link, host):
                continue
            self.results[link] = True
            internal_links.append(link)

        for link in internal_links:
            self.debug("Found a link: " + link)
            evt = SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__, event)
            self.notifyListeners(evt)

        if internal_links:
            evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(res), self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_googlesearch class
