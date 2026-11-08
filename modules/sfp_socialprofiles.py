# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_socialprofiles
# Purpose:      Tries to discover social media profiles of any identified human names.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from floodplain import SpiderFootEvent, SpiderFootPlugin
from floodplain.websearch import BraveSearch, GoogleCustomSearch, WebSearchFatal, hostMatches

# Site name -> (search query template, profile domain, profile URL patterns).
# Queries are URL-encoded by the search provider; patterns run against result
# URLs only, and a match is only accepted if its host is the profile domain.
sites = {
    "Facebook": (
        '"{name}" site:facebook.com',
        "facebook.com",
        [r'^(https?://(?:[a-z0-9-]+\.)*facebook\.com/[^/?#"\'<> ]+/?)'],
    ),
    "LinkedIn": (
        '"{name}" site:linkedin.com',
        "linkedin.com",
        [r'^(https?://(?:[a-z0-9-]+\.)*linkedin\.com/in/[^/?#"\'<> ]+/?)'],
    ),
}


class sfp_socialprofiles(SpiderFootPlugin):

    meta = {
        'name': "Social Media Profile Finder",
        'summary': "Tries to discover the social media profiles for human names identified.",
        'flags': ["slow", "apikey"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://brave.com/search/api/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api-dashboard.search.brave.com/documentation/services/web-search",
                "https://developers.google.com/custom-search/v1/overview"
            ],
            'apiKeyInstructions': [
                "Recommended: Brave Search API",
                "Visit https://api-dashboard.search.brave.com and create an account",
                "Subscribe to the Search plan (includes $5 of free credit each month, about 1,000 requests)",
                "Open 'API Keys', create a key and set it as brave_api_key",
                "Legacy (until 2027-01-01): set method to 'google' with an existing Google Custom Search API key and engine ID"
            ],
            'favIcon': "https://brave.com/static-assets/images/brave-favicon.png",
            'description': "Searches the web (Brave Search API, or Google Custom Search until it is "
            "discontinued on 2027-01-01) for social media profiles matching human names found in the scan.",
        }
    }

    # Default options
    opts = {
        "method": "brave",
        "max_results": 20,
        "tighten": True,
        "brave_api_key": "",
        "google_api_key": "",
        "google_cse_id": "013611106330597893267:tfgl3wxdtbp",
    }

    # Option descriptions
    optdescs = {
        "method": "Search engine to use: 'brave' (default) or 'google' (discontinued 2027-01-01).",
        "max_results": "Maximum search results to inspect per site (20 per billed Brave request, up to 100).",
        "tighten": "Tighten results by expecting to find the keyword of the target domain mentioned in the social media profile page results?",
        "brave_api_key": "Brave Search API key.",
        "google_api_key": "Google API Key (legacy).",
        "google_cse_id": "Google Custom Search Engine ID (legacy).",
    }

    MAX_PROFILE_BYTES = 2 * 1024 * 1024

    keywords = None
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.keywords = None
        self.errorState = False

        # Per-instance copy: never mutate the class-level defaults.
        self.opts = dict(self.opts)
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["HUMAN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SOCIAL_MEDIA", "RAW_RIR_DATA"]

    def provider(self):
        """Build the configured search provider.

        Returns:
            WebSearchProvider: provider, or None if not configured
        """
        method = str(self.opts.get("method", "brave")).lower()
        timeout = self.opts.get("_fetchtimeout", 15)
        useragent = self.opts.get("_useragent", "Floodplain")
        if method == "brave" and self.opts.get("brave_api_key"):
            return BraveSearch(self.sf, self.opts["brave_api_key"], timeout, useragent)
        if method == "google" and self.opts.get("google_api_key") and self.opts.get("google_cse_id"):
            return GoogleCustomSearch(self.sf, self.opts["google_api_key"], self.opts["google_cse_id"], timeout, useragent)
        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        provider = self.provider()
        if provider is None:
            self.error(f"You enabled sfp_socialprofiles but method '{self.opts.get('method')}' has no API key configured "
                       "(use method 'brave' with brave_api_key).")
            self.errorState = True
            return

        if not isinstance(eventData, str) or not eventData.strip() or len(eventData) > 100 or any(c in eventData for c in '"\t\r\n'):
            self.debug("Skipping malformed name.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if self.keywords is None:
            self.keywords = self.sf.domainKeywords(
                self.getTarget().getNames(), self.opts["_internettlds"]
            )
            if len(self.keywords) == 0:
                self.keywords = None

        for site, (template, domain, patterns) in sites.items():
            if self.checkForStop():
                return

            try:
                res = provider.search(template.format(name=eventData), self.opts["max_results"])
            except WebSearchFatal as e:
                self.error(str(e))
                self.errorState = True
                return

            if res is None:
                self.info(f"No data returned from {provider.name}.")
                continue

            self.__dataSource__ = provider.name

            # Submit the results for analysis
            evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(res), self.__name__, event)
            self.notifyListeners(evt)

            instances = list()
            for url in res["urls"]:
                for pattern in patterns:
                    m = re.match(pattern, url, re.IGNORECASE)
                    if not m:
                        continue
                    match = urllib.parse.unquote(m.group(1))
                    if match in instances or not hostMatches(match, domain):
                        continue
                    instances.append(match)
                    self.debug("Match found: " + match)

                    if self.checkForStop():
                        return

                    # Fetch the profile page if we are checking
                    # for a firm relationship.
                    # Keywords might be empty if the target was an IP, subnet or name.
                    if self.opts["tighten"] and self.keywords:
                        self.debug("Tightening results to look for " + str(self.keywords))
                        pres = self.sf.fetchUrl(
                            match,
                            timeout=self.opts["_fetchtimeout"],
                            useragent=self.opts.get("_useragent", "Floodplain"),
                            sizeLimit=self.MAX_PROFILE_BYTES,
                        )

                        if pres["content"] is None:
                            continue

                        found = False
                        for kw in self.keywords:
                            if re.search(
                                r"[^a-zA-Z\-\_]" + re.escape(kw) + r"[^a-zA-Z\-\_]",
                                pres["content"],
                                re.IGNORECASE,
                            ):
                                found = True
                                break

                        if not found:
                            continue

                    self.info("Social Media Profile found at " + site + ": " + match)
                    evt = SpiderFootEvent(
                        "SOCIAL_MEDIA", site + ": <SFURL>" + match + "</SFURL>", self.__name__, event
                    )
                    self.notifyListeners(evt)


# End of sfp_socialprofiles class
