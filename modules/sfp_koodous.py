# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_koodous
# Purpose:     Query Koodous for mobile apps.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-09-19
# Copyright:   (c) bcoles 2019
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
SEGMENT_RE = re.compile(r'^[A-Za-z0-9_]{1,100}$')
CURSOR_RE = re.compile(r'^[A-Za-z0-9+/=_-]{1,512}$')
LABEL_RE = re.compile(r'^[a-z0-9-]{1,63}$')


def validPackage(name: str) -> bool:
    """Linear-time check for an Android package name such as ``com.example.app``.

    Args:
        name (str): candidate package name

    Returns:
        bool: valid
    """
    if not isinstance(name, str) or len(name) > 255:
        return False
    segments = name.split('.')
    return len(segments) >= 2 and all(SEGMENT_RE.match(s) for s in segments)


def validDomain(domain: str) -> bool:
    """Linear-time check that a string is a plausible DNS domain name.

    Args:
        domain (str): candidate domain (lower-case, no trailing dot)

    Returns:
        bool: valid
    """
    if not domain or len(domain) > 253:
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    return all(LABEL_RE.match(label) and not label.startswith('-') and not label.endswith('-') for label in labels)


class sfp_koodous(SpiderFootPlugin):

    meta = {
        'name': "Koodous",
        'summary': "Search Koodous for mobile apps.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'model': "FREE_AUTH_LIMITED",
            "apiKeyInstructions": [
                "Visit https://koodous.com/apks",
                "Register a free account",
                "Visit https://koodous.com/settings/developers and use the authentication token provided",
            ],
            'references': [
                "https://docs.koodous.com/api/apks.html",
                "https://docs.koodous.com/apks.html#apks-search-system"
            ],
            'website': "https://koodous.com/apks/",
            'favIcon': "https://koodous.com/favicon.ico",
            'logo': "https://koodous.com/assets/img/koodous-logo.png",
            "description": "The Collaborative Platform for Android Malware Analysts."
        }
    }

    opts = {
        "api_key": "",
        'max_pages': 10,
    }

    optdescs = {
        "api_key": "Koodous API key.",
        'max_pages': "Maximum number of pages of results to fetch (capped at 50).",
    }

    results = None
    errorState = False

    API_URL = "https://developer.koodous.com/apks/"
    MAX_PAGES_HARD = 50
    MAX_RESPONSE_BYTES = 2 * 1024 * 1024

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
        self.results = self.tempStorage()

        # Per-instance copy: never mutate the class-level defaults.
        self.opts = dict(self.opts)
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'DOMAIN_NAME'
        ]

    def producedEvents(self):
        return [
            'APPSTORE_ENTRY',
            'RAW_RIR_DATA'
        ]

    def queryPackageName(self, qry, cursor=''):
        package_name = qry.encode('raw_unicode_escape').decode("ascii", errors='replace')

        params = urllib.parse.urlencode({
            'cursor': cursor,
            'search': f"package:{package_name}.*"
        })

        res = self.sf.fetchUrl(
            f"{self.API_URL}?{params}",
            headers={"Authorization": f"Token {self.opts['api_key']}"},
            useragent=self.opts.get('_useragent', "Floodplain"),
            timeout=self.opts['_fetchtimeout'],
            sizeLimit=self.MAX_RESPONSE_BYTES
        )

        # 100 requests per minute
        time.sleep(1)

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        """Parse a Koodous API response.

        Args:
            res (dict): fetchUrl result

        Returns:
            dict: decoded page; an empty page for "no results"; None on error
                (errorState is set for errors that make further queries pointless)
        """
        if not res:
            self.error("No response from Koodous.")
            return None

        code = str(res.get('code'))

        if code == '404':
            self.debug("No results from Koodous.")
            return {'results': []}

        if code in ('401', '403'):
            self.error("Koodous rejected the API key (missing, invalid or expired token).")
            self.errorState = True
            return None

        if code == '429':
            self.error("You are being rate-limited by Koodous.")
            self.errorState = True
            return None

        if code in ('500', '502', '503'):
            self.error("Koodous service is unavailable")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if code != '200':
            self.error(f"Unexpected reply from Koodous: HTTP {code}")
            self.errorState = True
            return None

        if not res.get('content'):
            return {'results': []}

        try:
            data = json.loads(res['content'])
        except (ValueError, TypeError) as e:
            self.debug(f"Error processing JSON response from Koodous: {e}")
            return None

        if not isinstance(data, dict) or not isinstance(data.get('results', []), list):
            self.debug("Unexpected JSON structure from Koodous.")
            return None

        return data

    def handleEvent(self, event):
        if self.errorState:
            return

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        eventData = event.data

        if not isinstance(eventData, str):
            return

        eventData = eventData.lower().rstrip('.')

        if not validDomain(eventData):
            self.debug("Skipping invalid domain name.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Reverse domain name to create potential package name
        domain_reversed = '.'.join(list(reversed(eventData.split('.'))))

        try:
            max_pages = min(max(int(self.opts['max_pages']), 1), self.MAX_PAGES_HARD)
        except (TypeError, ValueError):
            max_pages = 1
        page = 1
        cursor = ''
        while page <= max_pages:
            found = False

            if self.checkForStop():
                return

            data = self.queryPackageName(domain_reversed, cursor)

            page += 1

            if data is None:
                return

            results = data.get('results') or []

            for result in results:
                if not isinstance(result, dict):
                    continue

                package_name = result.get('package_name')

                if not validPackage(package_name):
                    continue

                app = result.get('app')

                # results can have a null app name, but it is probably a duplicate
                if not isinstance(app, str) or not app.strip():
                    continue

                # Untrusted text is embedded in <SFURL> markup: strip markup characters.
                app = re.sub(r'[<>\r\n]', '', app).strip()[:200]

                # TODO: compare company name with target
                # company = result.get('company')

                version = result.get('version')
                version = re.sub(r'[<>\r\n]', '', version).strip()[:50] if isinstance(version, str) else None

                if version:
                    app_full_name = f"{app} {version} ({package_name})"
                else:
                    app_full_name = f"{app} ({package_name})"

                if (
                    domain_reversed != package_name.lower()
                    and not package_name.lower().startswith(f"{domain_reversed}.")
                    and not package_name.lower().endswith(f".{domain_reversed}")
                    and f".{domain_reversed}." not in package_name.lower()
                ):
                    self.debug(f"App {app_full_name} does not match {domain_reversed}, skipping")
                    continue

                sha256 = result.get('sha256')

                if not isinstance(sha256, str) or not SHA256_RE.match(sha256.lower()):
                    continue
                sha256 = sha256.lower()

                app_data = f"{app_full_name}\n<SFURL>https://koodous.com/apks/{sha256}</SFURL>"

                evt = SpiderFootEvent('APPSTORE_ENTRY', app_data, self.__name__, event)
                self.notifyListeners(evt)
                found = True

            if found:
                evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(data), self.__name__, event)
                self.notifyListeners(evt)

            next_url = data.get('next')
            if not isinstance(next_url, str) or not next_url:
                break

            next_cursor = urllib.parse.parse_qs(urllib.parse.urlparse(next_url).query).get('cursor')
            if not next_cursor or not CURSOR_RE.match(next_cursor[0]):
                break

            cursor = next_cursor[0]

# End of sfp_koodous class
