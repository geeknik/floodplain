# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_emailrep
# Purpose:      Searches EmailRep.io for email address reputation.
#
# Author:      <bcoles[at]gmail[.]com>
#
# Created:     2019-08-07
# Copyright:   (c) bcoles 2019
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_emailrep(SpiderFootPlugin):

    meta = {
        'name': "EmailRep",
        'summary': "Search EmailRep.io for email address reputation.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://emailrep.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.emailrep.io/"
            ],
            'apiKeyInstructions': [
                "Visit https://emailrep.io/free",
                "Request a free API Key",
                "The API key will be sent to registered email account on approval"
            ],
            'favIcon': "https://emailrep.io/assets/img/favicon.png",
            'logo': "https://emailrep.io/assets/img/logo-light.png",
            'description': "Illuminate the \"reputation\" behind an email address.\n"
            "EmailRep uses hundreds of factors like domain age, traffic rankings, "
            "presence on social media sites, professional networking sites, personal connections, "
            "public records, deliverability, data breaches, dark web credential leaks, "
            "phishing emails, threat actor emails, and more to answer these types of questions.",
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        'api_key': 'EmailRep API key (required; EmailRep no longer answers unauthenticated queries).',
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
        return ['EMAILADDR']

    def producedEvents(self):
        return ['RAW_RIR_DATA', 'EMAILADDR_COMPROMISED', 'MALICIOUS_EMAILADDR']

    MAX_RESPONSE_BYTES = 256 * 1024

    # https://docs.emailrep.io/
    def query(self, qry):
        """Look up an email address on EmailRep.

        Args:
            qry (str): validated, lower-cased email address

        Returns:
            dict: EmailRep response, or None
        """
        headers = {
            'Accept': "application/json",
            'Key': self.opts['api_key'],
        }

        res = self.sf.fetchUrl(
            'https://emailrep.io/' + urllib.parse.quote(qry, safe='@'),
            headers=headers,
            useragent=self.opts.get('_useragent', "Floodplain"),
            timeout=self.opts['_fetchtimeout'],
            sizeLimit=self.MAX_RESPONSE_BYTES
        )

        # Stay well under the free-tier rate limit.
        time.sleep(1)

        code = str(res.get('code'))

        if code == '400':
            self.debug(f"EmailRep rejected the query for {qry} as invalid.")
            return None

        if code in ('401', '403'):
            self.error("EmailRep rejected the API key (HTTP 401/403).")
            self.errorState = True
            return None

        if code == '429':
            self.error("EmailRep rate limit exceeded.")
            self.errorState = True
            return None

        if code == '404':
            return None

        if code != '200' or not res.get('content'):
            self.error(f"Unexpected reply from EmailRep.io: HTTP {code}")
            self.errorState = True
            return None

        try:
            data = json.loads(res['content'])
        except (ValueError, TypeError) as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        return data if isinstance(data, dict) else None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # EmailRep disabled unauthenticated queries (HTTP 429 "please use an
        # API key"), so a key is required.
        if not self.opts['api_key']:
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if not isinstance(eventData, str) or not SpiderFootHelpers.validEmail(eventData):
            self.debug("Skipping invalid email address.")
            return

        email = eventData.lower()
        if email in self.results:
            return

        self.results[email] = True

        res = self.query(email)

        if res is None:
            return

        details = res.get('details')

        if not isinstance(details, dict):
            return

        credentials_leaked = details.get('credentials_leaked') is True
        if credentials_leaked:
            evt = SpiderFootEvent('EMAILADDR_COMPROMISED', eventData + " [Unknown]", self.__name__, event)
            self.notifyListeners(evt)

        malicious_activity = details.get('malicious_activity') is True
        if malicious_activity:
            evt = SpiderFootEvent('MALICIOUS_EMAILADDR', 'EmailRep [' + eventData + ']', self.__name__, event)
            self.notifyListeners(evt)

        if malicious_activity or credentials_leaked:
            evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(res), self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_emailrep class
