# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_nameapi
# Purpose:      Floodplain module to check if an email is
#               disposable using nameapi.org API.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     2020-10-02
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_nameapi(SpiderFootPlugin):

    meta = {
        'name': "NameAPI",
        'summary': "Check whether an email is disposable",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.nameapi.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.nameapi.org/en/developer/manuals/rest-web-services/53/web-services/disposable-email-address-detector/"
            ],
            'apiKeyInstructions': [
                "Visit https://nameapi.org",
                "Click on 'Get API Key'",
                "Register a free account",
                "The API key will be sent to your email"
            ],
            'favIcon': "https://www.nameapi.org/fileadmin/favicon.ico",
            'logo': "https://www.nameapi.org/fileadmin/templates/nameprofiler/images/name-api-logo.png",
            'description': "The NameAPI DEA-Detector checks email addresses "
            "against a list of known trash domains such as mailinator.com.\n"
            "It classifies those as disposable which operate as a time-limited, "
            "web based way of receiving emails, for example, sign up confirmations.",
        }
    }

    opts = {
        'api_key': ''
    }

    optdescs = {
        'api_key': "API Key for NameAPI"
    }

    results = None
    errorState = False

    API_URL = "https://api.nameapi.org/rest/v5.3/email/disposableemailaddressdetector"
    MAX_RESPONSE_BYTES = 64 * 1024

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
            "EMAILADDR"
        ]

    def producedEvents(self):
        return [
            "EMAILADDR_DISPOSABLE",
            "RAW_RIR_DATA"
        ]

    @staticmethod
    def isApiKeyFault(content) -> bool:
        """Detect NameAPI's "invalid api-key" fault (HTTP 400, error codes 11xx).

        Args:
            content (str): response body

        Returns:
            bool: the fault concerns the API key
        """
        try:
            data = json.loads(content or '')
        except (ValueError, TypeError):
            return False
        if not isinstance(data, dict):
            return False
        code = str(data.get('applicationErrorCode', ''))
        message = data.get('message') if isinstance(data.get('message'), str) else ''
        return code.startswith('11') or 'api-key' in message.lower() or 'apikey' in message.lower()

    def queryEmailAddr(self, qry):
        """Ask NameAPI whether an email address is disposable.

        NameAPI only accepts the key as a query parameter, so the request is
        HTTPS-only and sflib redacts ``apiKey=`` from every log line.

        Args:
            qry (str): validated email address

        Returns:
            str: "YES", "NO" or "UNKNOWN", or None on error
        """
        params = urllib.parse.urlencode({'apiKey': self.opts['api_key'], 'emailAddress': qry})
        res = self.sf.fetchUrl(
            f"{self.API_URL}?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts.get('_useragent', "Floodplain"),
            sizeLimit=self.MAX_RESPONSE_BYTES
        )

        code = str(res.get('code'))
        if code == '400' and self.isApiKeyFault(res.get('content')):
            # Do not log the response: NameAPI echoes the submitted key back.
            self.error("NameAPI rejected the API key.")
            self.errorState = True
            return None
        if code in ('401', '403'):
            self.error("NameAPI rejected the API key.")
            self.errorState = True
            return None
        if code == '429':
            self.error("NameAPI rate limit or quota exceeded.")
            self.errorState = True
            return None
        if code != '200' or not res.get('content'):
            self.info(f"No NameAPI result for {qry} (HTTP {code})")
            return None

        try:
            data = json.loads(res['content'])
        except (ValueError, TypeError) as e:
            self.error(f"Error processing JSON response from NameAPI: {e}")
            return None

        if not isinstance(data, dict):
            return None
        verdict = data.get('disposable')
        if verdict not in ("YES", "NO", "UNKNOWN"):
            return None
        return verdict

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts["api_key"]:
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if not isinstance(eventData, str) or not SpiderFootHelpers.validEmail(eventData):
            self.debug("Skipping invalid email address.")
            return

        email = eventData.lower()
        if email in self.results:
            return
        self.results[email] = True

        verdict = self.queryEmailAddr(email)

        if verdict == "YES":
            evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps({'emailAddress': email, 'disposable': verdict}), self.__name__, event)
            self.notifyListeners(evt)

            evt = SpiderFootEvent("EMAILADDR_DISPOSABLE", eventData, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_nameapi class
