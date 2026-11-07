# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_hudsonrock
# Purpose:     Check domains and e-mail addresses against Hudson Rock's Cavalier
#              infostealer intelligence (credentials harvested by infostealer
#              malware such as Lumma, RedLine, Raccoon, Vidar).
#
# Author:      Floodplain contributors
#
# Created:     2026-11-07
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
from urllib.parse import urlparse

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_hudsonrock(SpiderFootPlugin):

    meta = {
        'name': "Hudson Rock",
        'summary': "Check domains and e-mail addresses against Hudson Rock's infostealer "
        "intelligence for credentials harvested by infostealer malware.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.hudsonrock.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.hudsonrock.com/docs/domain-search",
                "https://docs.hudsonrock.com/docs/email-search"
            ],
            'apiKeyInstructions': [
                "Visit https://www.hudsonrock.com/free-api-key",
                "Request a free Cavalier API key",
                "Paste the key into this module's 'api_key' option"
            ],
            'description': "Hudson Rock's Cavalier database indexes tens of millions of computers "
            "compromised by infostealer malware. Lookups reveal whether an organisation's employees, "
            "users or third parties, or a specific e-mail address, have had credentials harvested.",
        }
    }

    opts = {
        'api_key': "",
        'max_pages': 1,
    }

    optdescs = {
        'api_key': "Hudson Rock Cavalier API key.",
        'max_pages': "Maximum number of result pages (20 infections each) to fetch per lookup.",
    }

    BASE_URL = "https://api.hudsonrock.com/json/v3"
    MAX_RESPONSE_BYTES = 10 * 1024 * 1024
    MAX_PAGES_HARD = 10
    MAX_EMAIL_EVENTS = 25
    MAX_HOSTNAMES = 500

    DATE_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})')
    FAMILY_RE = re.compile(r'^[A-Za-z0-9 ._-]{1,64}$')
    CURSOR_RE = re.compile(r'^[A-Za-z0-9+/=_-]{1,512}$')
    LABEL_RE = re.compile(r'^[a-z0-9-]{1,63}$')
    CRED_TYPES = ("employee", "user", "third_party")

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "EMAILADDR"]

    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED", "INTERNET_NAME", "RAW_RIR_DATA"]

    def validHostname(self, hostname: str) -> bool:
        """Validate a DNS hostname label-by-label in linear time.

        Args:
            hostname (str): lower-cased hostname without a trailing dot

        Returns:
            bool: hostname is syntactically valid
        """
        if not hostname or len(hostname) > 253:
            return False

        labels = hostname.split('.')
        if len(labels) < 2:
            return False

        return all(
            self.LABEL_RE.match(label) and not label.startswith('-') and not label.endswith('-')
            for label in labels
        )

    def query(self, endpoint: str, body: dict):
        """POST a search to the Cavalier API, following pagination up to max_pages.

        Args:
            endpoint (str): API path, e.g. "/search-by-domain"
            body (dict): JSON request body

        Returns:
            list: infection records (untrusted, not yet validated), or None on error
        """
        try:
            pages = int(self.opts['max_pages'])
        except (TypeError, ValueError):
            pages = 1
        pages = max(1, min(pages, self.MAX_PAGES_HARD))

        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'api-key': self.opts['api_key'],
        }

        infections = []
        cursor = None

        for _ in range(pages):
            if self.checkForStop():
                break

            payload = dict(body)
            if cursor:
                payload['cursor'] = cursor

            res = self.sf.fetchUrl(
                f"{self.BASE_URL}{endpoint}",
                timeout=self.opts.get('_fetchtimeout', 15),
                useragent=self.opts.get('_useragent', "Floodplain"),
                headers=headers,
                postData=json.dumps(payload),
            )

            if not res:
                return None

            code = str(res.get('code'))

            if code in ("401", "403"):
                self.error("Hudson Rock API key rejected or lacks permission; disabling module.")
                self.errorState = True
                return None

            if code == "429":
                self.error("Hudson Rock API rate limit exceeded; disabling module for this scan.")
                self.errorState = True
                return None

            if code == "404":
                break

            if code != "200":
                self.error(f"Unexpected HTTP response code {code} from Hudson Rock.")
                return None

            content = res.get('content')
            if not content:
                break

            if len(content) > self.MAX_RESPONSE_BYTES:
                self.error("Hudson Rock response exceeded size bound; ignoring.")
                return None

            try:
                data = json.loads(content)
            except (ValueError, TypeError) as e:
                self.debug(f"Error processing JSON response from Hudson Rock: {e}")
                return None

            if not isinstance(data, dict) or not isinstance(data.get('data'), list):
                self.debug("Unexpected Hudson Rock response structure.")
                return None

            infections.extend(i for i in data['data'] if isinstance(i, dict))

            cursor = data.get('nextCursor')
            if not isinstance(cursor, str) or not self.CURSOR_RE.match(cursor):
                break

        return infections

    def summarise(self, infection: dict):
        """Reduce an untrusted infection record to non-sensitive fields only.

        Passwords, victim IP addresses, computer names, malware paths and
        cookies are deliberately never read into the event pipeline.

        Args:
            infection (dict): raw infection record

        Returns:
            tuple: (family, date) strings
        """
        family = infection.get('stealer_family')
        if not isinstance(family, str) or not self.FAMILY_RE.match(family.strip()):
            family = "unknown family"
        else:
            family = family.strip()

        date = "unknown date"
        raw_date = infection.get('date_compromised')
        if isinstance(raw_date, str):
            m = self.DATE_RE.match(raw_date)
            if m:
                date = m.group(1)

        return family, date

    def credentials(self, infection: dict):
        """Yield well-formed credential dicts from an infection record (bounded).

        Args:
            infection (dict): raw infection record

        Yields:
            dict: a credential record (untrusted; only url/username/type are read)
        """
        creds = infection.get('credentials')
        if not isinstance(creds, list):
            return
        for c in creds[:1000]:
            if isinstance(c, dict):
                yield c

    def handleEmail(self, email: str, event) -> None:
        infections = self.query("/search-by-login/emails", {
            'logins': [email],
            'filter_credentials': True,
        })

        if not infections:
            return

        seen = set()
        for infection in infections:
            if len(seen) >= self.MAX_EMAIL_EVENTS:
                break
            family, date = self.summarise(infection)
            if (family, date) in seen:
                continue
            seen.add((family, date))
            evt = SpiderFootEvent(
                "EMAILADDR_COMPROMISED",
                f"{email} [Hudson Rock infostealer: {family}, {date}]",
                self.__name__, event)
            self.notifyListeners(evt)

    def handleDomain(self, domain: str, event) -> None:
        infections = self.query("/search-by-domain", {
            'domains': [domain],
            'filter_credentials': True,
        })

        if not infections:
            return

        type_counts = {t: 0 for t in self.CRED_TYPES}
        families = set()
        dates = set()
        hostnames = set()
        emails = {}

        for infection in infections:
            family, date = self.summarise(infection)
            families.add(family)
            if date != "unknown date":
                dates.add(date)

            for cred in self.credentials(infection):
                ctype = cred.get('type')
                if ctype in type_counts:
                    type_counts[ctype] += 1

                url = cred.get('url')
                if isinstance(url, str) and len(url) <= 2048 and len(hostnames) < self.MAX_HOSTNAMES:
                    try:
                        host = (urlparse(url).hostname or "").lower().rstrip('.')
                    except ValueError:
                        host = ""
                    if self.validHostname(host) and self.getTarget().matches(host, includeParents=True):
                        hostnames.add(host)

                # Only uncensored, syntactically valid addresses on the target
                # domain. Free-tier responses censor usernames, so this is
                # usually empty; passwords are never read.
                username = cred.get('username')
                if (isinstance(username, str) and len(username) <= 254
                        and '•' not in username and '*' not in username
                        and SpiderFootHelpers.validEmail(username)):
                    username = username.lower()
                    if self.getTarget().matches(username.split('@', 1)[1], includeParents=True):
                        emails.setdefault(username, (family, date))

        summary = {
            'source': "Hudson Rock",
            'domain': domain,
            'infections': len(infections),
            'credential_types': type_counts,
            'stealer_families': sorted(families),
            'latest_compromise': max(dates) if dates else None,
        }
        evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(summary, sort_keys=True), self.__name__, event)
        self.notifyListeners(evt)

        for host in sorted(hostnames):
            evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
            self.notifyListeners(evt)

        for email in sorted(emails)[:self.MAX_EMAIL_EVENTS]:
            family, date = emails[email]
            evt = SpiderFootEvent(
                "EMAILADDR_COMPROMISED",
                f"{email} [Hudson Rock infostealer: {family}, {date}]",
                self.__name__, event)
            self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts['api_key']:
            self.error("You enabled sfp_hudsonrock but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            email = eventData.strip().lower()
            if len(email) > 254 or not SpiderFootHelpers.validEmail(email):
                self.debug(f"Skipping invalid e-mail address: {eventData}")
                return
            self.handleEmail(email, event)
            return

        if eventName == "DOMAIN_NAME":
            domain = eventData.strip().lower().rstrip('.')
            if not self.validHostname(domain):
                self.debug(f"Skipping invalid domain: {eventData}")
                return
            self.handleDomain(domain, event)

# End of sfp_hudsonrock class
