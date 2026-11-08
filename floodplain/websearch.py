"""Pluggable web-search backends for modules that need a search engine.

Modules ask for results through one small interface instead of calling a
specific search API, so a provider can be added or retired in one place.

Providers:
    * ``BraveSearch`` — Brave Search API (default).
    * ``GoogleCustomSearch`` — Google Custom Search JSON API. Closed to new
      customers and discontinued by Google on 2027-01-01; kept only so
      existing keys keep working until then. Remove after the cutoff.

Threat model:
    * Queries contain scan targets (domains, names, emails) and are sent to
      the selected third party. That is inherent to the feature; nothing
      else is sent.
    * API keys travel in request headers where the provider allows it
      (Brave). Google only accepts a query-string key, which sflib redacts
      from every log line.
    * Responses are untrusted: size-bounded, JSON-validated, and only
      well-formed http(s) URLs are returned, de-duplicated and capped.
"""

import json
import urllib.parse
from typing import Optional

MAX_URL_LENGTH = 2048
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class WebSearchFatal(Exception):
    """The provider rejected us (bad key, quota, rate limit): stop querying."""


def cleanUrls(candidates, limit: int) -> list:
    """Keep only well-formed http(s) URLs, de-duplicated, in order.

    Args:
        candidates (list): untrusted URL values
        limit (int): maximum number of URLs to return

    Returns:
        list: clean URLs
    """
    seen = set()
    out = []
    for url in candidates:
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
            continue
        if any(c in url for c in ('\r', '\n', '\t', ' ', '<', '>', '"')):
            continue
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= limit:
            break
    return out


def hostMatches(url: str, domain: str) -> bool:
    """True if the URL's host is ``domain`` or a subdomain of it.

    Unlike ``host.endswith(domain)`` this does not match look-alikes such as
    ``evilexample.com`` for ``example.com``.

    Args:
        url (str): URL
        domain (str): domain name

    Returns:
        bool: host is the domain or one of its subdomains
    """
    try:
        host = (urllib.parse.urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return False
    domain = domain.lower().rstrip('.')
    return bool(domain) and (host == domain or host.endswith('.' + domain))


class WebSearchProvider:
    """Base class. Subclasses implement ``_fetchPage``."""

    name = "base"
    MAX_PAGES = 1
    PAGE_SIZE = 10

    def __init__(self, sf, api_key: str, timeout: int = 15, useragent: str = "Floodplain"):
        self.sf = sf
        self.api_key = api_key
        self.timeout = timeout
        self.useragent = useragent

    def search(self, query: str, max_results: int = 20) -> Optional[dict]:
        """Run a search.

        Args:
            query (str): search query, including operators such as ``site:``
            max_results (int): maximum URLs to return

        A ``WebSearchFatal`` raised by the provider (key rejected, quota
        exhausted, rate limited) propagates to the caller, which should stop
        querying.

        Returns:
            dict: {"provider": name, "query": query, "urls": [...]}, or None if
            the provider returned nothing usable
        """
        if not isinstance(query, str) or not query.strip() or len(query) > 400:
            return None
        try:
            max_results = max(1, min(int(max_results), self.MAX_PAGES * self.PAGE_SIZE))
        except (TypeError, ValueError):
            max_results = self.PAGE_SIZE

        urls = []
        page = 0
        while len(urls) < max_results and page < self.MAX_PAGES:
            page_urls, more = self._fetchPage(query, page)
            if page_urls is None:
                break
            urls.extend(page_urls)
            if not more:
                break
            page += 1

        urls = cleanUrls(urls, max_results)
        if not urls:
            return None
        return {"provider": self.name, "query": query, "urls": urls}

    def _fetchPage(self, query: str, page: int):
        raise NotImplementedError

    def _checkStatus(self, res: dict) -> Optional[str]:
        """Map an HTTP result to fatal / skip / ok.

        Args:
            res (dict): fetchUrl result

        Returns:
            str: response body for HTTP 200, otherwise None

        Raises:
            WebSearchFatal: 401/402/403/429
        """
        code = str((res or {}).get('code'))
        if code in ('401', '402', '403'):
            raise WebSearchFatal(f"{self.name} rejected the API key or the quota is exhausted (HTTP {code}).")
        if code == '429':
            raise WebSearchFatal(f"{self.name} rate limit reached (HTTP 429).")
        if code != '200' or not res.get('content'):
            return None
        return res['content']


class BraveSearch(WebSearchProvider):
    """Brave Search API web search.

    https://api-dashboard.search.brave.com/documentation/services/web-search
    """

    name = "Brave"
    API_URL = "https://api.search.brave.com/res/v1/web/search"
    PAGE_SIZE = 20   # API maximum
    MAX_PAGES = 5    # API allows offset 0-9; each page is one billed request

    def _checkStatus(self, res: dict) -> Optional[str]:
        """Brave reports authentication failures as HTTP 422, not 401.

        Args:
            res (dict): fetchUrl result

        Returns:
            str: response body for HTTP 200, otherwise None

        Raises:
            WebSearchFatal: invalid/missing key, quota or rate limit
        """
        if str((res or {}).get('code')) == '422':
            try:
                err = json.loads(res.get('content') or '').get('error', {})
            except (ValueError, TypeError, AttributeError):
                err = {}
            if not isinstance(err, dict):
                err = {}
            meta = err.get('meta') if isinstance(err.get('meta'), dict) else {}
            if str(err.get('code', '')).startswith('SUBSCRIPTION_TOKEN') or meta.get('component') == 'authentication':
                raise WebSearchFatal("Brave rejected the API key (SUBSCRIPTION_TOKEN_INVALID).")
            return None
        return super()._checkStatus(res)

    def _fetchPage(self, query: str, page: int):
        params = urllib.parse.urlencode({
            'q': query,
            'count': self.PAGE_SIZE,
            'offset': page,
            'safesearch': 'off',
        })
        res = self.sf.fetchUrl(
            f"{self.API_URL}?{params}",
            headers={
                'Accept': 'application/json',
                'X-Subscription-Token': self.api_key,
            },
            timeout=self.timeout,
            useragent=self.useragent,
            sizeLimit=MAX_RESPONSE_BYTES,
        )
        content = self._checkStatus(res)
        if content is None:
            return None, False
        try:
            data = json.loads(content)
        except (ValueError, TypeError):
            return None, False
        if not isinstance(data, dict):
            return None, False
        web = data.get('web')
        results = web.get('results') if isinstance(web, dict) else None
        if not isinstance(results, list):
            return [], False
        urls = [r.get('url') for r in results if isinstance(r, dict)]
        query_info = data.get('query')
        more = isinstance(query_info, dict) and query_info.get('more_results_available') is True
        return urls, more


class GoogleCustomSearch(WebSearchProvider):
    """Google Custom Search JSON API (discontinued 2027-01-01).

    https://developers.google.com/custom-search/v1/overview
    """

    name = "Google"
    API_URL = "https://www.googleapis.com/customsearch/v1"
    PAGE_SIZE = 10
    MAX_PAGES = 1

    def __init__(self, sf, api_key: str, cse_id: str, timeout: int = 15, useragent: str = "Floodplain"):
        super().__init__(sf, api_key, timeout, useragent)
        self.cse_id = cse_id

    def _fetchPage(self, query: str, page: int):
        params = urllib.parse.urlencode({'q': query, 'cx': self.cse_id, 'key': self.api_key})
        res = self.sf.fetchUrl(
            f"{self.API_URL}?{params}",
            timeout=self.timeout,
            useragent=self.useragent,
            sizeLimit=MAX_RESPONSE_BYTES,
        )
        content = self._checkStatus(res)
        if content is None:
            return None, False
        try:
            data = json.loads(content)
        except (ValueError, TypeError):
            return None, False
        items = data.get('items') if isinstance(data, dict) else None
        if not isinstance(items, list):
            return [], False
        return [i.get('link') for i in items if isinstance(i, dict)], False


def providerFromOpts(sf, opts: dict, google_key_opt: str = 'google_api_key',
                     google_cse_opt: str = 'google_cse_id') -> Optional[WebSearchProvider]:
    """Pick a provider from module options.

    Brave is used when ``brave_api_key`` is set; otherwise Google Custom
    Search when its key (and engine ID) are set; otherwise None. Each
    provider has its own key option so a key is never sent to the wrong
    service.

    Args:
        sf: SpiderFoot instance (provides fetchUrl)
        opts (dict): module options
        google_key_opt (str): option name holding the Google API key
        google_cse_opt (str): option name holding the Google engine ID

    Returns:
        WebSearchProvider: provider, or None if no key is configured
    """
    timeout = opts.get('_fetchtimeout', 15)
    useragent = opts.get('_useragent', "Floodplain")
    if opts.get('brave_api_key'):
        return BraveSearch(sf, opts['brave_api_key'], timeout, useragent)
    if opts.get(google_key_opt) and opts.get(google_cse_opt):
        return GoogleCustomSearch(sf, opts[google_key_opt], opts[google_cse_opt], timeout, useragent)
    return None
