# test_websearch.py
import json
import unittest
import urllib.parse
from unittest.mock import MagicMock

from spiderfoot.websearch import (BraveSearch, GoogleCustomSearch, WebSearchFatal,
                                  cleanUrls, hostMatches, providerFromOpts)

KEY = "brave-secret-key"


def brave_page(urls, more=False):
    return {'code': '200', 'content': json.dumps({
        'type': 'search',
        'query': {'original': 'x', 'more_results_available': more},
        'web': {'type': 'search', 'results': [{'url': u, 'title': 't'} for u in urls]},
    })}


class TestHelpers(unittest.TestCase):

    def test_cleanUrls_keeps_only_http_urls_deduplicated(self):
        dirty = ["https://a.example/x", "https://a.example/x", "ftp://a.example", "javascript:alert(1)",
                 "https://a.example/ y", "https://a.example/\r\nX: y", 5, None, "http://" + "a" * 3000,
                 "https:///nohost", "http://b.example/<script>", "http://c.example/ok"]
        self.assertEqual(cleanUrls(dirty, 10), ["https://a.example/x", "http://c.example/ok"])

    def test_cleanUrls_limit(self):
        self.assertEqual(len(cleanUrls([f"https://e.example/{i}" for i in range(50)], 7)), 7)

    def test_hostMatches_rejects_lookalikes(self):
        self.assertTrue(hostMatches("https://example.com/a", "example.com"))
        self.assertTrue(hostMatches("https://www.Example.com./a", "example.com"))
        self.assertFalse(hostMatches("https://evilexample.com/a", "example.com"))
        self.assertFalse(hostMatches("https://example.com.evil.net/a", "example.com"))
        self.assertFalse(hostMatches("https://evil.net/?u=example.com", "example.com"))
        self.assertFalse(hostMatches("not a url", "example.com"))
        self.assertFalse(hostMatches("https://example.com/", ""))


class TestBraveSearch(unittest.TestCase):

    def _provider(self, responses):
        sf = MagicMock()
        sf.fetchUrl.side_effect = responses if isinstance(responses, list) else [responses]
        return BraveSearch(sf, KEY, 10, "Floodplain"), sf

    def test_key_in_header_and_query_url_encoded(self):
        provider, sf = self._provider(brave_page(["https://www.example.com/a"]))
        res = provider.search('site:example.com "a&b=c #x"', 20)
        args, kwargs = sf.fetchUrl.call_args
        self.assertEqual(kwargs['headers']['X-Subscription-Token'], KEY)
        self.assertNotIn(KEY, args[0])
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(args[0]).query)
        self.assertEqual(qs['q'], ['site:example.com "a&b=c #x"'])
        self.assertEqual(qs['count'], ['20'])
        self.assertEqual(qs['offset'], ['0'])
        self.assertTrue(args[0].startswith("https://api.search.brave.com/res/v1/web/search?"))
        self.assertEqual(res, {'provider': 'Brave', 'query': 'site:example.com "a&b=c #x"', 'urls': ["https://www.example.com/a"]})

    def test_paginates_only_while_more_results_available(self):
        p1 = brave_page([f"https://e.example/{i}" for i in range(20)], more=True)
        p2 = brave_page([f"https://e.example/{i}" for i in range(20, 25)], more=False)
        provider, sf = self._provider([p1, p2, brave_page(["https://never.example/"])])
        res = provider.search("q", 100)
        self.assertEqual(sf.fetchUrl.call_count, 2)
        self.assertEqual(len(res['urls']), 25)
        self.assertIn("offset=1", sf.fetchUrl.call_args_list[1][0][0])

    def test_stops_when_enough_results(self):
        provider, sf = self._provider([brave_page([f"https://e.example/{i}" for i in range(20)], more=True)] * 5)
        res = provider.search("q", 20)
        self.assertEqual(sf.fetchUrl.call_count, 1)
        self.assertEqual(len(res['urls']), 20)

    def test_page_count_is_hard_capped(self):
        provider, sf = self._provider([brave_page([f"https://e.example/{p}/{i}" for i in range(20)], more=True) for p in range(20)])
        res = provider.search("q", 10 ** 9)
        self.assertEqual(sf.fetchUrl.call_count, BraveSearch.MAX_PAGES)
        self.assertEqual(len(res['urls']), BraveSearch.MAX_PAGES * BraveSearch.PAGE_SIZE)

    def test_fatal_codes_raise(self):
        for code in ('401', '402', '403', '429'):
            with self.subTest(code=code):
                provider, _ = self._provider({'code': code, 'content': '{}'})
                with self.assertRaises(WebSearchFatal):
                    provider.search("q")

    def test_invalid_token_422_is_fatal(self):
        body = json.dumps({"error": {"code": "SUBSCRIPTION_TOKEN_INVALID", "detail": "The provided subscription token is invalid.",
                                     "meta": {"component": "authentication"}, "status": 422}, "type": "ErrorResponse"})
        provider, _ = self._provider({'code': '422', 'content': body})
        with self.assertRaises(WebSearchFatal):
            provider.search("q")

    def test_validation_422_is_not_fatal(self):
        body = json.dumps({"error": {"code": "VALIDATION", "detail": "Unable to validate request parameter(s)",
                                     "meta": {"errors": []}, "status": 422}})
        for content in (body, 'not json', '[]', '{"error": "x"}'):
            with self.subTest(content=content):
                provider, _ = self._provider({'code': '422', 'content': content})
                self.assertIsNone(provider.search("q"))

    def test_non_fatal_errors_and_bad_json_return_none(self):
        for res in ({'code': '422', 'content': '{}'}, {'code': '500', 'content': ''}, {'code': None, 'content': None},
                    {'code': '200', 'content': 'nope'}, {'code': '200', 'content': '[]'},
                    {'code': '200', 'content': '{"web": {"results": "x"}}'}, {'code': '200', 'content': '{}'}):
            with self.subTest(res=res):
                provider, _ = self._provider(res)
                self.assertIsNone(provider.search("q"))

    def test_invalid_queries_are_not_sent(self):
        for q in ("", "   ", None, "x" * 401):
            with self.subTest(q=q):
                provider, sf = self._provider(brave_page([]))
                self.assertIsNone(provider.search(q))
                sf.fetchUrl.assert_not_called()


class TestGoogleCustomSearch(unittest.TestCase):

    def test_query_is_encoded_not_injectable(self):
        sf = MagicMock()
        sf.fetchUrl.return_value = {'code': '200', 'content': json.dumps({'items': [{'link': 'https://www.example.com/'}]})}
        res = GoogleCustomSearch(sf, "gkey", "cse", 10).search("site:example.com&key=attacker&cx=evil", 10)
        url = sf.fetchUrl.call_args[0][0]
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(qs['key'], ['gkey'])
        self.assertEqual(qs['cx'], ['cse'])
        self.assertEqual(qs['q'], ['site:example.com&key=attacker&cx=evil'])
        self.assertEqual(res['urls'], ['https://www.example.com/'])
        self.assertEqual(res['provider'], 'Google')


class TestProviderFromOpts(unittest.TestCase):

    def test_selection(self):
        sf = MagicMock()
        self.assertIsInstance(providerFromOpts(sf, {'brave_api_key': 'b', 'google_api_key': 'g', 'google_cse_id': 'c'}), BraveSearch)
        self.assertIsInstance(providerFromOpts(sf, {'brave_api_key': '', 'google_api_key': 'g', 'google_cse_id': 'c'}), GoogleCustomSearch)
        self.assertIsNone(providerFromOpts(sf, {'brave_api_key': '', 'google_api_key': 'g', 'google_cse_id': ''}))
        self.assertIsNone(providerFromOpts(sf, {}))
        g = providerFromOpts(sf, {'api_key': 'g', 'cse_id': 'c'}, google_key_opt='api_key', google_cse_opt='cse_id')
        self.assertIsInstance(g, GoogleCustomSearch)

    def test_google_key_is_never_sent_to_brave(self):
        sf = MagicMock()
        sf.fetchUrl.return_value = brave_page(["https://e.example/"])
        providerFromOpts(sf, {'brave_api_key': 'b', 'google_api_key': 'GOOGLEKEY', 'google_cse_id': 'c'}).search("q")
        args, kwargs = sf.fetchUrl.call_args
        self.assertNotIn('GOOGLEKEY', args[0] + json.dumps(kwargs.get('headers', {})))
