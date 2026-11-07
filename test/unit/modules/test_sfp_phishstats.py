import pytest
import unittest

from modules.sfp_phishstats import sfp_phishstats
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulePhishstats(unittest.TestCase):

    def test_opts(self):
        module = sfp_phishstats()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_phishstats()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_phishstats()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_phishstats()
        self.assertIsInstance(module.producedEvents(), list)


@pytest.mark.usefixtures
class TestModulePhishstatsBehaviour(unittest.TestCase):

    RECORD = '[{"id": 1, "ip": "93.184.216.34", "url": "http://bad.example/login", "score": 7}]'

    def _module(self, **opts):
        from spiderfoot import SpiderFootTarget
        module = sfp_phishstats()
        base = {'api_key': '', 'checkaffiliates': True, 'netblocklookup': True, 'maxnetblock': 24,
                'subnetlookup': True, 'maxsubnet': 24}
        base.update(opts)
        module.setup(SpiderFoot(self.default_options), base)
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _run(self, module, etype, data, responses):
        from unittest.mock import patch
        from spiderfoot import SpiderFootEvent
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent(etype, data, 'test', root)
        emitted = []
        side = responses if isinstance(responses, list) else None
        kw = {'side_effect': side} if side is not None else {'return_value': responses}
        with patch.object(module.sf, 'fetchUrl', **kw) as fetch, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append), \
                patch('modules.sfp_phishstats.time.sleep'):
            module.handleEvent(evt)
        return fetch, emitted

    def test_new_endpoint_and_optional_key_header(self):
        fetch, emitted = self._run(self._module(api_key='psk_test'), 'IP_ADDRESS', '93.184.216.34',
                                   {'code': '200', 'content': self.RECORD})
        args, kwargs = fetch.call_args
        self.assertTrue(args[0].startswith("https://api.phishstats.info/api/phishing?"))
        self.assertIn("_where=%28ip%2Ceq%2C93.184.216.34%29", args[0])
        self.assertNotIn("psk_test", args[0])
        self.assertEqual(kwargs['headers']['X-API-Key'], 'psk_test')
        self.assertEqual(sorted(e.eventType for e in emitted), ['BLACKLISTED_IPADDR', 'MALICIOUS_IPADDR', 'RAW_RIR_DATA'])

    def test_no_key_sends_no_key_header(self):
        fetch, _ = self._run(self._module(), 'IP_ADDRESS', '93.184.216.34', {'code': '200', 'content': '[]'})
        self.assertNotIn('X-API-Key', fetch.call_args[1]['headers'])

    def test_filter_injection_is_rejected(self):
        for data in ("1.2.3.4)~or(id,gt,0", "1.2.3.4,x", "not-an-ip"):
            with self.subTest(data=data):
                fetch, emitted = self._run(self._module(), 'IP_ADDRESS', data, {'code': '200', 'content': self.RECORD})
                fetch.assert_not_called()
                self.assertEqual(emitted, [])

    def test_mismatched_ip_is_ignored(self):
        _, emitted = self._run(self._module(), 'IP_ADDRESS', '1.2.3.4', {'code': '200', 'content': self.RECORD})
        self.assertEqual(emitted, [])

    def test_rate_limit_and_auth_errors_stop_module(self):
        for code in ('401', '403', '429'):
            with self.subTest(code=code):
                module = self._module()
                fetch, _ = self._run(module, 'NETBLOCK_OWNER', '93.184.216.0/30', [{'code': code, 'content': ''}] * 4)
                self.assertTrue(module.errorState)
                self.assertEqual(fetch.call_count, 1)

    def test_ipv6_or_oversized_netblocks_are_never_expanded(self):
        for etype, data in (('NETBLOCK_OWNER', '2001:db8::/64'), ('NETBLOCK_MEMBER', '2001:db8::/120'),
                            ('NETBLOCK_OWNER', '10.0.0.0/8'), ('NETBLOCK_OWNER', 'garbage/24')):
            with self.subTest(data=data):
                fetch, emitted = self._run(self._module(), etype, data, {'code': '200', 'content': '[]'})
                fetch.assert_not_called()

    def test_small_netblock_is_expanded(self):
        fetch, _ = self._run(self._module(), 'NETBLOCK_OWNER', '93.184.216.0/30', [{'code': '200', 'content': '[]'}] * 4)
        self.assertEqual(fetch.call_count, 4)

    def test_bad_responses_emit_nothing(self):
        for res in ({'code': '200', 'content': 'nope'}, {'code': '200', 'content': '{"ip": "93.184.216.34"}'},
                    {'code': '200', 'content': '[1, "x"]'}, {'code': '500', 'content': ''}):
            with self.subTest(res=res):
                _, emitted = self._run(self._module(), 'IP_ADDRESS', '93.184.216.34', res)
                self.assertEqual(emitted, [])
