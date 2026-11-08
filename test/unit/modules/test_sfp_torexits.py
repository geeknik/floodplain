import pytest
import unittest

from modules.sfp_torexits import sfp_torexits
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleTorexits(unittest.TestCase):

    def test_opts(self):
        module = sfp_torexits()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_torexits()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_torexits()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_torexits()
        self.assertIsInstance(module.producedEvents(), list)


@pytest.mark.usefixtures
class TestModuleTorexitsNetblocks(unittest.TestCase):

    EXITS = ["192.0.2.10", "198.51.100.7", "2001:db8:1::5", "2001:db9::1"]

    def _run(self, etype, data):
        from unittest.mock import patch
        module = sfp_torexits()
        module.setup(SpiderFoot(self.default_options), {'checkaffiliates': True, 'cacheperiod': 1, 'checknetblocks': True})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent(etype, data, 'test', root)
        emitted = []
        with patch.object(module, 'retrieveExitNodes', return_value=self.EXITS), \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return evt, emitted

    def test_huge_ipv6_netblock_is_not_enumerated(self):
        evt, emitted = self._run('NETBLOCKV6_OWNER', '2001:db8::/32')
        exits = [e for e in emitted if e.eventType == 'TOR_EXIT_NODE']
        self.assertEqual([e.data for e in exits], ['2001:db8:1::5'])
        self.assertEqual(exits[0].sourceEvent.eventType, 'IPV6_ADDRESS')

    def test_ipv4_netblock_hit_is_parented_to_ip_event(self):
        evt, emitted = self._run('NETBLOCK_OWNER', '192.0.2.0/24')
        exits = [e for e in emitted if e.eventType == 'TOR_EXIT_NODE']
        self.assertEqual([e.data for e in exits], ['192.0.2.10'])
        self.assertEqual(exits[0].sourceEvent.eventType, 'IP_ADDRESS')
        self.assertEqual(exits[0].sourceEvent.data, '192.0.2.10')

    def test_malformed_netblock_is_ignored(self):
        _, emitted = self._run('NETBLOCK_OWNER', 'not-a-netblock')
        self.assertEqual(emitted, [])
