# test_netblock_limit.py
"""Netblock expansion must stay bounded no matter what an event claims to be."""
import copy
import os
import unittest
from unittest.mock import patch

import netaddr
import pytest

from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootTarget

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")


class TestNetblockWithinLimit(unittest.TestCase):

    def test_ipv4(self):
        self.assertTrue(SpiderFootHelpers.netblockWithinLimit("192.0.2.0/24", 24))
        self.assertTrue(SpiderFootHelpers.netblockWithinLimit("192.0.2.0/30", 24))
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("192.0.0.0/16", 24))
        self.assertTrue(SpiderFootHelpers.netblockWithinLimit("10.0.0.0/16", 16))

    def test_ipv6_with_v6_limit(self):
        self.assertTrue(SpiderFootHelpers.netblockWithinLimit("2001:db8::/120", 120))
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("2001:db8::/64", 120))

    def test_ipv6_against_ipv4_scale_limit_keeps_same_host_count(self):
        self.assertTrue(SpiderFootHelpers.netblockWithinLimit("2001:db8::/120", 24))
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("2001:db8::/64", 24))
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("2001:db8::/119", 24))

    def test_hard_cap_overrides_user_options(self):
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("10.0.0.0/8", 0))
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("10.0.0.0/15", 8))
        self.assertFalse(SpiderFootHelpers.netblockWithinLimit("2001:db8::/96", 0))

    def test_malformed_and_out_of_range_fail_closed(self):
        for netblock, limit in (("garbage", 24), ("", 24), (None, 24), ("192.0.2.0/24", "x"),
                                ("192.0.2.0/24", None), ("192.0.2.0/24", 33), ("192.0.2.0/24", -1),
                                ("2001:db8::/120", 129), ("192.0.2.0/24", 120)):
            with self.subTest(netblock=netblock, limit=limit):
                self.assertFalse(SpiderFootHelpers.netblockWithinLimit(netblock, limit))

    def test_accepts_ipnetwork_objects(self):
        self.assertTrue(SpiderFootHelpers.netblockWithinLimit(netaddr.IPNetwork("192.0.2.0/28"), 24))


@pytest.mark.usefixtures
class TestModulesNeverExpandHugeNetblocks(unittest.TestCase):
    """Feed every netblock-consuming module an IPv6 /64 mislabelled as IPv4."""

    def test_no_module_expands_an_ipv6_slash64(self):
        real_iter = netaddr.IPNetwork.__iter__

        def guarded_iter(net):
            if net.size > SpiderFootHelpers.NETBLOCK_HARD_MAX_HOSTS:
                raise AssertionError(f"expanded oversized netblock {net}")
            return real_iter(net)

        mods = SpiderFootHelpers.loadModulesAsDict(os.path.join(ROOT, "modules"), ['sfp_template.py'])
        checked = []
        for name in sorted(mods):
            module_cls = getattr(__import__('modules.' + name, fromlist=[name]), name)
            watched = module_cls().watchedEvents()
            event_types = [e for e in ("NETBLOCK_OWNER", "NETBLOCK_MEMBER") if e in watched]
            if not event_types:
                continue
            saved_opts = copy.deepcopy(module_cls.opts)
            for etype in event_types:
                with self.subTest(module=name, event=etype):
                    # Many legacy modules write setup() options into the
                    # class-level dict; restore it so dummy keys don't leak
                    # into other tests.
                    module_cls.opts = copy.deepcopy(saved_opts)
                    module = module_cls()
                    opts = {k: ("dummy-key" if "api_key" in k or k.endswith("key") else v)
                            for k, v in module.opts.items()}
                    for k in opts:
                        if k in ("netblocklookup", "subnetlookup", "netblockscan", "checknetblocks"):
                            opts[k] = True
                    sf = SpiderFoot(self.default_options)
                    module.setup(sf, opts)
                    module.setTarget(SpiderFootTarget("example.com", "INTERNET_NAME"))
                    root = SpiderFootEvent("ROOT", "example.com", "", "")
                    evt = SpiderFootEvent(etype, "2001:db8::/64", "test", root)
                    with patch.object(netaddr.IPNetwork, "__iter__", guarded_iter), \
                            patch.object(sf, "fetchUrl", return_value={'code': '404', 'content': None, 'headers': {}}), \
                            patch.object(sf, "resolveHost", return_value=[]), \
                            patch.object(sf, "resolveHost6", return_value=[]), \
                            patch.object(sf, "resolveIP", return_value=[]), \
                            patch.object(module, "notifyListeners"):
                        try:
                            module.handleEvent(evt)
                        except AssertionError:
                            raise
                        except Exception:  # noqa: B902 - other failures are out of scope here
                            pass
                    checked.append(name)
            module_cls.opts = saved_opts
        self.assertGreaterEqual(len(set(checked)), 20, f"only checked {sorted(set(checked))}")
