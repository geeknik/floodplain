import pytest
import unittest
from unittest.mock import patch

from modules.sfp_dnszonexfer import sfp_dnszonexfer
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


class FakeRrset:

    def __init__(self, text, recordCount=1):
        self.text = text
        self.recordCount = recordCount

    def __len__(self):
        return self.recordCount

    def to_text(self):
        return self.text


class FakeMessage:

    def __init__(self, answer, wireSize=64):
        self.answer = answer
        self.wireSize = wireSize

    def to_wire(self):
        return b"x" * self.wireSize


@pytest.mark.usefixtures
class TestModuleDnsZonexfer(unittest.TestCase):

    def _module(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnszonexfer()
        module.setup(sf, dict())

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)
        return module

    def _providerEvent(self):
        rootEvent = SpiderFootEvent('ROOT', 'example.com', '', '')
        return SpiderFootEvent('PROVIDER_DNS', '192.0.2.53', 'sfp_dns', rootEvent)

    def test_opts(self):
        module = sfp_dnszonexfer()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnszonexfer()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnszonexfer()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnszonexfer()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_bounded_transfer_should_emit_records_and_name(self):
        module = self._module()
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        response = FakeMessage([
            FakeRrset('www.example.com. 300 IN A 192.0.2.1')
        ])

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])) as mockXfr:
            module.handleEvent(self._providerEvent())

        mockXfr.assert_called_once_with('192.0.2.53', 'example.com', timeout=30, lifetime=30)
        self.assertEqual(['RAW_DNS_RECORDS', 'INTERNET_NAME'], [event.eventType for event in emittedEvents])
        self.assertEqual('www.example.com. 300 IN A 192.0.2.1', emittedEvents[0].data)
        self.assertEqual('www.example.com', emittedEvents[1].data)

    def test_handleEvent_record_limit_should_reject_without_events(self):
        module = self._module()
        module.MAX_RECORDS = 1
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        response = FakeMessage([
            FakeRrset('www.example.com. 300 IN A 192.0.2.1', recordCount=2)
        ])

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])):
            module.handleEvent(self._providerEvent())

        self.assertEqual([], emittedEvents)

    def test_handleEvent_wire_limit_should_reject_without_events(self):
        module = self._module()
        module.MAX_WIRE_BYTES = 64
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        response = FakeMessage([
            FakeRrset('www.example.com. 300 IN A 192.0.2.1')
        ], wireSize=64)

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])):
            module.handleEvent(self._providerEvent())

        self.assertEqual([], emittedEvents)

    def test_handleEvent_event_byte_limit_should_reject_without_events(self):
        module = self._module()
        module.MAX_EVENT_BYTES = 8
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        response = FakeMessage([
            FakeRrset('www.example.com. 300 IN A 192.0.2.1')
        ])

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])):
            module.handleEvent(self._providerEvent())

        self.assertEqual([], emittedEvents)

    def test_handleEvent_decoded_byte_limit_should_count_duplicate_records(self):
        module = self._module()
        module.MAX_DECODED_BYTES = 64
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        record = 'www.example.com. 300 IN A 192.0.2.1'
        response = FakeMessage([
            FakeRrset(record),
            FakeRrset(record)
        ])

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])):
            module.handleEvent(self._providerEvent())

        self.assertEqual([], emittedEvents)

    def test_handleEvent_name_limit_should_reject_without_events(self):
        module = self._module()
        module.MAX_NAME_EVENTS = 1
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        response = FakeMessage([
            FakeRrset('www.example.com. 300 IN A 192.0.2.1'),
            FakeRrset('api.example.com. 300 IN CNAME www.example.com.')
        ])

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])):
            module.handleEvent(self._providerEvent())

        self.assertEqual([], emittedEvents)

    def test_handleEvent_deadline_should_reject_without_events(self):
        module = self._module()
        emittedEvents = list()
        module.notifyListeners = emittedEvents.append
        response = FakeMessage([
            FakeRrset('www.example.com. 300 IN A 192.0.2.1')
        ])

        with patch('modules.sfp_dnszonexfer.dns.query.xfr', return_value=iter([response])):
            with patch('modules.sfp_dnszonexfer.time.monotonic', side_effect=[0, 31]):
                module.handleEvent(self._providerEvent())

        self.assertEqual([], emittedEvents)
