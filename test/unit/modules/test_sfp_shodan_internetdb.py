import json
import pytest
import unittest
from unittest.mock import patch

from modules.sfp_shodan_internetdb import sfp_shodan_internetdb
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


SAMPLE = {
    "ip": "93.184.216.34",
    "ports": [22, 80, 443],
    "cpes": ["cpe:/a:igor_sysoev:nginx", "cpe:/a:openbsd:openssh:7.4"],
    "hostnames": ["www.example.com", "cohost.other.net"],
    "tags": ["cloud"],
    "vulns": ["CVE-2017-15906"],
}


@pytest.mark.usefixtures
class TestModuleShodanInternetdb(unittest.TestCase):

    def _module(self, opts=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_shodan_internetdb()
        module.setup(sf, opts or {'cvelookup': False})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        return module

    def _event(self, etype, data):
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        return SpiderFootEvent(etype, data, 'test', root)

    def _run(self, module, evt, response):
        emitted = []
        with patch.object(module.sf, 'fetchUrl', return_value=response) as fetch, \
             patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        return fetch, emitted

    def test_opts(self):
        module = sfp_shodan_internetdb()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_shodan_internetdb()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_shodan_internetdb()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_shodan_internetdb()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_should_emit_ports_software_hosts_and_vulns(self):
        module = self._module()
        evt = self._event('IP_ADDRESS', '93.184.216.34')
        _, emitted = self._run(module, evt, {'code': '200', 'content': json.dumps(SAMPLE)})

        got = {(e.eventType, e.data) for e in emitted}
        self.assertIn(("TCP_PORT_OPEN", "93.184.216.34:22"), got)
        self.assertIn(("TCP_PORT_OPEN", "93.184.216.34:443"), got)
        self.assertIn(("SOFTWARE_USED", "cpe:/a:openbsd:openssh:7.4"), got)
        self.assertIn(("INTERNET_NAME", "www.example.com"), got)
        self.assertIn(("CO_HOSTED_SITE", "cohost.other.net"), got)
        self.assertIn(("VULNERABILITY_GENERAL", "CVE-2017-15906"), got)
        self.assertIn("RAW_RIR_DATA", {e.eventType for e in emitted})
        for e in emitted:
            self.assertIs(e.sourceEvent, evt)

    def test_handleEvent_cvelookup_should_classify_via_cveInfo(self):
        module = self._module({'cvelookup': True})
        evt = self._event('IP_ADDRESS', '93.184.216.34')
        with patch.object(module.sf, 'cveInfo', return_value=("VULNERABILITY_CVE_MEDIUM", "CVE-2017-15906 desc")) as cve:
            _, emitted = self._run(module, evt, {'code': '200', 'content': json.dumps(SAMPLE)})
        cve.assert_called_once_with("CVE-2017-15906")
        self.assertIn(("VULNERABILITY_CVE_MEDIUM", "CVE-2017-15906 desc"), {(e.eventType, e.data) for e in emitted})

    def test_handleEvent_ipv6_ports_should_be_bracketed(self):
        module = self._module()
        ip = "2001:4860:4860::8888"
        evt = self._event('IPV6_ADDRESS', ip)
        body = {"ip": ip, "ports": [53], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
        _, emitted = self._run(module, evt, {'code': '200', 'content': json.dumps(body)})
        self.assertIn(("TCP_PORT_OPEN", f"[{ip}]:53"), {(e.eventType, e.data) for e in emitted})

    def test_handleEvent_non_global_ip_should_not_be_sent_to_third_party(self):
        module = self._module()
        for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fd00::1"):
            with self.subTest(ip=ip):
                etype = 'IPV6_ADDRESS' if ':' in ip else 'IP_ADDRESS'
                fetch, emitted = self._run(module, self._event(etype, ip), {'code': '200', 'content': '{}'})
                fetch.assert_not_called()
                self.assertEqual(emitted, [])

    def test_handleEvent_404_should_emit_nothing(self):
        module = self._module()
        _, emitted = self._run(module, self._event('IP_ADDRESS', '93.184.216.34'),
                               {'code': '404', 'content': '{"detail":"No information available"}'})
        self.assertEqual(emitted, [])
        self.assertFalse(module.errorState)

    def test_handleEvent_429_should_set_errorState(self):
        module = self._module()
        _, emitted = self._run(module, self._event('IP_ADDRESS', '93.184.216.34'),
                               {'code': '429', 'content': ''})
        self.assertEqual(emitted, [])
        self.assertTrue(module.errorState)

    def test_handleEvent_invalid_json_should_emit_nothing(self):
        module = self._module()
        _, emitted = self._run(module, self._event('IP_ADDRESS', '93.184.216.34'),
                               {'code': '200', 'content': '<html>not json</html>'})
        self.assertEqual(emitted, [])

    def test_handleEvent_duplicate_ip_should_query_once(self):
        module = self._module()
        resp = {'code': '200', 'content': json.dumps(SAMPLE)}
        fetch, _ = self._run(module, self._event('IP_ADDRESS', '93.184.216.34'), resp)
        fetch2, _ = self._run(module, self._event('IP_ADDRESS', '93.184.216.34'), resp)
        fetch.assert_called_once()
        fetch2.assert_not_called()

    def test_validateResponse_should_reject_ip_mismatch(self):
        module = self._module()
        self.assertIsNone(module.validateResponse(dict(SAMPLE, ip="1.2.3.4"), "93.184.216.34"))

    def test_validateResponse_should_reject_non_list_fields(self):
        module = self._module()
        self.assertIsNone(module.validateResponse(dict(SAMPLE, ports="22"), "93.184.216.34"))
        self.assertIsNone(module.validateResponse(["not", "a", "dict"], "93.184.216.34"))

    def test_validateResponse_should_drop_malformed_items(self):
        module = self._module()
        dirty = {
            "ip": "93.184.216.34",
            "ports": [22, -1, 70000, True, "80"],
            "cpes": ["cpe:/a:x:y", "not-a-cpe", 5],
            "hostnames": ["OK.Example.com.", "bad host!", "-lead.example.com", "trail-.example.com",
                          "localhost", "a..b.com", "x" * 300, ("a" * 64) + ".com"],
            "tags": ["cloud", None],
            "vulns": ["CVE-2021-44228", "CVE-bad", "'; DROP TABLE"],
        }
        clean = module.validateResponse(dirty, "93.184.216.34")
        self.assertEqual(clean['ports'], [22])
        self.assertEqual(clean['cpes'], ["cpe:/a:x:y"])
        self.assertEqual(clean['hostnames'], ["ok.example.com"])
        self.assertEqual(clean['tags'], ["cloud"])
        self.assertEqual(clean['vulns'], ["CVE-2021-44228"])
