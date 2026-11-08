import os
import pytest
import unittest

from modules.sfp_tool_nuclei import sfp_tool_nuclei
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleToolNuclei(unittest.TestCase):

    def test_opts(self):
        module = sfp_tool_nuclei()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_nuclei()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_nuclei()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_nuclei()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_tool_path_configured_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_nuclei()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)


NUCLEI_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "nuclei_v3_finding.jsonl")


@pytest.mark.usefixtures
class TestModuleToolNucleiV3(unittest.TestCase):
    """Parses real Nuclei v3.11.1 JSONL output (local canary template)."""

    def _run(self, stdout: bytes, target='127.0.0.1', etype='IP_ADDRESS'):
        import tempfile
        from unittest.mock import MagicMock, patch
        exe = tempfile.NamedTemporaryFile(delete=False)
        exe.close()
        module = sfp_tool_nuclei()
        module.setup(SpiderFoot(self.default_options), {'nuclei_path': exe.name, 'template_path': '/tmp/templates'})
        module.setTarget(SpiderFootTarget(target, etype))
        evt = SpiderFootEvent(etype, target, 'test', SpiderFootEvent('ROOT', target, '', ''))
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate.return_value = (stdout, b"")
        emitted = []
        with patch('modules.sfp_tool_nuclei.Popen', return_value=proc) as popen, \
                patch.object(module.sf, 'cveInfo', side_effect=lambda c: ("VULNERABILITY_CVE_CRITICAL", f"{c} desc")), \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        os.unlink(exe.name)
        return popen, emitted

    def test_uses_v3_flags(self):
        with open(NUCLEI_FIXTURE, "rb") as f:
            popen, _ = self._run(f.read())
        args = popen.call_args[0][0]
        for flag in ("-jsonl", "-omit-raw", "-disable-update-check", "-no-color"):
            self.assertIn(flag, args)
        self.assertNotIn("-json", args)
        self.assertEqual(args[args.index("-etags") + 1], "dos,fuzz,misc")
        self.assertNotIn("fuzz", args[args.index("-etags") + 2:])

    def test_real_v3_finding_yields_cve_from_template_classification(self):
        with open(NUCLEI_FIXTURE, "rb") as f:
            _, emitted = self._run(f.read())
        self.assertEqual([(e.eventType, e.data) for e in emitted],
                         [("VULNERABILITY_CVE_CRITICAL", "CVE-2021-44228 desc")])

    def test_cve_strings_in_response_data_are_ignored(self):
        import json
        finding = {"template-id": "tech-detect", "host": "127.0.0.1", "matched-at": "http://127.0.0.1/",
                   "info": {"name": "Tech", "severity": "info", "classification": {"cve-id": None}},
                   "extracted-results": ["CVE-2099-0001"], "response": "HTTP/1.1 200 OK\r\n\r\nCVE-2099-0002"}
        _, emitted = self._run(json.dumps(finding).encode())
        self.assertEqual([e.eventType for e in emitted], ["WEBSERVER_TECHNOLOGY"])
        self.assertNotIn("CVE-2099", emitted[0].data)

    def test_host_is_parsed_from_url_and_validated(self):
        import json
        rows = [
            {"template-id": "a", "host": "https://www.example.com:8443", "matched-at": "https://www.example.com:8443/x",
             "info": {"name": "A", "severity": "low"}},
            {"template-id": "b", "host": "evil host; rm -rf /", "matched-at": "x",
             "info": {"name": "B", "severity": "low"}},
        ]
        _, emitted = self._run("\n".join(json.dumps(r) for r in rows).encode(), target='example.com', etype='INTERNET_NAME')
        names = [e.data for e in emitted if e.eventType == "INTERNET_NAME"]
        self.assertEqual(names, ["www.example.com"])
        self.assertEqual(len([e for e in emitted if e.eventType == "VULNERABILITY_GENERAL"]), 2)

    def test_bad_lines_do_not_abort_parsing(self):
        import json
        good = json.dumps({"template-id": "g", "host": "127.0.0.1", "info": {"name": "<b>G</b>\nX", "severity": "medium"}})
        _, emitted = self._run(("not json\n[]\n" + good).encode())
        self.assertEqual(len(emitted), 1)
        self.assertNotIn("<", emitted[0].data)
        self.assertTrue(emitted[0].data.startswith("Template: bG/b X(g)"))
