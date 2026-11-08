import os
import pytest
import unittest
from unittest.mock import patch

from modules.sfp_tool_trufflehog import sfp_tool_trufflehog
from sflib import SpiderFoot
from floodplain import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleToolTrufflehog(unittest.TestCase):

    def test_opts(self):
        module = sfp_tool_trufflehog()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_trufflehog()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_trufflehog()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_trufflehog()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_tool_path_configured_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_trufflehog()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example value'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)

    def test_handleEvent_malicious_repo_url_should_not_invoke_subprocess(self):
        """A crafted event whose extracted repository URL begins with '-' (or
        contains whitespace) must be refused and never reach the subprocess,
        preventing command-line argument injection into trufflehog."""
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_trufflehog()
        module.setup(sf, {'trufflehog_path': '/usr/bin/trufflehog'})

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        # Contains "github.com/" so extraction is attempted, but the extracted
        # value starts with '-' and contains a space, so it must be refused.
        malicious = 'Github: --proxy=http://evil https://github.com/x'
        evt = SpiderFootEvent('SOCIAL_MEDIA', malicious, 'test', root)

        with patch('modules.sfp_tool_trufflehog.os.path.isfile', return_value=True), \
             patch('modules.sfp_tool_trufflehog.Popen') as mock_popen:
            module.handleEvent(evt)

        mock_popen.assert_not_called()

    def test_handleEvent_host_confusion_url_should_not_invoke_subprocess(self):
        """A URL whose authority is not an allowlisted code host must be refused,
        even when the raw event data contains an allowlisted host as a substring
        (e.g. https://evil.com/?x=github.com/repo or https://github.com.evil.com).

        Guards against the incomplete URL substring sanitization class (CWE-20):
        the trust decision must be made on the parsed hostname, never on a
        substring match of the raw event data."""
        sf = SpiderFoot(self.default_options)

        module = sfp_tool_trufflehog()
        module.setup(sf, {'trufflehog_path': '/usr/bin/trufflehog'})

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        root = SpiderFootEvent('ROOT', 'example.com', '', '')

        for confusing in (
            # allowlisted host appears only in the query string; real host is evil.com
            'Github: https://evil.com/?x=github.com/repo',
            # allowlisted host is only a left-hand label of a different domain
            'Github: https://github.com.evil.com/repo',
        ):
            with self.subTest(url=confusing):
                evt = SpiderFootEvent('SOCIAL_MEDIA', confusing, 'test', root)
                with patch('modules.sfp_tool_trufflehog.os.path.isfile', return_value=True), \
                     patch('modules.sfp_tool_trufflehog.Popen') as mock_popen:
                    module.handleEvent(evt)
                mock_popen.assert_not_called()


FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "trufflehog_v3_findings.jsonl")
REPO = "https://github.com/example-org/example-repo"


@pytest.mark.usefixtures
class TestModuleToolTrufflehogV3(unittest.TestCase):
    """Parses real TruffleHog v3.99.8 output (throwaway repo; secret values replaced by placeholders)."""

    def _run(self, stdout: bytes):
        import tempfile
        from unittest.mock import MagicMock, patch
        exe = tempfile.NamedTemporaryFile(delete=False)
        exe.close()
        module = sfp_tool_trufflehog()
        module.setup(SpiderFoot(self.default_options), {'trufflehog_path': exe.name, 'allrepos': True})
        module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        root = SpiderFootEvent('ROOT', 'example.com', '', '')
        evt = SpiderFootEvent('SOCIAL_MEDIA', f"GitHub: <SFURL>{REPO}</SFURL>", 'test', root)
        proc = MagicMock()
        proc.communicate.return_value = (stdout, b"")
        emitted = []
        with patch('modules.sfp_tool_trufflehog.Popen', return_value=proc) as popen, \
                patch.object(module, 'notifyListeners', side_effect=emitted.append):
            module.handleEvent(evt)
        os.unlink(exe.name)
        return popen, emitted

    def test_invokes_v3_cli_safely(self):
        with open(FIXTURE, "rb") as f:
            popen, _ = self._run(f.read())
        args = popen.call_args[0][0]
        self.assertEqual(args[1:], ['git', '--json', '--no-update', '--no-verification', '--', REPO])

    def test_parses_real_v3_findings_and_masks_secrets(self):
        with open(FIXTURE, "rb") as f:
            _, emitted = self._run(f.read())
        self.assertEqual([e.eventType for e in emitted], ['PASSWORD_COMPROMISED'] * 2)
        # TruffleHog scans concurrently, so result order is not stable.
        by_detector = {e.data.split("\n")[0]: e.data for e in emitted}
        self.assertEqual(by_detector["TruffleHog: Postgres secret (unverified)"].split("\n"), [
            "TruffleHog: Postgres secret (unverified)",
            f"Repository: {REPO}",
            "File: config.py:1",
            "Commit: 71c5cc6ae30f32e8a31363b8426c88b37f50bff3",
            "Secret: post… [62 chars]",
        ])
        self.assertIn("TruffleHog: Stripe secret (unverified)", by_detector)
        for e in emitted:
            # Fixture secrets are same-length placeholders ("post" / "sk_l" + X...).
            for leaked in ("XXXXXXXX", "dev@example.com", "trufflehog-23-", "db.internal", "admin"):
                self.assertNotIn(leaked, e.data)

    def test_hostile_output_is_bounded_and_sanitised(self):
        import json
        bad = [
            "not json", "[]", '{"no": "detector"}', '{"DetectorName": ["x"]}',
            json.dumps({"DetectorName": "X<script>\nInjected: yes", "Raw": "abcdefgh",
                        "SourceMetadata": {"Data": {"Git": {"file": "a\nb<x>", "line": True, "commit": "c" * 500}}}}),
        ]
        _, emitted = self._run("\n".join(bad).encode())
        self.assertEqual(len(emitted), 2)
        hostile = emitted[1].data
        self.assertNotIn("<", hostile)
        self.assertEqual(hostile.count("\n"), 4)
        self.assertIn("Commit: " + "c" * 64, hostile)
        self.assertIn("File: a bx\n", hostile)

    def test_findings_are_capped(self):
        import json
        row = json.dumps({"DetectorName": "X", "Raw": "secretvalue"})
        _, emitted = self._run(("\n".join([row] * 1000)).encode())
        self.assertEqual(len(emitted), sfp_tool_trufflehog.MAX_FINDINGS)
