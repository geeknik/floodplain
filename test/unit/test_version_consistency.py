# test_version_consistency.py
"""Every place that states the Floodplain version must agree."""
import os
import re
import unittest

from sfcli import SpiderFootCli
from spiderfoot import __version__

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class TestVersionConsistency(unittest.TestCase):

    def test_version_is_semver(self):
        self.assertRegex(__version__, r'^\d+\.\d+\.\d+$')

    def test_version_file(self):
        self.assertEqual(read("VERSION").strip(), f"Floodplain {__version__}")

    def test_cli_version_matches_server(self):
        # sfcli warns when its version differs from the server's /ping version.
        self.assertEqual(SpiderFootCli.version, __version__)

    def test_readme_badge_and_install_url(self):
        readme = read("README.md")
        badge = re.search(r'badge/version-([0-9.]+)-blue', readme)
        self.assertIsNotNone(badge)
        self.assertEqual(badge.group(1), __version__)
        self.assertIn(f"releases/tag/v{__version__}", readme)
        self.assertIn(f"archive/v{__version__}.tar.gz", readme)
