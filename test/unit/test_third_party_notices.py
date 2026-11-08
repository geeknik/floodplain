# test_third_party_notices.py
"""Every vendored web library must ship its license and be declared."""
import glob
import json
import os
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
VENDOR = os.path.join(ROOT, "floodplain", "static", "node_modules")


class TestThirdPartyNotices(unittest.TestCase):

    def vendored(self):
        return sorted(d for d in os.listdir(VENDOR) if os.path.isdir(os.path.join(VENDOR, d)))

    def test_every_vendored_library_ships_its_license(self):
        missing = [d for d in self.vendored() if not glob.glob(os.path.join(VENDOR, d, "LICEN[CS]E*"))]
        self.assertFalse(missing, f"Add the upstream LICENSE file for: {missing}")

    def test_vendored_libraries_match_package_json(self):
        with open(os.path.join(ROOT, "floodplain", "static", "package.json"), encoding="utf-8") as f:
            declared = sorted(json.load(f)["dependencies"])
        self.assertEqual(self.vendored(), declared)

    def test_every_vendored_library_is_listed_in_notices(self):
        with open(os.path.join(ROOT, "THIRD-PARTY-NOTICES.md"), encoding="utf-8") as f:
            notices = f.read()
        unlisted = [d for d in self.vendored() if f"`{d}/LICEN" not in notices]
        self.assertFalse(unlisted, f"List these in THIRD-PARTY-NOTICES.md: {unlisted}")

    def test_no_copyleft_web_libraries(self):
        # The web UI is served to every user; keep it permissively licensed.
        for d in self.vendored():
            for lic in glob.glob(os.path.join(VENDOR, d, "LICEN[CS]E*")):
                with open(lic, encoding="utf-8", errors="replace") as f:
                    head = f.read(400)
                with self.subTest(library=d):
                    self.assertNotIn("GNU GENERAL PUBLIC LICENSE", head)
                    self.assertNotIn("GNU AFFERO", head)

    def test_alertify_is_gone(self):
        for path in glob.glob(os.path.join(ROOT, "floodplain", "templates", "*.tmpl")) + \
                glob.glob(os.path.join(ROOT, "floodplain", "static", "js", "*.js")):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("alertify", f.read(), path)
