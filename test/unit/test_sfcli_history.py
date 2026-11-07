# test_sfcli_history.py
import os
import pathlib
import tempfile
import unittest

from sfcli import cliHistoryFile


class TestCliHistoryFile(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()

    def test_new_install(self):
        self.assertEqual(cliHistoryFile(self.home), os.path.join(self.home, ".floodplain_history"))

    def test_legacy_history_is_kept(self):
        pathlib.Path(os.path.join(self.home, ".spiderfoot_history")).touch()
        self.assertEqual(cliHistoryFile(self.home), os.path.join(self.home, ".spiderfoot_history"))

    def test_new_history_wins(self):
        for name in (".spiderfoot_history", ".floodplain_history"):
            pathlib.Path(os.path.join(self.home, name)).touch()
        self.assertEqual(cliHistoryFile(self.home), os.path.join(self.home, ".floodplain_history"))
