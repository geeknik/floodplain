# test_spiderfoothelpers_paths.py
"""Data/cache/log directory resolution (Floodplain + legacy SpiderFoot)."""
import os
import pathlib
import stat
import tempfile
import unittest
from unittest.mock import patch

from spiderfoot import SpiderFootHelpers

ENV_VARS = [f"{p}_{n}" for p in ("FLOODPLAIN", "SPIDERFOOT") for n in ("DATA", "CACHE", "LOGS")]


def clean_env(**overrides):
    """Environment with every path variable removed, plus overrides.

    Args:
        overrides: variables to set

    Returns:
        dict: environment
    """
    env = {k: v for k, v in os.environ.items() if k not in ENV_VARS}
    env.update(overrides)
    return env


class TestEnvPath(unittest.TestCase):

    def test_unset_returns_none(self):
        with patch.dict(os.environ, clean_env(), clear=True):
            self.assertIsNone(SpiderFootHelpers.envPath('DATA'))

    def test_floodplain_wins_over_legacy(self):
        with patch.dict(os.environ, clean_env(FLOODPLAIN_DATA="/srv/fp", SPIDERFOOT_DATA="/srv/sf"), clear=True):
            self.assertEqual(SpiderFootHelpers.envPath('DATA'), "/srv/fp")

    def test_legacy_used_when_new_unset_or_empty(self):
        for env in (clean_env(SPIDERFOOT_DATA="/srv/sf"), clean_env(FLOODPLAIN_DATA="", SPIDERFOOT_DATA="/srv/sf")):
            with self.subTest(env={k: env.get(k) for k in ("FLOODPLAIN_DATA", "SPIDERFOOT_DATA")}):
                with patch.dict(os.environ, env, clear=True):
                    self.assertEqual(SpiderFootHelpers.envPath('DATA'), "/srv/sf")

    def test_relative_paths_are_rejected(self):
        for value in ("data", "./data", "../etc", "~nonexistentuser12345/x"):
            for var in ("FLOODPLAIN_DATA", "SPIDERFOOT_DATA"):
                with self.subTest(var=var, value=value):
                    with patch.dict(os.environ, clean_env(**{var: value}), clear=True):
                        with self.assertRaises(ValueError) as ctx:
                            SpiderFootHelpers.envPath('DATA')
                        self.assertIn(var, str(ctx.exception))

    def test_path_is_normalised(self):
        with patch.dict(os.environ, clean_env(FLOODPLAIN_LOGS="/srv/fp/../fp//logs/"), clear=True):
            self.assertEqual(SpiderFootHelpers.envPath('LOGS'), "/srv/fp/logs")


class TestHomeDataPath(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()

    def test_fresh_home_uses_floodplain(self):
        self.assertEqual(SpiderFootHelpers.homeDataPath(self.home), (os.path.join(self.home, ".floodplain"), False))

    def test_legacy_only_is_used_in_place(self):
        os.mkdir(os.path.join(self.home, ".spiderfoot"))
        self.assertEqual(SpiderFootHelpers.homeDataPath(self.home), (os.path.join(self.home, ".spiderfoot"), True))

    def test_floodplain_wins_when_both_exist(self):
        os.mkdir(os.path.join(self.home, ".spiderfoot"))
        os.mkdir(os.path.join(self.home, ".floodplain"))
        self.assertEqual(SpiderFootHelpers.homeDataPath(self.home), (os.path.join(self.home, ".floodplain"), False))

    def test_legacy_file_not_dir_is_ignored(self):
        pathlib.Path(os.path.join(self.home, ".spiderfoot")).touch()
        self.assertEqual(SpiderFootHelpers.homeDataPath(self.home)[1], False)


class TestDirectories(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.data = os.path.join(self.root, "data")

    def test_dataPath_creates_owner_only_directory(self):
        with patch.dict(os.environ, clean_env(FLOODPLAIN_DATA=self.data), clear=True):
            path = SpiderFootHelpers.dataPath()
        self.assertEqual(path, self.data)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)

    def test_existing_directory_permissions_are_untouched(self):
        os.mkdir(self.data, 0o755)
        os.chmod(self.data, 0o755)
        with patch.dict(os.environ, clean_env(FLOODPLAIN_DATA=self.data), clear=True):
            SpiderFootHelpers.dataPath()
        self.assertEqual(stat.S_IMODE(os.stat(self.data).st_mode), 0o755)

    def test_non_directory_fails_closed(self):
        pathlib.Path(self.data).touch()
        with patch.dict(os.environ, clean_env(FLOODPLAIN_DATA=self.data), clear=True):
            with self.assertRaises(OSError):
                SpiderFootHelpers.dataPath()

    def test_cache_and_logs_default_under_data(self):
        with patch.dict(os.environ, clean_env(FLOODPLAIN_DATA=self.data), clear=True):
            self.assertEqual(SpiderFootHelpers.cachePath(), os.path.join(self.data, "cache"))
            self.assertEqual(SpiderFootHelpers.logPath(), os.path.join(self.data, "logs"))

    def test_cache_and_logs_overrides(self):
        cache, logs = os.path.join(self.root, "c"), os.path.join(self.root, "l")
        with patch.dict(os.environ, clean_env(FLOODPLAIN_DATA=self.data, SPIDERFOOT_CACHE=cache, FLOODPLAIN_LOGS=logs), clear=True):
            self.assertEqual(SpiderFootHelpers.cachePath(), cache)
            self.assertEqual(SpiderFootHelpers.logPath(), logs)

    def test_home_default_when_no_env(self):
        with patch.dict(os.environ, clean_env(), clear=True), \
                patch.object(SpiderFootHelpers, "homeDataPath", return_value=(self.data, False)):
            self.assertEqual(SpiderFootHelpers.dataPath(), self.data)


class TestDataFile(unittest.TestCase):

    def setUp(self):
        self.data = tempfile.mkdtemp()
        self.env = patch.dict(os.environ, clean_env(FLOODPLAIN_DATA=self.data), clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def touch(self, name):
        pathlib.Path(os.path.join(self.data, name)).touch()

    def test_new_install_gets_floodplain_name(self):
        self.assertEqual(SpiderFootHelpers.dataFile("floodplain.db", "spiderfoot.db"), os.path.join(self.data, "floodplain.db"))

    def test_legacy_file_is_kept(self):
        self.touch("spiderfoot.db")
        self.assertEqual(SpiderFootHelpers.dataFile("floodplain.db", "spiderfoot.db"), os.path.join(self.data, "spiderfoot.db"))

    def test_new_file_wins_when_both_exist(self):
        self.touch("spiderfoot.db")
        self.touch("floodplain.db")
        self.assertEqual(SpiderFootHelpers.dataFile("floodplain.db", "spiderfoot.db"), os.path.join(self.data, "floodplain.db"))
