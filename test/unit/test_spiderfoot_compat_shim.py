# test_spiderfoot_compat_shim.py
"""The deprecated ``spiderfoot`` package must alias ``floodplain`` exactly."""
import importlib
import sys
import unittest
import warnings

import floodplain


class TestSpiderfootShim(unittest.TestCase):

    def _import_shim(self):
        for name in [n for n in sys.modules if n == "spiderfoot" or n.startswith("spiderfoot.")]:
            del sys.modules[name]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            shim = importlib.import_module("spiderfoot")
        return shim, caught

    def test_import_warns(self):
        _, caught = self._import_shim()
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) and "floodplain" in str(w.message) for w in caught))

    def test_public_names_are_the_same_objects(self):
        shim, _ = self._import_shim()
        for name in ("SpiderFootPlugin", "SpiderFootEvent", "SpiderFootTarget", "SpiderFootHelpers",
                     "SpiderFootDb", "SpiderFootCorrelator", "SpiderFootThreadPool", "__version__"):
            with self.subTest(name=name):
                self.assertIs(getattr(shim, name), getattr(floodplain, name))

    def test_submodule_imports_resolve_to_floodplain(self):
        self._import_shim()
        from spiderfoot.db import SpiderFootDb
        from spiderfoot.logger import logWorkerSetup
        import spiderfoot.websearch as ws
        self.assertIs(SpiderFootDb, floodplain.SpiderFootDb)
        self.assertIs(logWorkerSetup, importlib.import_module("floodplain.logger").logWorkerSetup)
        self.assertIs(ws, importlib.import_module("floodplain.websearch"))

    def test_legacy_plugin_subclass_is_a_floodplain_plugin(self):
        shim, _ = self._import_shim()

        class sfp_legacy(shim.SpiderFootPlugin):
            pass

        self.assertTrue(issubclass(sfp_legacy, floodplain.SpiderFootPlugin))
