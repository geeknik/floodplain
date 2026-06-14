import unittest
from unittest.mock import patch

from spiderfoot.correlation_triage import CorrelationTriage


class TestCorrelationTriageEnablement(unittest.TestCase):

    def test_disabled_when_flag_off(self):
        t = CorrelationTriage(dbh=object(), config={"_llm_enabled": False, "_llm_api_key": "k"})
        self.assertFalse(t.is_enabled())

    def test_disabled_when_no_key(self):
        t = CorrelationTriage(dbh=object(), config={"_llm_enabled": True, "_llm_api_key": ""})
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(t.is_enabled())

    def test_enabled_with_flag_and_config_key(self):
        t = CorrelationTriage(dbh=object(), config={"_llm_enabled": True, "_llm_api_key": "k"})
        self.assertTrue(t.is_enabled())

    def test_env_var_key_overrides_empty_config(self):
        t = CorrelationTriage(dbh=object(), config={"_llm_enabled": True, "_llm_api_key": ""})
        with patch.dict("os.environ", {"FLOODPLAIN_OPENROUTER_API_KEY": "envkey"}, clear=True):
            self.assertTrue(t.is_enabled())
            self.assertEqual(t._resolve_api_key(), "envkey")
