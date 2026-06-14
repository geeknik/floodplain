import json
import unittest
from unittest.mock import MagicMock, patch

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


class TestCorrelationTriagePayload(unittest.TestCase):

    def _dbh_with(self, correlations, events_by_corr):
        dbh = MagicMock()
        dbh.scanCorrelationList.return_value = correlations
        dbh.scanResultEvent.side_effect = lambda scan_id, correlationId=None, **kw: events_by_corr.get(correlationId, [])
        return dbh

    def test_payload_is_metadata_only(self):
        # scanCorrelationList row layout
        correlations = [
            ("corr-1", "Title with SECRETVALUE", "rule_id", "HIGH", "Rule Name",
             "Rule description", "id: rule_id", 3),
        ]
        # event rows mirror scanResultEvent output: value at index 1 (sentinel
        # secret), type name at index 4.
        events = {
            "corr-1": [
                ["id", "SECRETVALUE-leak@example.com", "mod", "modname", "EMAILADDR", 1],
            ],
        }
        dbh = self._dbh_with(correlations, events)
        t = CorrelationTriage(dbh=dbh, config={"_llm_enabled": True, "_llm_api_key": "k"})

        payload = t.build_payload("scan-x")
        blob = json.dumps(payload)

        # metadata present
        self.assertIn("Rule Name", blob)
        self.assertIn("EMAILADDR", blob)
        # raw values absent (the egress contract)
        self.assertNotIn("SECRETVALUE", blob)
        self.assertEqual(payload[0]["index"], 0)
        self.assertEqual(payload[0]["risk"], "HIGH")
        self.assertEqual(payload[0]["event_count"], 3)
        self.assertEqual(payload[0]["event_types"], ["EMAILADDR"])


class TestCorrelationTriageValidate(unittest.TestCase):

    def setUp(self):
        self.t = CorrelationTriage(dbh=object(), config={})
        # index -> correlation id
        self.id_by_index = {0: "corr-0", 1: "corr-1"}

    def test_valid_response_maps_to_ids_and_coerces(self):
        raw = {"results": [
            {"index": 0, "priority": "high", "rank": 2, "explanation": "a", "group": "g"},
            {"index": 1, "priority": "BOGUS", "rank": 1, "explanation": "b"},
        ]}
        out = self.t.validate_results(raw, self.id_by_index)
        out_by_id = {r["correlation_id"]: r for r in out}
        self.assertEqual(out_by_id["corr-0"]["priority"], "HIGH")   # upper-cased
        self.assertEqual(out_by_id["corr-1"]["priority"], "INFO")   # invalid -> INFO
        self.assertEqual(out_by_id["corr-0"]["grp"], "g")
        self.assertIsNone(out_by_id["corr-1"]["grp"])

    def test_unknown_index_is_dropped(self):
        raw = {"results": [{"index": 99, "priority": "LOW", "rank": 1, "explanation": "x"}]}
        self.assertEqual(self.t.validate_results(raw, self.id_by_index), [])

    def test_explanation_is_length_bounded(self):
        raw = {"results": [{"index": 0, "priority": "LOW", "rank": 1, "explanation": "y" * 5000}]}
        out = self.t.validate_results(raw, self.id_by_index)
        self.assertLessEqual(len(out[0]["explanation"]), 500)

    def test_malformed_response_raises(self):
        from spiderfoot.llm import LLMError
        with self.assertRaises(LLMError):
            self.t.validate_results({"not_results": []}, self.id_by_index)
