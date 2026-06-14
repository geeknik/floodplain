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


class TestCorrelationTriageRun(unittest.TestCase):

    def _dbh(self, correlations):
        dbh = MagicMock()
        dbh.scanCorrelationList.return_value = correlations
        dbh.scanResultEvent.return_value = [["id", "v", "m", "mod", "IP_ADDRESS", 1]]
        return dbh

    def _correlations(self, n):
        return [(f"corr-{i}", f"title {i}", "rid", "LOW", "Rule", "Desc", "yaml", 1) for i in range(n)]

    def test_disabled_does_not_call_client_or_db_writes(self):
        dbh = self._dbh(self._correlations(1))
        t = CorrelationTriage(dbh=dbh, config={"_llm_enabled": False, "_llm_api_key": "k"})
        with patch("spiderfoot.correlation_triage.OpenRouterClient") as MockClient:
            result = t.triage("scan-x")
        MockClient.assert_not_called()
        dbh.correlationLlmCreate.assert_not_called()
        self.assertFalse(result["enabled"])

    def test_happy_path_persists_rows(self):
        dbh = self._dbh(self._correlations(2))
        cfg = {"_llm_enabled": True, "_llm_api_key": "k", "_llm_model": "test/model"}
        t = CorrelationTriage(dbh=dbh, config=cfg)
        fake = MagicMock()
        fake.chat.return_value = {"results": [
            {"index": 0, "priority": "HIGH", "rank": 1, "explanation": "a"},
            {"index": 1, "priority": "LOW", "rank": 2, "explanation": "b"},
        ]}
        with patch("spiderfoot.correlation_triage.OpenRouterClient", return_value=fake):
            result = t.triage("scan-x")
        self.assertEqual(result["triaged"], 2)
        self.assertEqual(dbh.correlationLlmCreate.call_count, 2)

    def test_triage_queries_correlation_list_once(self):
        """triage() must fetch scanCorrelationList only once (reused for both the
        payload and the index->id map), not once per helper."""
        dbh = self._dbh(self._correlations(3))
        cfg = {"_llm_enabled": True, "_llm_api_key": "k", "_llm_model": "test/model"}
        t = CorrelationTriage(dbh=dbh, config=cfg)
        fake = MagicMock()
        fake.chat.return_value = {"results": []}
        with patch("spiderfoot.correlation_triage.OpenRouterClient", return_value=fake):
            t.triage("scan-x")
        self.assertEqual(dbh.scanCorrelationList.call_count, 1)

    def test_invalid_output_writes_nothing(self):
        from spiderfoot.llm import LLMError
        dbh = self._dbh(self._correlations(1))
        cfg = {"_llm_enabled": True, "_llm_api_key": "k", "_llm_model": "test/model"}
        t = CorrelationTriage(dbh=dbh, config=cfg)
        fake = MagicMock()
        fake.chat.return_value = {"garbage": True}
        with patch("spiderfoot.correlation_triage.OpenRouterClient", return_value=fake):
            with self.assertRaises(LLMError):
                t.triage("scan-x")
        dbh.correlationLlmCreate.assert_not_called()

    def test_truncates_when_over_cap(self):
        dbh = self._dbh(self._correlations(5))
        cfg = {"_llm_enabled": True, "_llm_api_key": "k", "_llm_model": "test/model",
               "_llm_max_correlations": 2}
        t = CorrelationTriage(dbh=dbh, config=cfg)
        fake = MagicMock()
        fake.chat.return_value = {"results": [{"index": 0, "priority": "LOW", "rank": 1, "explanation": "a"}]}
        with patch("spiderfoot.correlation_triage.OpenRouterClient", return_value=fake):
            result = t.triage("scan-x")
        self.assertTrue(result["truncated"])


class TestPackageExports(unittest.TestCase):
    def test_classes_importable_from_package(self):
        from spiderfoot import CorrelationTriage, OpenRouterClient, LLMError  # noqa: F401
