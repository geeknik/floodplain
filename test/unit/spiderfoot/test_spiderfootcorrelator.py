# test_spiderfootcorrelator.py
import unittest

from spiderfoot import SpiderFootCorrelator, SpiderFootDb


class TestSpiderFootCorrelator(unittest.TestCase):
    """
    Test SpiderFootCorrelator
    """

    def test_init_argument_dbh_invalid_type_should_raise_TypeError(self):
        invalid_types = [None, str(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootCorrelator(invalid_type, {})

    def test_init_argument_ruleset_invalid_type_should_raise_TypeError(self):
        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootCorrelator(None, invalid_type)

    def test_init_argument_ruleset_invalid_rule_should_raise_SyntaxError(self):
        sfdb = SpiderFootDb(self.default_options, False)

        ruleset = {"sample rule": "invalid yaml"}
        with self.assertRaises(SyntaxError):
            SpiderFootCorrelator(sfdb, ruleset)

    def test_run_correlations_invalid_scan_instance_should_raise_ValueError(self):
        sfdb = SpiderFootDb(self.default_options, False)

        correlator = SpiderFootCorrelator(sfdb, {}, 'example scan id')
        with self.assertRaises(ValueError):
            correlator.run_correlations()

    def test_build_db_criteria_argument_matchrule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.build_db_criteria(invalid_type)

    def test_enrich_event_sources_argument_rule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.enrich_event_sources(invalid_type)

    def test_enrich_event_children_argument_rule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.enrich_event_children(invalid_type)

    def test_enrich_event_entities_argument_rule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.enrich_event_entities(invalid_type)

    def test_process_rule_argument_rule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.process_rule(invalid_type)

    def test_build_correlation_title_argument_rule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.build_correlation_title(invalid_type, [])

    def test_build_correlation_title_argument_data_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.build_correlation_title({}, invalid_type)

    def test_create_correlation_argument_rule_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.create_correlation(invalid_type, [], readonly=True)

    def test_create_correlation_argument_data_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    correlator.create_correlation({}, invalid_type, readonly=True)

    def test_check_ruleset_validity_should_return_bool(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        ruleset = [{"sample": "sample"}]
        self.assertIsInstance(correlator.check_ruleset_validity(ruleset), bool)

        invalid_types = [None, str(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                self.assertIsInstance(correlator.check_ruleset_validity(invalid_type), bool)

    def test_check_rule_validity_invalid_rule_should_return_false(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                self.assertFalse(correlator.check_rule_validity(invalid_type))

    def test_check_rule_validity_rule_missing_mandatory_field_should_return_false(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        rule = {
            "id": "sample",
            "collections": [],
            "headline": "sample"
        }
        self.assertFalse(correlator.check_rule_validity(rule))

        rule = {
            "id": "sample",
            "meta": "sample",
            "headline": "sample"
        }
        self.assertFalse(correlator.check_rule_validity(rule))

        rule = {
            "id": "sample",
            "meta": "sample",
            "collections": []
        }
        self.assertFalse(correlator.check_rule_validity(rule))

    def test_build_correlation_title_missing_field_does_not_crash_or_use_stale_value(self):
        """A headline referencing a field that is absent from the matched data
        must not raise (undefined 'v' -> NameError) nor substitute a stale
        value from a previously-resolved field."""
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        # The missing field comes first, so the buggy code path hit `v` before
        # it was ever assigned (NameError).
        rule = {"headline": "{missingfield} relates to {data}"}
        data = [{"data": "example.com", "type": "INTERNET_NAME"}]

        title = correlator.build_correlation_title(rule, data)

        self.assertIsInstance(title, str)
        # The available field is still substituted.
        self.assertIn("example.com", title)
        # The unavailable field is left as a literal placeholder rather than
        # crashing or being filled with another field's value.
        self.assertIn("{missingfield}", title)

    def test_init_does_not_crash_on_non_string_meta_value(self):
        """Loading a rule whose meta contains a non-string value must not raise
        (the meta-normalisation step previously referenced a non-existent
        top-level rule key for any non-string meta value)."""
        sfdb = SpiderFootDb(self.default_options, False)

        rule_yaml = (
            "id: testrule\n"
            "version: 1\n"
            "meta:\n"
            "  name: Test\n"
            "  description: Test description\n"
            "  risk: INFO\n"
            "  references:\n"
            "    - https://example.com\n"
            "collections:\n"
            "  - collect:\n"
            "      - field: type\n"
            "        method: exact\n"
            "        value: INTERNET_NAME\n"
            "headline: Test headline\n"
        )

        correlator = SpiderFootCorrelator(sfdb, {"testrule": rule_yaml})
        self.assertEqual(len(correlator.get_ruleset()), 1)
        # The non-string meta value is preserved untouched.
        self.assertEqual(correlator.get_ruleset()[0]["meta"]["references"], ["https://example.com"])
