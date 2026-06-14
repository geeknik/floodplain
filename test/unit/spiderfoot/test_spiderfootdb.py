# test_spiderfootdb.py
import pytest
import unittest

from spiderfoot import SpiderFootDb, SpiderFootEvent


@pytest.mark.usefixtures
class TestSpiderFootDb(unittest.TestCase):
    """
    Test SpiderFootDb
    """

    def test_init_argument_opts_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, opts, init=False)
        """
        invalid_types = [None, "", list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootDb(invalid_type)

    def test_init_argument_opts_with_empty_value_should_raise_ValueError(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(ValueError):
            SpiderFootDb(dict())

    def test_init_argument_opts_with_empty_key___database_value_should_raise_ValueError(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(ValueError):
            opts = dict()
            opts['__database'] = None
            SpiderFootDb(opts)

    def test_init_should_create_SpiderFootDb_object(self):
        """
        Test __init__(self, opts, init=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        self.assertIsInstance(sfdb, SpiderFootDb)

    @unittest.skip("todo")
    def test_create_should_create_database_schema(self):
        """
        Test create(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.create()
        self.assertEqual('TBD', 'TBD')

    def test_close_should_close_database_connection(self):
        """
        Test close(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.close()

    def test_search_should_return_a_list(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'scan_id': "example scan id",
            'type': "example type",
            'value': "example value",
            'regex': "example regex"
        }

        search_results = sfdb.search(criteria, False)
        self.assertIsInstance(search_results, list)
        self.assertFalse(search_results)

    def test_search_argument_criteria_of_invalid_type_should_raise_TypeError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, "", list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.search(invalid_type, False)

    def test_search_argument_criteria_key_of_invalid_type_should_raise_TypeError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'type': "example type",
            'value': "example value",
            'regex': []
        }

        with self.assertRaises(TypeError):
            sfdb.search(criteria, False)

    def test_search_argument_criteria_no_valid_criteria_should_raise_ValueError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'invalid_criteria': "example invalid criteria"
        }

        with self.assertRaises(ValueError):
            sfdb.search(criteria, False)

    def test_search_argument_criteria_one_criteria_should_raise_ValueError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'type': "example type"
        }

        with self.assertRaises(ValueError):
            sfdb.search(criteria, False)

    def test_eventTypes_should_return_a_list(self):
        """
        Test eventTypes(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        event_types = sfdb.eventTypes()
        self.assertIsInstance(event_types, list)

    def test_scanLogEvent_should_create_a_scan_log_event(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanLogEvent("", "", "", None)

        self.assertEqual('TBD', 'TBD')

    def test_scanLogEvent_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanLogEvent(invalid_type, "", "")

    def test_scanLogEvent_argument_classification_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanLogEvent(instance_id, invalid_type, "")

    def test_scanLogEvent_argument_message_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanLogEvent(instance_id, "", invalid_type)

    @unittest.skip("todo")
    def test_scanInstanceCreate_should_create_a_scan_instance(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanInstanceCreate_argument_instanceId_already_exists_should_halt_and_catch_fire(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        with self.assertRaises(IOError):
            sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        self.assertEqual('TBD', 'TBD')

    def test_scanInstanceCreate_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_name = ""
        scan_target = "spiderfoot.net"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanInstanceCreate(invalid_type, scan_name, scan_target)

    def test_scanInstanceCreate_argument_scanName_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_target = "spiderfoot.net"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanInstanceCreate(instance_id, invalid_type, scan_target)

    def test_scanInstanceCreate_argument_scanTarget_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = ""
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanInstanceCreate(instance_id, scan_name, invalid_type)

    def test_scanInstanceSet(self):
        """
        Test scanInstanceSet(self, instanceId, started=None, ended=None, status=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instance = 'example scan instance'
        sfdb.scanInstanceSet(scan_instance, None, None, None)
        self.assertEqual('TBD', 'TBD')

    def test_scanInstanceSet_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanInstanceSet(self, instanceId, started=None, ended=None, status=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        started = None
        ended = None
        status = None

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanInstanceSet(invalid_type, started, ended, status)

    def test_scanInstanceGet_should_return_scan_info(self):
        """
        Test scanInstanceGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        scan_instance_get = sfdb.scanInstanceGet(instance_id)

        self.assertEqual(len(scan_instance_get), 6)

        self.assertIsInstance(scan_instance_get[0], str)
        self.assertEqual(scan_instance_get[0], scan_name)

        self.assertIsInstance(scan_instance_get[1], str)
        self.assertEqual(scan_instance_get[1], scan_target)

        self.assertIsInstance(scan_instance_get[2], float)

        self.assertIsInstance(scan_instance_get[3], float)

        self.assertIsInstance(scan_instance_get[4], float)

        self.assertIsInstance(scan_instance_get[5], str)
        self.assertEqual(scan_instance_get[5], 'CREATED')

    def test_scanInstanceGet_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanInstanceGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanInstanceGet(invalid_type)

    def test_scanResultSummary_should_return_a_list(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_results_summary = sfdb.scanResultSummary(instance_id, "type")
        self.assertIsInstance(scan_results_summary, list)

    def test_scanResultSummary_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultSummary(invalid_type)

    def test_scanResultSummary_argument_by_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultSummary(instance_id, invalid_type)

        with self.assertRaises(ValueError):
            sfdb.scanResultSummary(instance_id, "invalid filter type")

    def test_scanResultSummary_argument_by_invalid_value_should_raise_ValueError(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        with self.assertRaises(ValueError):
            sfdb.scanResultSummary(instance_id, "invalid filter type")

    def test_scanResultEvent_should_return_a_list(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_event = sfdb.scanResultEvent(instance_id, "", False)
        self.assertIsInstance(scan_result_event, list)

    def test_scanResultEvent_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ALL'
        filter_fp = None

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultEvent(invalid_type, event_type, filter_fp)

    def test_scanResultEvent_argument_eventType_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultEvent(instance_id, invalid_type, None)

    def test_scanResultEventUnique_should_return_a_list(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_event = sfdb.scanResultEventUnique(instance_id, "", False)
        self.assertIsInstance(scan_result_event, list)

    def test_scanResultEventUnique_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ALL'
        filter_fp = None

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultEventUnique(invalid_type, event_type, filter_fp)

    def test_scanResultEventUnique_argument_eventType_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultEventUnique(instance_id, invalid_type, None)

    def test_scanLogs_should_return_a_list(self):
        """
        Test scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_logs = sfdb.scanLogs(instance_id, None, None, None)
        self.assertIsInstance(scan_logs, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanLogs_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        limit = None
        from_row_id = None
        reverse = None

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanLogs(invalid_type, limit, from_row_id, reverse)

    def test_scanErrors_should_return_a_list(self):
        """
        Test scanErrors(self, instanceId, limit=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        instance_id = "example instance id"
        scan_instance = sfdb.scanErrors(instance_id)
        self.assertIsInstance(scan_instance, list)

    def test_scanErrors_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanErrors(self, instanceId, limit=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanErrors(invalid_type)

    def test_scanInstanceDelete(self):
        """
        Test scanInstanceDelete(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        instance_id = "example instance id"
        sfdb.scanInstanceDelete(instance_id)

        self.assertEqual('TBD', 'TBD')

    def test_scanInstanceDelete_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanInstanceDelete(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanInstanceDelete(invalid_type)

    @unittest.skip("todo")
    def test_scanResultsUpdateFP(self):
        """
        Test scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        result_hashes = None
        fp_flag = None
        sfdb.scanResultsUpdateFP(instance_id, result_hashes, fp_flag)

        self.assertEqual('TBD', 'TBD')

    def test_scanResultsUpdateFP_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        result_hashes = []
        fp_flag = None
        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultsUpdateFP(invalid_type, result_hashes, fp_flag)

    def test_scanResultsUpdateFP_argument_resultHashes_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        fp_flag = None
        invalid_types = [None, "", dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultsUpdateFP(instance_id, invalid_type, fp_flag)

    def test_configSet_should_set_config_opts(self):
        """
        Test configSet(self, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)
        opts = dict()
        opts['example'] = 'example non-default config opt'
        sfdb.configSet(opts)

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertIn('example', config)

        self.assertEqual('TBD', 'TBD')

    def test_configSet_argument_optmap_of_invalid_type_should_raise_TypeError(self):
        """
        Test configSet(self, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, "", list()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.configSet(invalid_type)

    def test_configGet_should_return_a_dict(self):
        """
        Test configGet(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        config = sfdb.configGet()
        self.assertIsInstance(config, dict)

    def test_configClear_should_clear_config(self):
        """
        Test configClear(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        opts = dict()
        opts['example'] = 'example non-default config opt'
        sfdb.configSet(opts)

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertIn('example', config)

        sfdb.configClear()

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertNotIn('example', config)

    def test_scanConfigSet_argument_optMap_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanConfigSet(self, id, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, ""]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanConfigSet(instance_id, invalid_type)

    def test_scanConfigSet_argument_instanceId_with_empty_value_should_raise_ValueError(self):
        """
        Test scanConfigSet(self, id, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)

        with self.assertRaises(ValueError):
            sfdb.scanConfigSet("", dict())

    def test_scanConfigGet_should_return_a_dict(self):
        """
        Test scanConfigGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_config = sfdb.scanConfigGet(instance_id)
        self.assertIsInstance(scan_config, dict)

    def test_scanConfigGet_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanConfigGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanConfigGet(invalid_type)

    def test_scanEventStore_should_store_a_scan_event(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        event = SpiderFootEvent(event_type, event_data, module, source_event)
        instance_id = "example instance id"
        sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event = ""
        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanEventStore(invalid_type, event)

    def test_scanEventStore_argument_instanceId_with_empty_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event = ""
        with self.assertRaises(ValueError):
            sfdb.scanEventStore("", event)

    def test_scanEventStore_argument_sfEvent_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanEventStore(instance_id, invalid_type)

    def test_scanEventStore_argument_sfEvent_with_invalid_eventType_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.eventType = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_eventType_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"

        with self.assertRaises(ValueError):
            event.eventType = ''
            sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_invalid_data_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.data = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_data_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"

        with self.assertRaises(ValueError):
            event.data = ''
            sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_invalid_module_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.module = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_module_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        with self.assertRaises(ValueError):
            event.module = ''
            sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_invalid_confidence_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.confidence = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_confidence_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.confidence = invalid_value
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_invalid_visibility_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.visibility = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_visibility_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.visibility = invalid_value
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_invalid_risk_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.risk = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_risk_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.risk = invalid_value
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_invalid_sourceEvent_property_type_should_raise_TypeError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.sourceEvent = invalid_type
                    sfdb.scanEventStore(instance_id, event)

    def test_scanInstanceList_should_return_a_list(self):
        """
        Test scanInstanceList(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instances = sfdb.scanInstanceList()
        self.assertIsInstance(scan_instances, list)

    def test_scanResultHistory_should_return_a_list(self):
        """
        Test scanResultHistory(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_history = sfdb.scanResultHistory(instance_id)
        self.assertIsInstance(scan_result_history, list)

    def test_scanResultHistory_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultHistory(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanResultHistory(invalid_type)

    def test_scanElementSourcesDirect_should_return_a_list(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        element_id_list = []
        scan_element_sources_direct = sfdb.scanElementSourcesDirect(instance_id, element_id_list)
        self.assertIsInstance(scan_element_sources_direct, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementSourcesDirect_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        element_id_list = []
        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementSourcesDirect(invalid_type, element_id_list)

    def test_scanElementSourcesDirect_argument_elementIdList_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementSourcesDirect(instance_id, invalid_type)

    def test_scanElementChildrenDirect_should_return_a_list(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_element_children_direct = sfdb.scanElementChildrenDirect(instance_id, list())
        self.assertIsInstance(scan_element_children_direct, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementChildrenDirect_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        element_id_list = []
        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementChildrenDirect(invalid_type, element_id_list)

    def test_scanElementChildrenDirect_argument_elementIdList_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementChildrenDirect(instance_id, invalid_type)

    def test_scanElementSourcesAll_should_return_a_list(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        child_data = ["example child", "example child"]
        scan_element_sources_all = sfdb.scanElementSourcesAll(instance_id, child_data)
        self.assertIsInstance(scan_element_sources_all, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementSourcesAll_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        child_data = []
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementSourcesAll(invalid_type, child_data)

    def test_scanElementSourcesAll_argument_childData_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementSourcesAll(instance_id, invalid_type)

    def test_scanElementSourcesAll_argument_childData_with_empty_value_should_raise_ValueError(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        child_data = []

        with self.assertRaises(ValueError):
            sfdb.scanElementSourcesAll(instance_id, child_data)

    def test_scanElementChildrenAll_should_return_a_list(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_element_children_all = sfdb.scanElementChildrenAll(instance_id, list())
        self.assertIsInstance(scan_element_children_all, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementChildrenAll_argument_instanceId_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        parent_ids = []
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementChildrenAll(invalid_type, parent_ids)

    def test_scanElementChildrenAll_argument_parentIds_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.scanElementChildrenAll(instance_id, invalid_type)

    def test_correlationResultCreate_arguments_of_invalid_type_should_raise_TypeError(self):
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate(invalid_type, "", "", "", "", "", "", [])

            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate("", invalid_type, "", "", "", "", "", [])

            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate("", "", invalid_type, "", "", "", "", [])

            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate("", "", "", invalid_type, "", "", "", [])

            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate("", "", "", "", invalid_type, "", "", [])

            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate("", "", "", "", "", invalid_type, "", [])

            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfdb.correlationResultCreate("", "", "", "", "", "", invalid_type, [])

    def test_schema_foreign_keys_reference_existing_tables(self):
        """All schema FOREIGN KEY clauses must reference a table the schema creates.

        Regression test for the 'tbl_scan_instances' (plural) typo in
        tbl_scan_correlation_results: it referenced a table that does not exist
        and would break every correlation-result insert if SQLite foreign-key
        enforcement were ever enabled.
        """
        import sqlite3

        conn = sqlite3.connect(":memory:")
        try:
            cur = conn.cursor()
            for query in SpiderFootDb.createSchemaQueries:
                cur.execute(query)
            conn.commit()

            cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            tables = {row[0] for row in cur.fetchall()}

            dangling = []
            for table in tables:
                for fk in cur.execute(f"PRAGMA foreign_key_list('{table}')").fetchall():
                    referenced_table = fk[2]
                    if referenced_table not in tables:
                        dangling.append((table, referenced_table))

            self.assertEqual(
                dangling,
                [],
                f"Schema has foreign keys referencing non-existent tables: {dangling}",
            )
        finally:
            conn.close()

    def test_scanInstanceDelete_removes_correlation_results(self):
        """Deleting a scan must also remove its correlation results and the
        correlation->event mappings, rather than orphaning them in the database.
        """
        import contextlib

        sfdb = SpiderFootDb(self.default_options, False)
        scan_id = "test-delete-correlations-cleanup"

        with contextlib.suppress(Exception):
            sfdb.scanInstanceDelete(scan_id)

        sfdb.scanInstanceCreate(scan_id, "examplescan", "example.com")
        sfdb.correlationResultCreate(
            scan_id, "rule_id", "Rule Name", "descr", "INFO",
            "id: rule_id", "title", ["hash1", "hash2"],
        )
        self.assertTrue(
            len(sfdb.scanCorrelationList(scan_id)) >= 1,
            "correlation should exist before the scan is deleted",
        )

        sfdb.scanInstanceDelete(scan_id)

        self.assertEqual(
            sfdb.scanCorrelationList(scan_id),
            [],
            "correlation results were orphaned after deleting the scan",
        )

    def test_schema_has_correlation_llm_table_with_valid_fk(self):
        """The triage table must exist and its FK must reference a real table."""
        import sqlite3

        conn = sqlite3.connect(":memory:")
        try:
            cur = conn.cursor()
            for query in SpiderFootDb.createSchemaQueries:
                cur.execute(query)
            conn.commit()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cur.fetchall()}
            self.assertIn("tbl_scan_correlation_llm", tables)

            for fk in cur.execute("PRAGMA foreign_key_list('tbl_scan_correlation_llm')").fetchall():
                self.assertIn(fk[2], tables)
        finally:
            conn.close()

    def test_correlation_llm_create_and_list_roundtrip(self):
        """Triage rows can be written and read back for a scan."""
        import contextlib

        sfdb = SpiderFootDb(self.default_options, False)
        scan_id = "test-corr-llm-roundtrip"
        with contextlib.suppress(Exception):
            sfdb.scanInstanceDelete(scan_id)
        sfdb.scanInstanceCreate(scan_id, "examplescan", "example.com")
        corr_id = sfdb.correlationResultCreate(
            scan_id, "rule_id", "Rule Name", "descr", "INFO",
            "id: rule_id", "title", ["hash1"],
        )

        try:
            sfdb.correlationLlmCreate(corr_id, "HIGH", 1, "Because reasons.", "group-a", "test/model", 1700000000)
            rows = sfdb.scanCorrelationLlmList(scan_id)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row[0], corr_id)       # correlation_id
            self.assertEqual(row[1], "HIGH")        # priority
            self.assertEqual(row[2], 1)             # rank
            self.assertEqual(row[3], "Because reasons.")  # explanation
            self.assertEqual(row[4], "group-a")     # grp
            self.assertEqual(row[5], "test/model")  # model
        finally:
            with contextlib.suppress(Exception):
                sfdb.scanInstanceDelete(scan_id)
