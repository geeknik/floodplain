# test_spiderfootwebui.py
import pytest
import unittest

from sfwebui import SpiderFootWebUi


@pytest.mark.usefixtures
class TestSpiderFootWebUi(unittest.TestCase):
    """
    Test SpiderFootWebUi
    """

    def test_init_config_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, config, web_config)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        with self.assertRaises(TypeError):
            SpiderFootWebUi(None, opts)

    def test_init_no_web_config_should_raise(self):
        """
        Test __init__(self, config, web_config)
        """
        with self.assertRaises(TypeError):
            SpiderFootWebUi(self.web_default_options, None)

        with self.assertRaises(ValueError):
            SpiderFootWebUi(self.web_default_options, dict())

    def test_init(self):
        """
        Test __init__(self, config)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        self.assertIsInstance(sfwebui, SpiderFootWebUi)

    def test_error_page(self):
        """
        Test error_page(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        sfwebui.error_page()

    def test_error_page_401(self):
        """
        Test error_page(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        error_page_401 = sfwebui.error_page_401(None, None, None, None)
        self.assertIsInstance(error_page_401, str)

    def test_error_page_404(self):
        """
        Test error_page_404(self, status, message, traceback, version)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        error_page_404 = sfwebui.error_page_404(None, None, None, None)
        self.assertIsInstance(error_page_404, str)

    def test_clean_user_input_should_return_a_list(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        clean_user_input = sfwebui.cleanUserInput(list())
        self.assertIsInstance(clean_user_input, list)

    def test_clean_user_input_invalid_input_should_raise(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfwebui.cleanUserInput(invalid_type)

    def test_clean_user_input_should_clean_user_input(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        clean_input = sfwebui.cleanUserInput([
            "<p>some HTML with \"some quotes\" & some JavaScript\n<script>alert('JavaScript')</script></p>",
            "Some more input. This function accepts a list"
        ])
        self.assertIsInstance(clean_input, list)
        self.assertEqual(clean_input, [
            '&lt;p&gt;some HTML with "some quotes" & some JavaScript\n&lt;script&gt;alert(&#x27;JavaScript&#x27;)&lt;/script&gt;&lt;/p&gt;',
            "Some more input. This function accepts a list"
        ])

    def test_search_base_should_return_a_list(self):
        """
        Test searchBase(self, id=None, eventType=None, value=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.searchBase(None, None, None)
        self.assertIsInstance(search_results, list)

        search_results = sfwebui.searchBase(None, None, "//")
        self.assertIsInstance(search_results, list)

    @unittest.skip("todo")
    def test_scan_correlations_export(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = ""
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scancorrelationsexport(scan_id, "csv", "excel")
        self.assertIsInstance(search_results, bytes)
        search_results = sfwebui.scancorrelationsexport(scan_id, "xlxs", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_event_result_export_should_return_bytes(self):
        """
        Test scaneventresultexport(self, id, type, filetype="csv", dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scaneventresultexport("", "")
        self.assertIsInstance(search_results, bytes)
        search_results = sfwebui.scaneventresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_event_result_export_multi(self):
        """
        Test scaneventresultexportmulti(self, ids, filetype="csv", dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scaneventresultexportmulti("", "")
        self.assertIsInstance(search_results, bytes)
        search_results = sfwebui.scaneventresultexportmulti("", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_search_result_export(self):
        """
        Test scansearchresultexport(self, id, eventType=None, value=None, filetype="csv", dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scansearchresultexport("")
        self.assertIsInstance(search_results, bytes)
        search_results = sfwebui.scansearchresultexport("", None, None, "excel")
        self.assertIsInstance(search_results, bytes)

    def test_scan_export_logs_invalid_scan_id_should_return_string(self):
        """
        Test scanexportlogs(self: 'SpiderFootWebUi', id: str, dialect: str = "excel") -> str
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        logs = sfwebui.scanexportlogs(None, "excel")
        self.assertIsInstance(logs, str)
        self.assertIn("Scan ID not found.", logs)

    @unittest.skip("todo")
    def test_scan_export_logs_should_return_bytes(self):
        """
        Test scanexportlogs(self: 'SpiderFootWebUi', id: str, dialect: str = "excel") -> str
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        logs = sfwebui.scanexportlogs("scan id", "excel")
        self.assertIsInstance(logs, bytes)

    @unittest.skip("todo")
    def test_scan_export_json_multi(self):
        """
        Test scanexportjsonmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scanexportjsonmulti(None)
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_viz_should_return_a_string(self):
        """
        Test scanviz(self, id, gexf="0")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_viz = sfwebui.scanviz(None, None)
        self.assertIsInstance(scan_viz, str)

    @unittest.skip("todo")
    def test_scan_viz_multi_should_return_a_string(self):
        """
        Test scanvizmulti(self, ids, gexf="1")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_viz_multi = sfwebui.scanvizmulti(None, None)
        self.assertIsInstance(scan_viz_multi, str)

    def test_scanopts_should_return_dict(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_opts = sfwebui.scanopts("example scan instance")
        self.assertIsInstance(scan_opts, dict)
        self.assertEqual(scan_opts, dict())

    def test_rerunscan_invalid_scan_id_should_return_error(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        rerunscan = sfwebui.rerunscan("example scan instance")
        self.assertIsInstance(rerunscan, str)
        self.assertIn("Invalid scan ID", rerunscan)

    @unittest.skip("todo")
    def test_rerunscanmulti(self):
        """
        Test rerunscanmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        rerunscanmulti = sfwebui.rerunscanmulti("example scan instance")
        self.assertIsInstance(rerunscanmulti, str)

    @unittest.skip("todo")
    def test_newscan(self):
        """
        Test newscan(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_clonescan(self):
        """
        Test clonescan(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        clone_scan = sfwebui.clonescan("example scan instance")
        self.assertIsInstance(clone_scan, str)

    def test_index(self):
        """
        Test index(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        index = sfwebui.index()
        self.assertIsInstance(index, str)

    def test_scaninfo(self):
        """
        Test scaninfo(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_info = sfwebui.scaninfo("example scan instance")
        self.assertIsInstance(scan_info, str)

    def test_opts(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        opts['__globaloptdescs__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        opts_page = sfwebui.opts()
        self.assertIsInstance(opts_page, str)
        self.assertIn('Settings', opts_page)

    def test_optsexport_should_return_a_string(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        opts_export = sfwebui.optsexport(None)
        self.assertIsInstance(opts_export, str)

    def test_optsraw_should_return_a_list(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        opts_raw = sfwebui.optsraw()
        self.assertIsInstance(opts_raw, list)
        self.assertEqual(opts_raw[0], 'SUCCESS')

    def test_error(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        message = "example message"
        scan_error = sfwebui.error(message)
        self.assertIsInstance(scan_error, str)
        self.assertIn("example message", scan_error)

    def test_scandelete_invalid_scanid_should_return_an_error(self):
        """
        Test scandelete(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_delete = sfwebui.scandelete("example scan id")
        self.assertIsInstance(scan_delete, dict)
        self.assertEqual("Scan example scan id does not exist", scan_delete.get('error').get('message'))

    def test_savesettings_invalid_csrf_token_should_return_an_error(self):
        """
        Test savesettings(self, allopts, token, configFile=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        save_settings = sfwebui.savesettings(None, "invalid token", None)
        self.assertIsInstance(save_settings, str)
        self.assertIn("Invalid token", save_settings)

    @unittest.skip("todo")
    def test_savesettings(self):
        self.assertEqual('TBD', 'TBD')

    def test_savesettingsraw_invalid_csrf_token_should_return_an_error(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        save_settings_raw = sfwebui.savesettingsraw(None, "invalid token")
        self.assertIsInstance(save_settings_raw, bytes)
        self.assertIn(b"Invalid token", save_settings_raw)

    @unittest.skip("todo")
    def test_savesettingsraw(self):
        self.assertEqual('TBD', 'TBD')

    def test_reset_settings_should_return_true(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        reset_settings = sfwebui.reset_settings()
        self.assertIsInstance(reset_settings, bool)
        self.assertTrue(reset_settings)

    @unittest.skip("todo")
    def test_result_set_fp(self):
        """
        Test resultsetfp(self, id, resultids, fp)
        """
        self.assertEqual('TBD', 'TBD')

    def test_eventtypes_should_return_list(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        event_types = sfwebui.eventtypes()
        self.assertIsInstance(event_types, list)

    def test_modules_should_return_list(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        modules = sfwebui.modules()
        self.assertIsInstance(modules, list)

    def test_correlationrules_should_return_list(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        correlationrules = sfwebui.correlationrules()
        self.assertIsInstance(correlationrules, list)

    def test_ping_should_return_list(self):
        """
        Test ping(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        ping = sfwebui.ping()
        self.assertIsInstance(ping, list)
        self.assertEqual(ping[0], 'SUCCESS')

    def test_query_should_perform_sql_query(self):
        """
        Test query(self, query)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        select = "12345"
        query = sfwebui.query(f"SELECT {select}")
        self.assertIsInstance(query, list)
        self.assertEqual(len(query), 1)
        self.assertEqual(str(query[0].get(select)), str(select))

    def test_query_invalid_query_should_return_error(self):
        """
        Test query(self, query)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        query = sfwebui.query(None)
        self.assertIsInstance(query, dict)
        self.assertEqual("Invalid query.", query.get('error').get('message'))

        query = sfwebui.query("UPDATE 1")
        self.assertIsInstance(query, dict)
        self.assertEqual("Non-SELECTs are unpredictable and not recommended.", query.get('error').get('message'))

    @unittest.skip("todo")
    def test_start_scan_should_start_a_scan(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        start_scan = sfwebui.startscan('example scan name', 'spiderfoot.net', 'example module list', None, None)
        self.assertEqual(start_scan, start_scan)
        self.assertEqual('TBD', 'TBD')

    def test_start_scan_invalid_scanname_should_return_error(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        start_scan = sfwebui.startscan(None, 'example scan target', None, None, None)
        self.assertIn('Invalid request: scan name was not specified.', start_scan)
        start_scan = sfwebui.startscan('', 'example scan target', None, None, None)
        self.assertIn('Invalid request: scan name was not specified.', start_scan)

    def test_start_scan_invalid_scantarget_should_return_error(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        start_scan = sfwebui.startscan('example scan name', None, None, None, None)
        self.assertIn('Invalid request: scan target was not specified.', start_scan)
        start_scan = sfwebui.startscan('example scan name', '', None, None, None)
        self.assertIn('Invalid request: scan target was not specified.', start_scan)

    def test_start_scan_unrecognized_scantarget_type_should_return_error(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        start_scan = sfwebui.startscan('example scan name', 'example scan target', 'example module list', None, None)
        self.assertIn('Invalid target type. Could not recognize it as a target SpiderFoot supports.', start_scan)

    def test_start_scan_invalid_modules_should_return_error(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        start_scan = sfwebui.startscan('example scan name', 'spiderfoot.net', None, None, None)
        self.assertIn('Invalid request: no modules specified for scan.', start_scan)
        start_scan = sfwebui.startscan('example scan name', 'spiderfoot.net', '', '', '')
        self.assertIn('Invalid request: no modules specified for scan.', start_scan)

    def test_start_scan_invalid_typelist_should_return_error(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        start_scan = sfwebui.startscan('example scan name', 'spiderfoot.net', None, 'invalid type list', None)
        self.assertIn('Invalid request: no modules specified for scan.', start_scan)
        start_scan = sfwebui.startscan('example scan name', 'spiderfoot.net', '', 'invalid type list', '')
        self.assertIn('Invalid request: no modules specified for scan.', start_scan)

    def test_stopscan_invalid_scanid_should_return_an_error(self):
        """
        Test stopscan(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        stop_scan = sfwebui.stopscan("example scan id")
        self.assertIsInstance(stop_scan, dict)
        self.assertEqual("Scan example scan id does not exist", stop_scan.get('error').get('message'))

    def test_scanlog_should_return_a_list(self):
        """
        Test scanlog(self, id, limit=None, rowId=None, reverse=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_log = sfwebui.scanlog(None, None, None, None)
        self.assertIsInstance(scan_log, list)
        scan_log = sfwebui.scanlog('', '', '', '')
        self.assertIsInstance(scan_log, list)

    def test_scanerrors_should_return_a_list(self):
        """
        Test scanerrors(self, id, limit=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_errors = sfwebui.scanerrors(None, None)
        self.assertIsInstance(scan_errors, list)
        scan_errors = sfwebui.scanerrors('', '')
        self.assertIsInstance(scan_errors, list)

    def test_scanlist_should_return_a_list(self):
        """
        Test scanlist(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_list = sfwebui.scanlist()
        self.assertIsInstance(scan_list, list)

    def test_scanstatus_should_return_a_list(self):
        """
        Test scanstatus(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_status = sfwebui.scanstatus("example scan instance")
        self.assertIsInstance(scan_status, list)

    def test_scansummary_should_return_a_list(self):
        """
        Test scansummary(self, id, by)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_summary = sfwebui.scansummary(None, None)
        self.assertIsInstance(scan_summary, list)
        scan_summary = sfwebui.scansummary('', '')
        self.assertIsInstance(scan_summary, list)

    def test_scaneventresults_should_return_a_list(self):
        """
        Test scaneventresults(self, id, eventType, filterfp=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_results = sfwebui.scaneventresults(None, None, None)
        self.assertIsInstance(scan_results, list)
        scan_results = sfwebui.scaneventresults('', '', '')
        self.assertIsInstance(scan_results, list)

    def test_scaneventresultsunique_should_return_a_list(self):
        """
        Test scaneventresultsunique(self, id, eventType, filterfp=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_results = sfwebui.scaneventresultsunique(None, None, None)
        self.assertIsInstance(scan_results, list)
        scan_results = sfwebui.scaneventresultsunique('', '', '')
        self.assertIsInstance(scan_results, list)

    def test_search_should_return_a_list(self):
        """
        Test search(self, id=None, eventType=None, value=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.search(None, None, None)
        self.assertIsInstance(search_results, list)
        search_results = sfwebui.search('', '', '')
        self.assertIsInstance(search_results, list)

    def test_scan_history_missing_scanid_should_return_error(self):
        """
        Test scanhistory(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        scan_history = sfwebui.scanhistory(None)
        self.assertIsInstance(scan_history, dict)
        self.assertEqual("No scan specified", scan_history.get('error').get('message'))
        scan_history = sfwebui.scanhistory("example scan id")
        self.assertIsInstance(scan_history, list)

    def test_scan_history_should_return_a_list(self):
        """
        Test scanhistory(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_history = sfwebui.scanhistory("example scan id")
        self.assertIsInstance(scan_history, list)

    def test_scan_element_type_discovery_should_return_a_dict(self):
        """
        Test scanelementtypediscovery(self, id, eventType)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_element_type_discovery = sfwebui.scanelementtypediscovery(None, None)
        self.assertIsInstance(scan_element_type_discovery, dict)
        scan_element_type_discovery = sfwebui.scanelementtypediscovery('', '')
        self.assertIsInstance(scan_element_type_discovery, dict)

    def test_scancorrelationsexport_xlsx_uses_correct_file_extension(self):
        """Excel correlation export must yield a .xlsx file, not a misspelled .xlxs.

        Regression test for the '.xlxs' typo in the correlation export's
        Content-Disposition filename.
        """
        import contextlib

        import cherrypy
        from spiderfoot import SpiderFootDb

        opts = self.default_options
        opts['__modules__'] = dict()

        scan_id = "test-correlations-xlsx-extension"
        sfdb = SpiderFootDb(opts, False)
        with contextlib.suppress(Exception):
            sfdb.scanInstanceDelete(scan_id)
        sfdb.scanInstanceCreate(scan_id, "examplescan", "example.com")

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        try:
            result = sfwebui.scancorrelationsexport(scan_id, "xlsx")
            self.assertIsInstance(result, bytes)
            disposition = cherrypy.response.headers['Content-Disposition']
            self.assertIn(".xlsx", disposition)
            self.assertNotIn(".xlxs", disposition)
        finally:
            sfdb.scanInstanceDelete(scan_id)

    def test_scancorrelationsexport_csv_rule_name_column_holds_rule_name(self):
        """The 'Rule Name' column of the correlation export must contain the
        human-readable rule name (rule_name), not the machine rule id.

        Regression: scancorrelationsexport read row[2] (rule_id) for the
        'Rule Name' column; scanCorrelationList returns rule_name at row[4]."""
        import contextlib
        import csv as csvmod
        import io

        from spiderfoot import SpiderFootDb

        opts = self.default_options
        opts['__modules__'] = dict()

        scan_id = "test-correlations-rule-name-column"
        sfdb = SpiderFootDb(opts, False)
        with contextlib.suppress(Exception):
            sfdb.scanInstanceDelete(scan_id)
        sfdb.scanInstanceCreate(scan_id, "examplescan", "example.com")
        sfdb.correlationResultCreate(
            scan_id,
            "rule_machine_id",       # ruleId
            "Human Readable Rule",   # ruleName
            "rule description",      # ruleDescr
            "INFO",                  # ruleRisk
            "id: rule_machine_id",   # ruleYaml
            "Correlation headline",  # correlationTitle
            ["deadbeefcafef00d"],    # eventHashes
        )

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        try:
            result = sfwebui.scancorrelationsexport(scan_id, "csv")
            self.assertIsInstance(result, bytes)
            rows = list(csvmod.reader(io.StringIO(result.decode("utf-8"))))
            self.assertEqual(rows[0], ["Rule Name", "Correlation", "Risk", "Description"])
            self.assertGreaterEqual(len(rows), 2)
            for data_row in rows[1:]:
                self.assertEqual(data_row[0], "Human Readable Rule")
                self.assertEqual(data_row[1], "Correlation headline")
        finally:
            with contextlib.suppress(Exception):
                sfdb.scanInstanceDelete(scan_id)

    def test_scancorrelationsexport_malicious_scan_name_cannot_inject_headers(self):
        """A scan name containing CR/LF must not be able to inject headers into
        the Content-Disposition response header (CWE-113 / HTTP response
        splitting). The scan name is user-controlled at scan creation time."""
        import contextlib

        import cherrypy
        from spiderfoot import SpiderFootDb

        opts = self.default_options
        opts['__modules__'] = dict()

        scan_id = "test-correlations-header-injection"
        malicious_name = 'pwn\r\nSet-Cookie: injected=1\r\nX-Evil: "yes'
        sfdb = SpiderFootDb(opts, False)
        with contextlib.suppress(Exception):
            sfdb.scanInstanceDelete(scan_id)
        sfdb.scanInstanceCreate(scan_id, malicious_name, "example.com")

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        try:
            sfwebui.scancorrelationsexport(scan_id, "csv")
            disposition = cherrypy.response.headers['Content-Disposition']
            # No CR/LF -> cannot start a new header line (response splitting).
            self.assertNotIn("\r", disposition)
            self.assertNotIn("\n", disposition)
            # Single, properly-quoted filename token: the only double quotes are
            # the wrapping pair, so a quote in the name cannot break out and
            # inject extra parameters/headers.
            self.assertTrue(disposition.startswith("attachment"))
            self.assertEqual(disposition.count('"'), 2)
        finally:
            with contextlib.suppress(Exception):
                sfdb.scanInstanceDelete(scan_id)

    def test_build_content_disposition_neutralises_untrusted_filenames(self):
        """build_content_disposition() must neutralise CR/LF, quote breakout and
        path separators in untrusted download filenames (RFC 6266 / CWE-113)."""
        build = SpiderFootWebUi.build_content_disposition

        # CR/LF header-splitting payload: no raw newlines survive.
        out = build('a\r\nSet-Cookie: x=1.csv')
        self.assertNotIn("\r", out)
        self.assertNotIn("\n", out)
        self.assertTrue(out.startswith("attachment;"))

        # quote-breakout payload: only the wrapping quote pair remains.
        out = build('a"; attachment; filename="b.csv')
        self.assertEqual(out.count('"'), 2)
        self.assertNotIn("\r", out)
        self.assertNotIn("\n", out)

        # path separators do not survive in the legacy filename token.
        out = build('../../etc/passwd')
        legacy_token = out.split("filename*=")[0]
        self.assertNotIn("/", legacy_token)
        self.assertNotIn("\\", legacy_token)

        # a clean name is preserved verbatim in the legacy token.
        self.assertIn('filename="MyScan-SpiderFoot.csv"', build('MyScan-SpiderFoot.csv'))

        # empty / non-string input falls back to a safe default.
        self.assertIn('filename="export"', build(''))
        self.assertIn('filename="export"', build(None))

    def test_scancorrelationtriage_disabled_returns_not_configured(self):
        from unittest.mock import patch
        opts = self.default_options
        opts['__modules__'] = dict()
        opts['_llm_enabled'] = False
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        with patch("sfwebui.CorrelationTriage") as MockTriage:
            instance = MockTriage.return_value
            instance.is_enabled.return_value = False
            result = sfwebui.scancorrelationtriage("scan-x")
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("enabled"))

    def test_scancorrelationtriage_enabled_invokes_orchestrator(self):
        from unittest.mock import patch
        opts = self.default_options
        opts['__modules__'] = dict()
        opts['_llm_enabled'] = True
        opts['_llm_api_key'] = "k"
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        with patch("sfwebui.CorrelationTriage") as MockTriage:
            instance = MockTriage.return_value
            instance.is_enabled.return_value = True
            instance.triage.return_value = {"enabled": True, "triaged": 3, "truncated": False, "model": "m"}
            result = sfwebui.scancorrelationtriage("scan-x")
        instance.triage.assert_called_once_with("scan-x")
        self.assertEqual(result["triaged"], 3)
