import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import sf


class TestWebServerAuthentication(unittest.TestCase):

    @staticmethod
    def server_config(host):
        return {
            'host': host,
            'port': 5001,
            'root': '/',
            'cors_origins': [],
        }

    def start_server(self, host, data_dir):
        with patch.object(sf.SpiderFootHelpers, 'dataPath', return_value=data_dir), \
                patch.object(sf.SpiderFootHelpers, 'dataFile',
                             side_effect=lambda current, legacy: os.path.join(data_dir, current)), \
                patch.object(sf.cherrypy.config, 'update'), \
                patch.object(sf.cherrypy_cors, 'install'), \
                patch.object(sf.cherrypy.engine.autoreload, 'unsubscribe'), \
                patch.object(sf, 'SpiderFootWebUi', return_value=object()), \
                patch.object(sf.cherrypy, 'quickstart') as quickstart:
            sf.start_web_server(self.server_config(host), {})

        return quickstart

    def test_non_loopback_without_password_is_rejected(self):
        with tempfile.TemporaryDirectory() as data_dir, \
                patch.dict(os.environ, {}, clear=True), \
                patch.object(sf.SpiderFootHelpers, 'dataPath', return_value=data_dir), \
                patch.object(sf.cherrypy, 'quickstart') as quickstart:
            with self.assertRaises(SystemExit) as context:
                sf.start_web_server(self.server_config('0.0.0.0'), {})

        self.assertEqual(-1, context.exception.code)
        quickstart.assert_not_called()

    def test_loopback_without_password_is_preserved(self):
        with tempfile.TemporaryDirectory() as data_dir, patch.dict(os.environ, {}, clear=True):
            quickstart = self.start_server('127.0.0.1', data_dir)

        quickstart.assert_called_once()

    def test_non_loopback_with_password_is_preserved(self):
        with tempfile.TemporaryDirectory() as data_dir, patch.dict(os.environ, {}, clear=True):
            pathlib.Path(data_dir, 'passwd').write_text('analyst:secret\n', encoding='utf-8')
            quickstart = self.start_server('0.0.0.0', data_dir)

        quickstart.assert_called_once()

    def test_explicit_development_override_is_preserved(self):
        with tempfile.TemporaryDirectory() as data_dir, \
                patch.dict(os.environ, {sf.INSECURE_LISTEN_ENV: '1'}, clear=True):
            quickstart = self.start_server('0.0.0.0', data_dir)

        quickstart.assert_called_once()

    def test_listener_classification_fails_closed(self):
        for host in ('127.0.0.1', '127.1.2.3', '::1'):
            with self.subTest(host=host):
                self.assertTrue(sf.is_loopback_listener(host))

        for host in ('0.0.0.0', '192.0.2.10', '::', 'localhost', 'example.test', '', None):
            with self.subTest(host=host):
                self.assertFalse(sf.is_loopback_listener(host))
