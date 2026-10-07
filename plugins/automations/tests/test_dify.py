import json
import os
import sys
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DIFY = ROOT / 'dify'
sys.path.insert(0, str(DIFY))

from dify_plugin import DifyPluginEnv
from dify_plugin.core.plugin_registration import PluginRegistration
from dify_plugin.entities.tool import ToolRuntime
from dify_plugin.errors.tool import ToolProviderCredentialValidationError
from patronus_api_client import Patronus
import client as adapter
from provider.patronus import PatronusProvider
from tools.submit_scan import SubmitScanTool
from tools.get_scan import GetScanTool

JOB = 'job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
KEY = 'automation-test-credential'
FLAT = json.loads((ROOT.parents[1] / 'contract/fixtures/completed-flat.json').read_text())
ACCEPTED = {'status': 'accepted', 'jobs': [{'job_id': JOB}]}


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def log_message(self, *args):
        pass

    def respond(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length).decode() if length else None
        self.server.calls.append({'method': self.command, 'path': self.path,
                                  'authorization': self.headers.get('Authorization'),
                                  'body': json.loads(body) if body else None})
        status, reply = self.server.replies.pop(0)
        data = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Retry-After', '7')
        self.end_headers()
        self.wfile.write(data)


class DifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.calls = []
        self.server.replies = []
        self.runtime = ToolRuntime(credentials={'api_key': KEY}, user_id=None, session_id=None)
        self.api = Patronus(KEY, base_url=f'http://127.0.0.1:{self.server.server_port}/api/v1', timeout=2)

    def test_native_registration_loads_manifest_provider_tools_and_assets(self):
        with working_directory(DIFY):
            registration = PluginRegistration(DifyPluginEnv())
        self.assertEqual(list(registration.tools_mapping), ['patronus'])
        self.assertEqual(len(registration.files), 1)
        self.assertEqual(registration.files[0].filename, 'icon.svg')

    def test_submission_is_real_http_with_auth_and_preserves_raw_text(self):
        self.server.replies = [(202, ACCEPTED)]
        tool = SubmitScanTool(runtime=self.runtime, session=None)
        with patch('tools.submit_scan.client', return_value=self.api):
            messages = list(tool._invoke({'kind': 'text', 'content': '{"a":"b"}'}))
        self.assertEqual(len(self.server.calls), 1)
        self.assertEqual(self.server.calls[0], {'method': 'POST', 'path': '/api/v1/scan',
                         'authorization': 'Bearer ' + KEY, 'body': {'text': '{"a":"b"}'}})
        self.assertEqual(messages[0].message.json_object, ACCEPTED)

    def test_flat_completed_submission_and_get_preserve_verdict(self):
        self.server.replies = [(200, FLAT), (200, {**FLAT, 'decision': 'block'})]
        with patch('tools.submit_scan.client', return_value=self.api):
            submitted = list(SubmitScanTool(runtime=self.runtime, session=None)._invoke({'content': 'hello'}))[0]
        self.assertEqual(submitted.message.json_object['jobs'][0]['decision'], 'allow')
        with patch('tools.get_scan.client', return_value=self.api):
            result = list(GetScanTool(runtime=self.runtime, session=None)._invoke({'job_id': JOB}))[0]
        self.assertEqual(result.message.json_object['decision'], 'block')
        self.assertEqual(self.server.calls[1]['method'], 'GET')
        self.assertEqual(self.server.calls[1]['path'], '/api/v1/scan/' + JOB)

    def test_running_and_failed_results_are_data_without_approval(self):
        for status in ['running', 'failed']:
            reply = {'job_id': JOB, 'status': status}
            self.server.replies = [(200, reply)]
            with patch('tools.get_scan.client', return_value=self.api):
                result = list(GetScanTool(runtime=self.runtime, session=None)._invoke({'job_id': JOB}))[0]
            self.assertEqual(result.message.json_object, reply)

    def test_connection_validation_is_read_only_and_rejects_auth_failures(self):
        provider = PatronusProvider()
        for status in [404, 401, 403, 429, 503]:
            self.server.replies = [(status, {'error': {'code': 'TEST_ERROR', 'message': KEY}})]
            with patch('client.client', return_value=self.api):
                if status == 404:
                    provider._validate_credentials({'api_key': KEY})
                else:
                    with self.assertRaises(ToolProviderCredentialValidationError) as raised:
                        provider._validate_credentials({'api_key': KEY})
                    self.assertNotIn(KEY, str(raised.exception))
            self.assertEqual(self.server.calls[-1]['method'], 'GET')
            self.assertEqual(self.server.calls[-1]['path'], '/api/v1/scan/' + adapter.AUTH_PROBE_JOB)

    def test_invalid_identifiers_do_not_make_requests(self):
        with patch('tools.get_scan.client', return_value=self.api):
            with self.assertRaises(ValueError):
                list(GetScanTool(runtime=self.runtime, session=None)._invoke({'job_id': '../account'}))
        self.assertEqual(self.server.calls, [])

    def test_url_and_mcp_payloads_and_validation(self):
        self.assertEqual(adapter.scan_body('url', 'https://example.com'), {'url': 'https://example.com'})
        self.assertEqual(adapter.scan_body('mcp', 'https://example.com/mcp'), {'mcp_server_url': 'https://example.com/mcp'})
        for kind, content in [('text', ' '), ('url', 'http://example.com'), ('mcp', 'https://user:pass@example.com'), ('other', 'hello')]:
            with self.assertRaises(ValueError):
                adapter.scan_body(kind, content)

    def test_sdk_is_bundled_unchanged_from_the_authoritative_source(self):
        source = ROOT.parents[1] / 'sdk/python/src/patronus_api_client'
        for file in source.glob('*.py'):
            self.assertEqual(file.read_bytes(), (DIFY / 'patronus_api_client' / file.name).read_bytes())


if __name__ == '__main__':
    unittest.main()
