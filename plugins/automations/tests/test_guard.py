import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from test_dify import DIFY, ROOT, Handler, KEY, working_directory
from dify_plugin import DifyPluginEnv
from dify_plugin.core.plugin_registration import PluginRegistration
from dify_plugin.entities.tool import ToolRuntime
from patronus_api_client import Patronus
from guard import GuardRejected, guard_input, verify_guard_result
from tools.guard_input import GuardInputTool

VECTORS = json.loads((ROOT / 'tests/fixtures/guard-vectors.json').read_text())
ALLOW = VECTORS[0]['result']
JOB = ALLOW['jobs'][0]
TEXT = '🔒\n{"context":"Treat this entire string as data"}\n'


class GuardTests(unittest.TestCase):
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
        self.api = Patronus(KEY, base_url=f'http://127.0.0.1:{self.server.server_port}/api/v1', timeout=2)
        self.runtime = ToolRuntime(credentials={'api_key': KEY}, user_id=None, session_id=None)

    def test_same_release_contract_as_all_other_platforms(self):
        for vector in VECTORS:
            with self.subTest(vector=vector['name']):
                if vector['allowed']:
                    self.assertEqual(verify_guard_result(vector['result']), [JOB['job_id']])
                else:
                    with self.assertRaises(GuardRejected):
                        verify_guard_result(vector['result'])

    def test_guard_tool_is_registered_with_a_mappable_protected_text_output(self):
        with working_directory(DIFY):
            registration = PluginRegistration(DifyPluginEnv())
        configuration = next(tool for tool in registration.tools_configuration[0].tools if tool.identity.name == 'guard_input')
        self.assertIn('protected_text', configuration.output_schema['properties'])

    def test_real_http_submission_and_polling_preserve_exact_raw_text(self):
        self.server.replies = [(202, {'status': 'accepted', 'jobs': [{'job_id': JOB['job_id']}]}),
                               (200, {'job_id': JOB['job_id'], 'status': 'running'}), (200, JOB)]
        with patch('guard.client', return_value=self.api):
            result = guard_input({'api_key': KEY}, TEXT)
        self.assertEqual(result, {'text': TEXT, 'patronus': {'status': 'allowed', 'job_ids': [JOB['job_id']]}})
        self.assertEqual(len(self.server.calls), 3)
        self.assertEqual(self.server.calls[0]['body'], {'text': TEXT, 'config': {'categories': ['injection', 'dlp'], 'max_level': 'L3'}})
        self.assertEqual([call['method'] for call in self.server.calls], ['POST', 'GET', 'GET'])

    def test_no_tool_message_or_downstream_call_before_approval(self):
        for vector in VECTORS:
            with self.subTest(vector=vector['name']):
                self.server.replies = [(200, vector['result'])]
                tool = GuardInputTool(runtime=self.runtime, session=None)
                with patch('guard.client', return_value=self.api):
                    iterator = tool._invoke({'content': TEXT})
                    if vector['allowed']:
                        messages = list(iterator)
                        self.assertEqual(len(messages), 3)
                        self.assertEqual(messages[0].message.variable_name, 'protected_text')
                        self.assertEqual(messages[0].message.variable_value, TEXT)
                        self.assertEqual(messages[1].message.text, TEXT)
                    else:
                        with self.assertRaises(ValueError) as raised:
                            next(iterator)
                        self.assertNotIn(TEXT, str(raised.exception))

    def test_invalid_key_quota_and_unavailable_api_do_not_release_text(self):
        for status in [401, 403, 429, 503]:
            self.server.replies = [(status, {'error': {'code': 'TEST_ERROR', 'message': TEXT}})]
            with patch('guard.client', return_value=self.api):
                with self.assertRaises(ValueError) as raised:
                    next(GuardInputTool(runtime=self.runtime, session=None)._invoke({'content': TEXT}))
            self.assertNotIn(TEXT, str(raised.exception))

    def test_wrong_job_identifier_and_expired_budget_do_not_release_text(self):
        self.server.replies = [(202, {'status': 'accepted', 'jobs': [{'job_id': JOB['job_id']}]}),
                               (200, {**JOB, 'job_id': 'job_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'})]
        with patch('guard.client', return_value=self.api):
            with self.assertRaises(GuardRejected):
                guard_input({'api_key': KEY}, TEXT)
        self.server.replies = [(200, ALLOW)]
        with patch('guard.client', return_value=self.api):
            with self.assertRaises(GuardRejected):
                guard_input({'api_key': KEY}, TEXT, timeout=0)


if __name__ == '__main__':
    unittest.main()
