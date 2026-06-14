import json
import unittest
from unittest.mock import patch, MagicMock

import requests

from spiderfoot.llm import OpenRouterClient, LLMError


class TestOpenRouterClient(unittest.TestCase):

    def _client(self, **kw):
        return OpenRouterClient(api_key="secret-key", model="test/model", **kw)

    def test_rejects_non_openrouter_base_url(self):
        with self.assertRaises(ValueError):
            OpenRouterClient(api_key="k", model="m", base_url="https://evil.example.com/v1")

    def test_rejects_non_https_base_url(self):
        with self.assertRaises(ValueError):
            OpenRouterClient(api_key="k", model="m", base_url="http://openrouter.ai/api/v1")

    def test_chat_sends_auth_and_returns_parsed_json(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({"results": [{"index": 0}]})}}]
        }
        with patch("spiderfoot.llm.requests.post", return_value=resp) as mock_post:
            out = self._client().chat("sys", "usr")

        self.assertEqual(out, {"results": [{"index": 0}]})
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer secret-key")
        self.assertEqual(kwargs["json"]["model"], "test/model")

    def test_chat_raises_LLMError_on_non_2xx(self):
        # 4xx must fail fast: no retry, no parse fall-through. The body is VALID
        # JSON so a regression that routed 4xx into the parse path would NOT
        # raise (and this test would catch it), and call_count pins no-retry.
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "bad request"
        resp.json.return_value = {"choices": [{"message": {"content": '{"results": []}'}}]}
        with patch("spiderfoot.llm.requests.post", return_value=resp) as mock_post:
            with self.assertRaises(LLMError):
                self._client(max_retries=2).chat("sys", "usr")
        self.assertEqual(mock_post.call_count, 1)

    def test_chat_raises_LLMError_on_non_json_content(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"choices": [{"message": {"content": "not json"}}]}
        with patch("spiderfoot.llm.requests.post", return_value=resp):
            with self.assertRaises(LLMError):
                self._client().chat("sys", "usr")

    def test_chat_extracts_json_from_markdown_fence(self):
        # Models like openrouter/fusion may wrap JSON in a ```json fence.
        content = "```json\n{\"results\": [{\"index\": 0}]}\n```"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"choices": [{"message": {"content": content}}]}
        with patch("spiderfoot.llm.requests.post", return_value=resp):
            out = self._client().chat("sys", "usr")
        self.assertEqual(out, {"results": [{"index": 0}]})

    def test_chat_extracts_json_object_from_surrounding_prose(self):
        content = "Here is the analysis:\n{\"results\": []}\nLet me know if you need more."
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"choices": [{"message": {"content": content}}]}
        with patch("spiderfoot.llm.requests.post", return_value=resp):
            out = self._client().chat("sys", "usr")
        self.assertEqual(out, {"results": []})

    def test_chat_error_does_not_leak_api_key(self):
        # 401 is a 4xx: fail fast (no retry, no parse fall-through). Valid JSON
        # body ensures a buggy fall-through would parse rather than raise.
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "unauthorized"
        resp.json.return_value = {"choices": [{"message": {"content": '{"results": []}'}}]}
        with patch("spiderfoot.llm.requests.post", return_value=resp) as mock_post:
            try:
                self._client(max_retries=2).chat("sys", "usr")
                self.fail("expected LLMError")
            except LLMError as e:
                self.assertNotIn("secret-key", str(e))
        self.assertEqual(mock_post.call_count, 1)

    def test_chat_retries_on_5xx(self):
        # 5xx is retryable: initial attempt + max_retries retries, then LLMError.
        resp = MagicMock()
        resp.status_code = 503
        resp.text = "service unavailable"
        with patch("spiderfoot.llm.time.sleep"):
            with patch("spiderfoot.llm.requests.post", return_value=resp) as mock_post:
                with self.assertRaises(LLMError):
                    self._client(max_retries=2).chat("sys", "usr")
        self.assertEqual(mock_post.call_count, 3)

    def test_chat_retries_on_network_error(self):
        # Network errors are retryable: initial attempt + max_retries retries.
        with patch("spiderfoot.llm.time.sleep"):
            with patch("spiderfoot.llm.requests.post",
                       side_effect=requests.ConnectionError("boom")) as mock_post:
                with self.assertRaises(LLMError):
                    self._client(max_retries=2).chat("sys", "usr")
        self.assertEqual(mock_post.call_count, 3)
