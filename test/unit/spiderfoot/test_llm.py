import json
import unittest
from unittest.mock import patch, MagicMock

from spiderfoot.llm import OpenRouterClient, LLMError


class TestOpenRouterClient(unittest.TestCase):

    def _client(self, **kw):
        return OpenRouterClient(api_key="secret-key", model="test/model", **kw)

    def test_rejects_non_openrouter_base_url(self):
        with self.assertRaises(ValueError):
            OpenRouterClient(api_key="k", model="m", base_url="https://evil.example.com/v1")

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
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "upstream error"
        with patch("spiderfoot.llm.requests.post", return_value=resp):
            with self.assertRaises(LLMError):
                self._client(max_retries=0).chat("sys", "usr")

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
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "unauthorized"
        with patch("spiderfoot.llm.requests.post", return_value=resp):
            try:
                self._client(max_retries=0).chat("sys", "usr")
                self.fail("expected LLMError")
            except LLMError as e:
                self.assertNotIn("secret-key", str(e))
