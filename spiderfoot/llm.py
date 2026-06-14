# -------------------------------------------------------------------------------
# Name:         llm
# Purpose:      Minimal OpenRouter chat-completions client for LLM features.
#               This is the only module that performs LLM network egress.
# Licence:      MIT
# -------------------------------------------------------------------------------
import json
import logging
import re
import time
from urllib.parse import urlparse

import requests

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
_ALLOWED_HOST = "openrouter.ai"


class LLMError(Exception):
    """Raised when an LLM request fails or returns an unusable response."""


def _extract_json_object(content: str) -> dict:
    """Parse a JSON object from model content, tolerating fences/prose.

    Some models (notably openrouter/fusion) do not honor response_format and may
    wrap the JSON in a ```json fence or surrounding prose. Try a direct parse,
    then a fenced parse, then the outermost {...} slice.

    Args:
        content (str): raw message content returned by the model

    Returns:
        dict: parsed JSON object

    Raises:
        ValueError: no JSON object could be parsed.
    """
    if not isinstance(content, str):
        raise ValueError("content is not a string")

    candidates = [content.strip()]

    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", content, re.DOTALL)
    if fence:
        candidates.append(fence.group(1).strip())

    start, end = content.find("{"), content.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidates.append(content[start:end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("no JSON object found in content")


class OpenRouterClient:
    """Minimal client for the OpenRouter chat-completions API.

    Attributes are read-only after construction. The API key is never logged
    and never included in raised exceptions.
    """

    log = logging.getLogger("spiderfoot.llm")

    def __init__(self, api_key: str, model: str, *,
                 base_url: str = DEFAULT_BASE_URL, timeout: int = 30,
                 max_tokens: int = 2000, max_retries: int = 2) -> None:
        if not isinstance(api_key, str) or not api_key:
            raise ValueError("api_key must be a non-empty string")
        if not isinstance(model, str) or not model:
            raise ValueError("model must be a non-empty string")

        host = (urlparse(base_url).hostname or "").lower()
        if host != _ALLOWED_HOST and not host.endswith("." + _ALLOWED_HOST):
            raise ValueError("base_url host is not an OpenRouter endpoint")

        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = int(timeout)
        self.max_tokens = int(max_tokens)
        self.max_retries = int(max_retries)

    def chat(self, system: str, user: str) -> dict:
        """Send one chat completion and return the parsed JSON object content.

        Args:
            system (str): system prompt
            user (str): user prompt (the data payload)

        Returns:
            dict: parsed JSON object from the model's message content

        Raises:
            LLMError: request failed, non-2xx, timed out, or response was not
                a JSON object.
        """
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        last_status = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.post(url, headers=headers, json=body, timeout=self.timeout)
            except requests.RequestException as e:
                self.log.warning(f"LLM request error (attempt {attempt}): {type(e).__name__}")
                if attempt >= self.max_retries:
                    raise LLMError("LLM request failed (network error)") from None
                time.sleep(1 + attempt)
                continue

            last_status = resp.status_code
            if resp.status_code >= 500:
                self.log.warning(f"LLM upstream {resp.status_code} (attempt {attempt})")
                if attempt >= self.max_retries:
                    break
                time.sleep(1 + attempt)
                continue
            if resp.status_code < 200 or resp.status_code >= 300:
                raise LLMError(f"LLM request returned status {resp.status_code}")

            try:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = _extract_json_object(content)
            except (ValueError, KeyError, IndexError, TypeError) as e:
                raise LLMError(f"LLM response was not usable JSON ({type(e).__name__})") from None

            if not isinstance(parsed, dict):
                raise LLMError("LLM response JSON was not an object")

            self.log.info(f"LLM call ok: model={self.model} status={resp.status_code}")
            return parsed

        raise LLMError(f"LLM request failed after retries (last status {last_status})")
