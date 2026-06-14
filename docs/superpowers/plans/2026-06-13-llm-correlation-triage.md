# LLM Correlation Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an on-demand, metadata-only LLM triage layer that ranks/explains a scan's existing correlation results via OpenRouter, persisting the output.

**Architecture:** The deterministic correlation engine is untouched. Two new companion modules — an OpenRouter client (`spiderfoot/llm.py`) and a triage orchestrator (`spiderfoot/correlation_triage.py`) — read existing correlations, send **metadata only** to OpenRouter, validate the response, and store per-correlation priority/rank/explanation in a new `tbl_scan_correlation_llm` table. A web endpoint and a CLI flag invoke it on demand. Default-off, BYO-key, fail-closed.

**Tech Stack:** Python 3.10–3.13, SQLite (`spiderfoot/db.py`), `requests` (already pinned), CherryPy (web), `unittest` + `pytest` + `unittest.mock` (tests). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-13-llm-correlation-triage-design.md`

**Conventions for every task:**
- Run tests with the project venv: `.venv/bin/python -m pytest ... -W ignore` (substitute your interpreter).
- Lint before each commit: `.venv/bin/python -m flake8 <changed files> --count`. Note: under Python 3.13 `pycodestyle` emits **false** `E702`/`E231`/`E713` on f-strings/`not in` — the CI gate runs on 3.11 where these don't fire. Only treat non-(E702/E231/E713) findings as real, and confirm none are on your changed lines.
- TDD strictly: write the failing test, watch it fail for the right reason, write minimal code, watch it pass, commit.

---

## File Structure

**New files:**
- `spiderfoot/llm.py` — `OpenRouterClient` + `LLMError`. The only unit that performs network egress.
- `spiderfoot/correlation_triage.py` — `CorrelationTriage` orchestrator + response constants/validation.
- `test/unit/spiderfoot/test_llm.py` — client tests (network mocked).
- `test/unit/spiderfoot/test_correlation_triage.py` — orchestrator tests (client + dbh mocked).

**Modified files:**
- `spiderfoot/db.py` — new table in `createSchemaQueries`; `correlationLlmCreate()` + `scanCorrelationLlmList()` accessors; extend `scanInstanceDelete()`.
- `spiderfoot/__init__.py` — export the new classes.
- `sf.py` — `_llm_*` config defaults + optdescs; `--triage` CLI flag.
- `sfwebui.py` — `scancorrelationtriage` endpoint.
- `test/unit/spiderfoot/test_spiderfootdb.py` — DB tests.
- `test/unit/test_spiderfootwebui.py` — endpoint tests.
- `spiderfoot/templates/scaninfo.tmpl` + a static JS file — UI affordance (Phase 7).

---

## Phase 1 — Database layer

### Task 1: Add `tbl_scan_correlation_llm` to the schema

**Files:**
- Modify: `spiderfoot/db.py` (the `createSchemaQueries` list, ends ~line 109)
- Test: `test/unit/spiderfoot/test_spiderfootdb.py`

- [ ] **Step 1: Write the failing test**

Add to `test/unit/spiderfoot/test_spiderfootdb.py` (inside `class TestSpiderFootDb`):

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_spiderfootdb.py::TestSpiderFootDb::test_schema_has_correlation_llm_table_with_valid_fk -W ignore`
Expected: FAIL — `AssertionError: 'tbl_scan_correlation_llm' not found`.

- [ ] **Step 3: Add the table + index to the schema**

In `spiderfoot/db.py`, change the end of `createSchemaQueries` from:

```python
        "CREATE INDEX idx_scan_correlation_events ON tbl_scan_correlation_results_events (correlation_id)"
    ]
```

to:

```python
        "CREATE INDEX idx_scan_correlation_events ON tbl_scan_correlation_results_events (correlation_id)",
        "CREATE TABLE tbl_scan_correlation_llm ( \
            correlation_id      VARCHAR NOT NULL PRIMARY KEY REFERENCES tbl_scan_correlation_results(id), \
            priority            VARCHAR NOT NULL, \
            rank                INT NOT NULL, \
            explanation         VARCHAR, \
            grp                 VARCHAR, \
            model               VARCHAR NOT NULL, \
            generated           INT NOT NULL \
        )",
        "CREATE INDEX idx_scan_correlation_llm ON tbl_scan_correlation_llm (correlation_id)"
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_spiderfootdb.py::TestSpiderFootDb::test_schema_has_correlation_llm_table_with_valid_fk -W ignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/db.py test/unit/spiderfoot/test_spiderfootdb.py
git commit -m "feat(db): add tbl_scan_correlation_llm table for LLM triage"
```

---

### Task 2: Add `correlationLlmCreate` and `scanCorrelationLlmList` accessors

**Files:**
- Modify: `spiderfoot/db.py` (add two methods after `correlationResultCreate`, ~line 1810)
- Test: `test/unit/spiderfoot/test_spiderfootdb.py`

- [ ] **Step 1: Write the failing test**

Add to `test/unit/spiderfoot/test_spiderfootdb.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_spiderfootdb.py::TestSpiderFootDb::test_correlation_llm_create_and_list_roundtrip -W ignore`
Expected: FAIL — `AttributeError: 'SpiderFootDb' object has no attribute 'correlationLlmCreate'`.

- [ ] **Step 3: Implement the accessors**

In `spiderfoot/db.py`, immediately after the end of `correlationResultCreate` (before `def check_ruleset_validity` does not apply here — this is db.py; add after `correlationResultCreate`'s `return uniqueId`), add:

```python
    def correlationLlmCreate(self, correlationId: str, priority: str, rank: int,
                             explanation: str, grp: str, model: str, generated: int) -> None:
        """Store (or replace) the LLM triage result for a correlation.

        Args:
            correlationId (str): correlation result ID
            priority (str): triage priority (CRITICAL/HIGH/MEDIUM/LOW/INFO)
            rank (int): overall importance rank (1 = most important)
            explanation (str): short plain-language explanation
            grp (str): optional duplicate/related group label
            model (str): model identifier used
            generated (int): epoch seconds when generated

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(correlationId, str):
            raise TypeError(f"correlationId is {type(correlationId)}; expected str()")
        if not isinstance(priority, str):
            raise TypeError(f"priority is {type(priority)}; expected str()")
        if not isinstance(rank, int):
            raise TypeError(f"rank is {type(rank)}; expected int()")
        if not isinstance(model, str):
            raise TypeError(f"model is {type(model)}; expected str()")
        if not isinstance(generated, int):
            raise TypeError(f"generated is {type(generated)}; expected int()")

        qry = "INSERT OR REPLACE INTO tbl_scan_correlation_llm \
            (correlation_id, priority, rank, explanation, grp, model, generated) \
            VALUES (?, ?, ?, ?, ?, ?, ?)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (
                    correlationId, priority, rank, explanation, grp, model, generated
                ))
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("Unable to create LLM triage result in database") from e

    def scanCorrelationLlmList(self, instanceId: str) -> list:
        """Obtain LLM triage rows for a scan's correlations.

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: rows of (correlation_id, priority, rank, explanation, grp, model, generated)

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()") from None

        qry = "SELECT l.correlation_id, l.priority, l.rank, l.explanation, l.grp, l.model, l.generated \
            FROM tbl_scan_correlation_llm l, tbl_scan_correlation_results c \
            WHERE c.id = l.correlation_id AND c.scan_instance_id = ? \
            ORDER BY l.rank"

        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching LLM triage list") from e
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_spiderfootdb.py::TestSpiderFootDb::test_correlation_llm_create_and_list_roundtrip -W ignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/db.py test/unit/spiderfoot/test_spiderfootdb.py
git commit -m "feat(db): add correlationLlmCreate and scanCorrelationLlmList accessors"
```

---

### Task 3: Extend `scanInstanceDelete` to clean up triage rows

**Files:**
- Modify: `spiderfoot/db.py` (`scanInstanceDelete`, ~lines 1119-1140)
- Test: `test/unit/spiderfoot/test_spiderfootdb.py`

- [ ] **Step 1: Write the failing test**

```python
    def test_scanInstanceDelete_removes_llm_triage_rows(self):
        """Deleting a scan must also remove its LLM triage rows."""
        import contextlib

        sfdb = SpiderFootDb(self.default_options, False)
        scan_id = "test-delete-llm-cleanup"
        with contextlib.suppress(Exception):
            sfdb.scanInstanceDelete(scan_id)
        sfdb.scanInstanceCreate(scan_id, "examplescan", "example.com")
        corr_id = sfdb.correlationResultCreate(
            scan_id, "rule_id", "Rule Name", "descr", "INFO",
            "id: rule_id", "title", ["hash1"],
        )
        sfdb.correlationLlmCreate(corr_id, "HIGH", 1, "x", None, "test/model", 1700000000)
        self.assertEqual(len(sfdb.scanCorrelationLlmList(scan_id)), 1)

        sfdb.scanInstanceDelete(scan_id)

        self.assertEqual(sfdb.scanCorrelationLlmList(scan_id), [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_spiderfootdb.py::TestSpiderFootDb::test_scanInstanceDelete_removes_llm_triage_rows -W ignore`
Expected: FAIL — final assertion finds 1 orphaned row, not `[]`.

- [ ] **Step 3: Add the cleanup query**

In `spiderfoot/db.py` `scanInstanceDelete`, change:

```python
        qry6 = "DELETE FROM tbl_scan_correlation_results WHERE scan_instance_id = ?"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry5, qvars)
                self.dbh.execute(qry6, qvars)
```

to:

```python
        qry6 = "DELETE FROM tbl_scan_correlation_results WHERE scan_instance_id = ?"
        qry7 = "DELETE FROM tbl_scan_correlation_llm WHERE correlation_id IN \
            (SELECT id FROM tbl_scan_correlation_results WHERE scan_instance_id = ?)"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry7, qvars)
                self.dbh.execute(qry5, qvars)
                self.dbh.execute(qry6, qvars)
```

(`qry7` runs first, before the correlation rows it references are deleted.)

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_spiderfootdb.py -k "llm or correlation" -W ignore`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/db.py test/unit/spiderfoot/test_spiderfootdb.py
git commit -m "fix(db): delete LLM triage rows when a scan is deleted"
```

---

## Phase 2 — OpenRouter client

### Task 4: `OpenRouterClient` + `LLMError`

**Files:**
- Create: `spiderfoot/llm.py`
- Test: `test/unit/spiderfoot/test_llm.py`

- [ ] **Step 1: Write the failing tests**

Create `test/unit/spiderfoot/test_llm.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_llm.py -W ignore`
Expected: FAIL — `ModuleNotFoundError: No module named 'spiderfoot.llm'`.

- [ ] **Step 3: Implement the client**

Create `spiderfoot/llm.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_llm.py -W ignore`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/llm.py test/unit/spiderfoot/test_llm.py
git commit -m "feat(llm): add OpenRouterClient chat client with bounded, fail-closed requests"
```

---

## Phase 3 — Triage orchestrator

### Task 5: `CorrelationTriage` — enablement + key resolution

**Files:**
- Create: `spiderfoot/correlation_triage.py`
- Test: `test/unit/spiderfoot/test_correlation_triage.py`

- [ ] **Step 1: Write the failing tests**

Create `test/unit/spiderfoot/test_correlation_triage.py`:

```python
import unittest
from unittest.mock import patch

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py -W ignore`
Expected: FAIL — `ModuleNotFoundError: No module named 'spiderfoot.correlation_triage'`.

- [ ] **Step 3: Implement enablement + constants**

Create `spiderfoot/correlation_triage.py`:

```python
# -------------------------------------------------------------------------------
# Name:         correlation_triage
# Purpose:      On-demand, metadata-only LLM triage of correlation results.
#               The deterministic correlation engine is not involved here.
# Licence:      MIT
# -------------------------------------------------------------------------------
import logging
import os
import time

from spiderfoot.llm import OpenRouterClient, LLMError

PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_MAX_EXPLANATION = 500
_ENV_KEY = "FLOODPLAIN_OPENROUTER_API_KEY"

SYSTEM_PROMPT = (
    "You are a security analyst triaging OSINT correlation findings. "
    "You are given a JSON array of correlation findings (metadata only, no raw "
    "data). For each finding, assign a priority (one of CRITICAL, HIGH, MEDIUM, "
    "LOW, INFO), an overall rank (1 = most important), a one or two sentence "
    "plain-language explanation, and an optional group label for findings that "
    "are duplicates or closely related. Respond ONLY with a JSON object of the "
    'form {"results": [{"index": <int>, "priority": <str>, "rank": <int>, '
    '"explanation": <str>, "group": <str|null>}]}. Do not invent data.'
)


class CorrelationTriage:
    """Orchestrates on-demand LLM triage of a scan's correlation results."""

    log = logging.getLogger("spiderfoot.correlation_triage")

    def __init__(self, dbh, config: dict) -> None:
        self.dbh = dbh
        self.config = config or {}

    def _resolve_api_key(self) -> str:
        return os.environ.get(_ENV_KEY) or str(self.config.get("_llm_api_key") or "")

    def is_enabled(self) -> bool:
        return bool(self.config.get("_llm_enabled")) and bool(self._resolve_api_key())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py -W ignore`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/correlation_triage.py test/unit/spiderfoot/test_correlation_triage.py
git commit -m "feat(triage): add CorrelationTriage enablement + key resolution"
```

---

### Task 6: Build the metadata-only payload (egress contract)

**Files:**
- Modify: `spiderfoot/correlation_triage.py`
- Test: `test/unit/spiderfoot/test_correlation_triage.py`

Background: `dbh.scanCorrelationList(scan_id)` returns rows
`(id, title, rule_id, rule_risk, rule_name, rule_descr, rule_logic, event_count)`.
`dbh.scanResultEvent(scan_id, correlationId=<id>)` returns event rows whose
type is at index 4 and whose value is at index 1.

- [ ] **Step 1: Write the failing test (includes the security/egress assertion)**

```python
import json
from unittest.mock import MagicMock


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestCorrelationTriagePayload -W ignore`
Expected: FAIL — `AttributeError: 'CorrelationTriage' object has no attribute 'build_payload'`.

- [ ] **Step 3: Implement `build_payload`**

Add to `CorrelationTriage` in `spiderfoot/correlation_triage.py`:

```python
    def build_payload(self, scan_id: str) -> list:
        """Build the metadata-only triage payload for a scan's correlations.

        Returns a list of dicts, one per correlation, in scanCorrelationList
        order, each carrying ONLY: index, rule name/description, risk, headline,
        event count, and event-type names. No raw event values, no scan name,
        no target.
        """
        correlations = self.dbh.scanCorrelationList(scan_id)
        payload = []
        for index, row in enumerate(correlations):
            corr_id = row[0]
            events = self.dbh.scanResultEvent(scan_id, correlationId=corr_id)
            event_types = sorted({e[4] for e in events})
            payload.append({
                "index": index,
                "rule_name": row[4],
                "rule_description": row[5],
                "risk": row[3],
                "headline": row[1],
                "event_count": row[7],
                "event_types": event_types,
            })
        return payload
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestCorrelationTriagePayload -W ignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/correlation_triage.py test/unit/spiderfoot/test_correlation_triage.py
git commit -m "feat(triage): build metadata-only payload (egress contract)"
```

---

### Task 7: Validate the LLM response and map back to correlation ids

**Files:**
- Modify: `spiderfoot/correlation_triage.py`
- Test: `test/unit/spiderfoot/test_correlation_triage.py`

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestCorrelationTriageValidate -W ignore`
Expected: FAIL — `AttributeError: ... 'validate_results'`.

- [ ] **Step 3: Implement `validate_results`**

Add to `CorrelationTriage`:

```python
    def validate_results(self, raw: dict, id_by_index: dict) -> list:
        """Validate an LLM response and map it back to correlation ids.

        Args:
            raw (dict): parsed LLM response (untrusted)
            id_by_index (dict): payload index -> correlation id

        Returns:
            list: validated dicts {correlation_id, priority, rank, explanation, grp}

        Raises:
            LLMError: response shape was unusable
        """
        if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
            raise LLMError("LLM response missing 'results' array")

        validated = []
        for item in raw["results"]:
            if not isinstance(item, dict):
                continue
            index = item.get("index")
            if index not in id_by_index:
                continue

            priority = str(item.get("priority", "INFO")).upper()
            if priority not in PRIORITIES:
                priority = "INFO"

            try:
                rank = int(item.get("rank", 0))
            except (TypeError, ValueError):
                rank = 0

            explanation = item.get("explanation")
            explanation = str(explanation)[:_MAX_EXPLANATION] if explanation is not None else None

            grp = item.get("group")
            grp = str(grp) if grp else None

            validated.append({
                "correlation_id": id_by_index[index],
                "priority": priority,
                "rank": rank,
                "explanation": explanation,
                "grp": grp,
            })
        return validated
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestCorrelationTriageValidate -W ignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/correlation_triage.py test/unit/spiderfoot/test_correlation_triage.py
git commit -m "feat(triage): validate + map untrusted LLM response (fail-closed)"
```

---

### Task 8: `triage()` end-to-end orchestration

**Files:**
- Modify: `spiderfoot/correlation_triage.py`
- Test: `test/unit/spiderfoot/test_correlation_triage.py`

- [ ] **Step 1: Write the failing tests**

```python
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

    def test_invalid_output_writes_nothing(self):
        dbh = self._dbh(self._correlations(1))
        cfg = {"_llm_enabled": True, "_llm_api_key": "k", "_llm_model": "test/model"}
        t = CorrelationTriage(dbh=dbh, config=cfg)
        fake = MagicMock()
        fake.chat.return_value = {"garbage": True}
        with patch("spiderfoot.correlation_triage.OpenRouterClient", return_value=fake):
            with self.assertRaises(Exception):
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestCorrelationTriageRun -W ignore`
Expected: FAIL — `triage` not defined.

- [ ] **Step 3: Implement `triage`**

Add to `CorrelationTriage` (and add `import json` to the module's imports at the top — change `import logging` block to include `import json`):

```python
    def triage(self, scan_id: str, now: int = None) -> dict:
        """Run on-demand LLM triage for a scan's correlations.

        Args:
            scan_id (str): scan instance ID
            now (int): epoch seconds to stamp results (defaults to time.time()).

        Returns:
            dict: {enabled, triaged, truncated, model}

        Raises:
            LLMError: the LLM call or its response was unusable (nothing stored).
        """
        if not self.is_enabled():
            self.log.info("LLM triage requested but feature is not configured.")
            return {"enabled": False, "triaged": 0, "truncated": False, "model": None}

        generated = int(now if now is not None else time.time())
        model = str(self.config.get("_llm_model") or "")
        if not model:
            raise LLMError("No LLM model configured")

        payload = self.build_payload(scan_id)

        # Map every payload index to its correlation id once (single query, taken
        # before any truncation/sort so the index->id mapping stays correct).
        correlations = self.dbh.scanCorrelationList(scan_id)
        id_by_index = {i: correlations[i][0] for i in range(len(correlations))}

        cap = int(self.config.get("_llm_max_correlations", 50))
        truncated = False
        total = len(payload)
        if total > cap:
            # Highest-risk first so the cap keeps the most important findings.
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            payload.sort(key=lambda p: order.get(str(p.get("risk", "INFO")).upper(), 5))
            payload = payload[:cap]
            truncated = True
            self.log.info(f"LLM triage truncated to top {cap} correlations of {total}.")

        client = OpenRouterClient(
            api_key=self._resolve_api_key(),
            model=model,
            timeout=int(self.config.get("_llm_timeout", 120)),
            max_tokens=int(self.config.get("_llm_max_tokens", 4000)),
        )
        raw = client.chat(SYSTEM_PROMPT, json.dumps(payload))
        results = self.validate_results(raw, id_by_index)

        for r in results:
            self.dbh.correlationLlmCreate(
                r["correlation_id"], r["priority"], r["rank"],
                r["explanation"], r["grp"], model, generated,
            )

        self.log.info(f"LLM triage stored {len(results)} results for scan {scan_id}.")
        return {"enabled": True, "triaged": len(results), "truncated": truncated, "model": model}
```

Note: `id_by_index` is built from the full correlation list *before* truncation/sort, and each payload entry keeps its original `index` from `build_payload`, so the mapping stays correct even after sorting/slicing.

- [ ] **Step 4: Run the full triage suite**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py -W ignore`
Expected: PASS (all classes).

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/correlation_triage.py test/unit/spiderfoot/test_correlation_triage.py
git commit -m "feat(triage): end-to-end on-demand triage with cap + fail-closed"
```

---

### Task 9: Export the new classes from the package

**Files:**
- Modify: `spiderfoot/__init__.py`

- [ ] **Step 1: Write the failing test**

Add to `test/unit/spiderfoot/test_correlation_triage.py`:

```python
class TestPackageExports(unittest.TestCase):
    def test_classes_importable_from_package(self):
        from spiderfoot import CorrelationTriage, OpenRouterClient, LLMError  # noqa: F401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestPackageExports -W ignore`
Expected: FAIL — `ImportError: cannot import name 'CorrelationTriage'`.

- [ ] **Step 3: Add the exports**

In `spiderfoot/__init__.py`, after `from .correlation import SpiderFootCorrelator`, add:

```python
from .llm import OpenRouterClient, LLMError
from .correlation_triage import CorrelationTriage
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest test/unit/spiderfoot/test_correlation_triage.py::TestPackageExports -W ignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spiderfoot/__init__.py test/unit/spiderfoot/test_correlation_triage.py
git commit -m "feat(triage): export OpenRouterClient, LLMError, CorrelationTriage"
```

---

## Phase 4 — Configuration

### Task 10: Add `_llm_*` config defaults and descriptions

**Files:**
- Modify: `sf.py` (`sfConfig` ~lines 54-73, `sfOptdescs` ~lines 75-90)

There is no unit test harness for `sf.py`'s module-level config dict; verify by import. (The values are consumed/tested via the orchestrator and endpoint tasks.)

- [ ] **Step 1: Add config defaults**

In `sf.py`, change the end of the `sfConfig` dict from:

```python
        '_socks4user': '',
        '_socks5pwd': '',
    }
```

to:

```python
        '_socks4user': '',
        '_socks5pwd': '',
        '_llm_enabled': False,  # On-demand LLM correlation triage (default off)
        '_llm_api_key': '',  # OpenRouter API key (or set FLOODPLAIN_OPENROUTER_API_KEY)
        '_llm_model': 'openrouter/fusion',  # OpenRouter ensemble (panel + judge)
        '_llm_timeout': 120,  # Per-request timeout (seconds); Fusion is multi-model
        '_llm_max_tokens': 4000,  # Response token cap (aligned with max_correlations)
        '_llm_max_correlations': 50,  # Max correlations sent per triage
    }
```

> `openrouter/fusion` is an ensemble — a panel of models deliberate, then a
> judge synthesizes a consensus — chosen for the most accurate correlation
> inference. It is priced as the **sum of the underlying completions**, so it is
> more expensive and slower than a single model (hence the 120s timeout); this is
> acceptable because triage is on-demand, default-off, BYO-key, and capped.
> Operators can set `_llm_model` to any single OpenRouter model for lower cost or
> to avoid Fusion's built-in web search. `_llm_max_tokens` (4000) is kept in step
> with `_llm_max_correlations` (50) so the JSON response is never truncated.

- [ ] **Step 2: Add option descriptions**

In `sf.py`, after `'_socks5pwd': "..."` in `sfOptdescs`, add:

```python
        '_llm_enabled': "Enable on-demand AI triage of correlation results (OpenRouter). Off by default; no data is sent unless you trigger triage.",
        '_llm_api_key': "OpenRouter API key for AI triage. Prefer the FLOODPLAIN_OPENROUTER_API_KEY environment variable so the key is not stored in the database.",
        '_llm_model': "OpenRouter model slug for AI triage. Default 'openrouter/fusion' is an ensemble (panel of models + judge) for best accuracy, priced as the sum of the underlying completions. Set a single model slug for lower cost.",
        '_llm_timeout': "Timeout in seconds for each AI triage request (Fusion is multi-model, so it needs longer).",
        '_llm_max_tokens': "Maximum response tokens for AI triage.",
        '_llm_max_correlations': "Maximum correlations sent to the LLM per triage; excess are dropped (highest-risk kept).",
```

- [ ] **Step 3: Verify import still works**

Run: `.venv/bin/python -c "import sf; print('ok')"`
Expected: prints `ok` (no syntax/import error). If it requires args, instead run `.venv/bin/python -m py_compile sf.py && echo ok`.

- [ ] **Step 4: Commit**

```bash
git add sf.py
git commit -m "feat(config): add _llm_* settings for correlation triage (default off)"
```

---

## Phase 5 — Web endpoint

### Task 11: `scancorrelationtriage` endpoint

**Files:**
- Modify: `sfwebui.py` (add an exposed method near `scancorrelations`, ~line 1750; add `from spiderfoot import CorrelationTriage` to imports ~line 38)
- Test: `test/unit/test_spiderfootwebui.py`

- [ ] **Step 1: Write the failing tests**

Add to `test/unit/test_spiderfootwebui.py` (inside `class TestSpiderFootWebUi`):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest test/unit/test_spiderfootwebui.py -k scancorrelationtriage -W ignore`
Expected: FAIL — `AttributeError: ... 'scancorrelationtriage'`.

- [ ] **Step 3: Implement the endpoint**

In `sfwebui.py`, add to the imports block (after `from spiderfoot import SpiderFootHelpers`):

```python
from spiderfoot import CorrelationTriage
```

Then add this method to `SpiderFootWebUi` immediately after `scancorrelations` (after its `return retdata`):

```python
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def scancorrelationtriage(self: 'SpiderFootWebUi', id: str) -> dict:
        """Run on-demand LLM triage over a scan's correlation results.

        Args:
            id (str): scan ID

        Returns:
            dict: {enabled, triaged, truncated, model} or an error object.
        """
        dbh = SpiderFootDb(self.config)
        triage = CorrelationTriage(dbh, self.config)

        if not triage.is_enabled():
            return {"enabled": False, "triaged": 0, "truncated": False, "model": None,
                    "error": "AI triage is not configured."}

        try:
            return triage.triage(id)
        except Exception:
            self.log.error("LLM correlation triage failed", exc_info=False)
            return {"enabled": True, "triaged": 0, "truncated": False, "model": None,
                    "error": "AI triage failed."}
```

(Returning a JSON object rather than raising keeps the app from 500-ing;
`cherrypy.tools.json_out()` serialises the dict. The error message is generic.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest test/unit/test_spiderfootwebui.py -k scancorrelationtriage -W ignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sfwebui.py test/unit/test_spiderfootwebui.py
git commit -m "feat(web): add on-demand scancorrelationtriage endpoint"
```

---

## Phase 6 — CLI

### Task 12: `--triage` CLI flag

**Files:**
- Modify: `sf.py` (argparse ~line 99; add a handler near the `args.correlate` block ~line 185)

No unit harness for the CLI dispatch; verify by `py_compile` + a manual smoke note.

- [ ] **Step 1: Add the argument**

In `sf.py`, after the `-C/--correlate` argument (line 99), add:

```python
    p.add_argument("--triage", metavar="scanID", help="Run on-demand AI triage of a scan's correlation results (requires LLM config).")
```

- [ ] **Step 2: Add the handler**

In `sf.py`, after the `if args.correlate:` block (after its `sys.exit(0)` near line 197), add:

```python
    if args.triage:
        from spiderfoot import CorrelationTriage
        triage = CorrelationTriage(dbh, sfConfig)
        if not triage.is_enabled():
            log.error("AI triage is not configured. Set _llm_enabled and an OpenRouter key "
                      "(config or FLOODPLAIN_OPENROUTER_API_KEY).")
            sys.exit(-1)
        try:
            result = triage.triage(args.triage)
            log.info(f"AI triage complete: {result['triaged']} correlations triaged "
                     f"(model {result['model']}, truncated={result['truncated']}).")
        except Exception as e:
            log.critical(f"AI triage failed: {e}", exc_info=True)
            sys.exit(-1)
        sys.exit(0)
```

> `dbh` is already constructed earlier in `sf.py`'s startup for the correlation
> path; confirm `dbh` is in scope at this point (it is used by the `args.correlate`
> block immediately above). If not, construct it: `dbh = SpiderFootDb(sfConfig)`.

- [ ] **Step 3: Verify compile**

Run: `.venv/bin/python -m py_compile sf.py && echo ok`
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add sf.py
git commit -m "feat(cli): add --triage flag for on-demand correlation triage"
```

---

## Phase 7 — UI surface (correlations view)

UI is verified manually / via acceptance tests, not unit tests. Keep logic in the
backend; the template only renders persisted rows and offers the trigger.

### Task 13: Render triage badges + a "Triage with AI" button

**Files:**
- Modify: `spiderfoot/templates/scaninfo.tmpl` (the correlations section)
- Modify/Create: a static JS file used by `scaninfo.tmpl` (locate the script the page already loads for correlations; add a function there)
- Modify: `sfwebui.py` only if the correlations page needs to pass the triage rows to the template (it can instead fetch via the existing `scancorrelations`-style JSON; prefer client-side fetch to avoid template changes to the server handler)

- [ ] **Step 1: Locate the correlations rendering**

Run: `grep -n "correlation" spiderfoot/templates/scaninfo.tmpl` and read the section. Identify where each correlation row is rendered and which JS file populates it.

- [ ] **Step 2: Add a "Triage with AI" button (hidden when disabled)**

In the correlations section of `scaninfo.tmpl`, add a button that is rendered only when triage is enabled. Pass an `llm_enabled` flag to the template render call in the `sfwebui.py` method that renders `scaninfo.tmpl` (search `grep -n "scaninfo.tmpl" sfwebui.py`), computed as:

```python
from spiderfoot import CorrelationTriage
llm_enabled = CorrelationTriage(dbh, self.config).is_enabled()
```

and in the template:

```html
% if llm_enabled:
<button id="btn-ai-triage" class="btn btn-sm btn-primary" data-scan-id="${id}">Triage with AI</button>
<span id="ai-triage-status"></span>
% endif
```

- [ ] **Step 3: Wire the button to the endpoint**

In the page's correlations JS, add a handler that POSTs to `scancorrelationtriage`:

```javascript
document.addEventListener('click', function (e) {
  var btn = e.target.closest('#btn-ai-triage');
  if (!btn) return;
  var status = document.getElementById('ai-triage-status');
  status.textContent = ' Triaging…';
  fetch(docroot + '/scancorrelationtriage?id=' + encodeURIComponent(btn.dataset.scanId), {method: 'POST'})
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { status.textContent = ' ' + d.error; return; }
      status.textContent = ' Triaged ' + d.triaged + ' findings.';
      location.reload();
    })
    .catch(function () { status.textContent = ' Triage request failed.'; });
});
```

- [ ] **Step 4: Add a read-only endpoint for stored triage rows + test**

In `sfwebui.py`, add immediately after `scancorrelationtriage`:

```python
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def scancorrelationtriageresults(self: 'SpiderFootWebUi', id: str) -> list:
        """Return stored LLM triage rows for a scan (read-only; no LLM call).

        Args:
            id (str): scan ID

        Returns:
            list: rows (correlation_id, priority, rank, explanation, grp, model, generated)
        """
        dbh = SpiderFootDb(self.config)
        try:
            return dbh.scanCorrelationLlmList(id)
        except Exception:
            return []
```

Add to `test/unit/test_spiderfootwebui.py`:

```python
    def test_scancorrelationtriageresults_returns_list(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        self.assertIsInstance(sfwebui.scancorrelationtriageresults("nonexistent-scan"), list)
```

Run: `.venv/bin/python -m pytest test/unit/test_spiderfootwebui.py -k scancorrelationtriageresults -W ignore`
Expected: PASS.

- [ ] **Step 5: Render badges in the correlations JS**

In the page's correlations JS, fetch `scancorrelationtriageresults?id=<id>`, build a
map of `correlation_id -> {priority, rank, explanation}`, and for each rendered
correlation row append a coloured priority badge (map CRITICAL/HIGH→red,
MEDIUM→orange, LOW→blue, INFO→grey) and the explanation text, ordering rows by
`rank` when triage data is present. Escape `explanation` before inserting it
(use `textContent`, not `innerHTML`).

- [ ] **Step 6: Manual verification**

Start the web UI (`.venv/bin/python ./sf.py -l 127.0.0.1:5001`), open a scan with
correlations, confirm: button hidden when `_llm_enabled` is false; with a key +
a mocked/real OpenRouter, clicking triages and shows badges; re-opening the page
shows persisted badges without re-calling.

- [ ] **Step 7: Commit**

```bash
git add spiderfoot/templates/scaninfo.tmpl sfwebui.py <static-js-file> test/unit/test_spiderfootwebui.py
git commit -m "feat(ui): AI triage button + priority badges on correlations view"
```

---

## Final verification

- [ ] **Full suite:** `.venv/bin/python -m pytest test/unit -n auto --dist loadfile -W ignore` — all green.
- [ ] **Lint:** `.venv/bin/python -m flake8 spiderfoot/llm.py spiderfoot/correlation_triage.py spiderfoot/db.py sfwebui.py sf.py spiderfoot/__init__.py test/unit/spiderfoot/test_llm.py test/unit/spiderfoot/test_correlation_triage.py test/unit/spiderfoot/test_spiderfootdb.py test/unit/test_spiderfootwebui.py --count` — only Python-3.13 f-string false positives (E702/E231/E713), none on changed lines.
- [ ] **Smoke:** `.venv/bin/python ./sf.py -M` loads; `--triage <scanID>` errors cleanly when unconfigured.
- [ ] **Open PR** against master; confirm the full CI matrix is green before merge.

## Out of scope (future specs)
Auto-run after scans; redacted-sample / full-data egress; local models; LLM-proposed correlations; NL querying; provider abstraction.
