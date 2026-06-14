# Design: On-demand LLM correlation triage (OpenRouter)

> Status: **Approved (design)** — 2026-06-13. Drives the implementation plan.
> Scope: Floodplain correlation engine. Companion to `ROADMAP.md §6` (AI/LLM analysis).

## 1. Purpose

Add an **on-demand, metadata-only triage layer** on top of the existing
correlation engine. After the deterministic engine has produced a scan's
correlation results, a user can ask an LLM (via OpenRouter) to:

- assign each correlation a **priority/severity** and an overall **rank**,
- write a short **plain-language explanation** of why it matters,
- optionally flag **duplicate/related** correlations (a group label).

The goal is to cut analyst triage time by surfacing the most important findings
first — without changing *which* correlations the engine produces.

## 2. Goals / non-goals

**Goals**
- Deterministic correlation engine is **unchanged**; triage is a separate layer.
- **Metadata-only egress** (see §5) — no raw findings leave the box.
- **On-demand only** — zero egress until a user explicitly triggers it.
- Results **persisted** and surfaced in the UI and exports.
- Fail-closed, BYO-key, default-off, bounded cost (AETHER doctrine).

**Non-goals (explicitly deferred)**
- Automatic triage after every scan.
- Sending raw or redacted event *values* to the LLM.
- Local-model backends / provider abstraction beyond OpenRouter's model routing.
- LLM-*generated* correlations (finding correlations the static rules miss).
- Natural-language querying of findings.

## 3. Locked decisions (from brainstorming)

| # | Decision |
|---|----------|
| Role | Post-correlation **enrichment/triage** layer; engine untouched. |
| Egress | **Metadata only** (rule name/description, risk, headline, event count, event-type names). |
| Trigger | **On-demand only** (UI button + CLI flag). |
| Output | **Persist** in a new `tbl_scan_correlation_llm` table; shown in UI + exports. |
| Structure | **Companion modules** (`spiderfoot/llm.py` + a triage orchestrator); correlator class not modified. |

## 4. Architecture

Three new, isolated units plus two thin entry points.

### 4.1 `spiderfoot/llm.py` — `OpenRouterClient`
A minimal client for OpenRouter's chat-completions API. Single public method:

```
class OpenRouterClient:
    def __init__(self, api_key: str, model: str, *,
                 base_url: str = "https://openrouter.ai/api/v1",
                 timeout: int = 30, max_tokens: int = 2000,
                 max_retries: int = 2): ...

    def chat(self, system: str, user: str, schema: dict) -> dict:
        """POST one chat completion; require a JSON object response;
        validate it against `schema`; return the parsed dict.
        Raises LLMError on any failure (network, non-2xx, timeout,
        non-JSON, schema mismatch)."""
```

- **Auth:** `Authorization: Bearer <api_key>` header. The key is never logged
  and never included in exceptions or error responses.
- **Transport:** `requests` (already pinned), HTTPS with default certificate
  verification. `base_url` host is validated against the expected OpenRouter
  host; a non-OpenRouter host is rejected.
- **Bounds:** request body size cap; `timeout`; `max_tokens`; `max_retries`
  with backoff on transient (5xx/timeout) errors only.
- **Response:** request a JSON-object response (`response_format`); parse and
  validate against `schema` before returning. No streaming.
- **Errors:** one typed `LLMError`; messages are generic and contain no secrets.

This is the only unit that performs network egress, so it is the single point
to audit and the single thing tests mock.

### 4.2 `spiderfoot/correlation_triage.py` — orchestrator
Pure-ish coordination logic (no direct network; uses `OpenRouterClient`).

```
class CorrelationTriage:
    def __init__(self, dbh: SpiderFootDb, config: dict): ...
    def is_enabled(self) -> bool: ...        # config flag + key present
    def triage(self, scan_id: str) -> dict:  # returns {triaged, ranked, model, truncated}
```

`triage(scan_id)` steps:
1. **Guard:** if not `is_enabled()`, return a "not configured" result; **no egress**.
2. **Load** correlations via `dbh.scanCorrelationList(scan_id)`.
3. **Build the metadata payload** (see §5) — assign each correlation a stable
   integer index used in the prompt/response (the real `id` never needs to be
   sent, but is harmless metadata; the contract test pins exactly which fields
   are included).
4. **Cap:** if more than `_llm_max_correlations` (default 200), send the
   highest-risk N and set `truncated=True` (logged; never silently dropped).
5. **Call** `OpenRouterClient.chat(system, user, schema)`.
6. **Validate & map** the response back to real correlation ids (unknown ids
   dropped); coerce `priority` to the enum, bound `explanation` length.
7. **Persist** to `tbl_scan_correlation_llm` (replace any prior rows for the
   scan's correlations — re-triage overwrites).
8. **Return** a summary for the caller.

### 4.3 Entry points
- **Web:** `SpiderFootWebUi.scancorrelationtriage(self, id)` — `@cherrypy.expose`,
  POST. Returns JSON `{status, triaged, ranked, model, truncated}` or a
  "not configured" error when disabled. The correlations view gains a
  "Triage with AI" button (hidden when disabled) that renders priority badges
  and explanations from the persisted rows.
- **CLI:** a `sf.py` flag `--triage <scanID>` that runs the orchestrator once
  and prints a summary. Errors clearly if LLM is not configured.

## 5. Egress contract (security core)

For each correlation, **only** these fields are sent to OpenRouter:

- `rule_name` (e.g. "Open S3 bucket")
- `rule_description`
- `risk` (the engine's rule risk level)
- `headline` / correlation `title`
- matched-event **count**
- event **type names** only (e.g. `EMAILADDR`, `IP_ADDRESS`) — a tally; never values

**Never sent:** event data/values, the scan target, the scan name, raw YAML
rule logic, hostnames, IPs, emails, credentials, or any fetched content.

A dedicated unit test asserts the serialized payload contains none of the
forbidden data (constructed from fixtures that embed sentinel secret/PII
strings in event values and the scan name, then asserting those sentinels do
not appear in the payload).

## 6. Data model

New table (created in `SpiderFootDb.createSchemaQueries`):

```sql
CREATE TABLE tbl_scan_correlation_llm (
    correlation_id  VARCHAR NOT NULL PRIMARY KEY
                        REFERENCES tbl_scan_correlation_results(id),
    priority        VARCHAR NOT NULL,   -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    rank            INT NOT NULL,       -- 1 = most important
    explanation     VARCHAR,            -- bounded length, plain text
    grp             VARCHAR,            -- optional duplicate/related group label
    model           VARCHAR NOT NULL,   -- model id used
    generated       INT NOT NULL        -- epoch seconds (time.time())
);
CREATE INDEX idx_scan_correlation_llm ON tbl_scan_correlation_llm (correlation_id);
```

The FK references `tbl_scan_correlation_results(id)` (singular table name —
consistent with the FK-typo fix). Only derived metadata is stored; no raw
findings.

**Deletion:** `SpiderFootDb.scanInstanceDelete` is extended to delete the
scan's rows from `tbl_scan_correlation_llm` (sub-query on the scan's
correlation ids), so triage data is not orphaned — consistent with the
correlation-cleanup fix.

New DB accessors (thin, parameterized, type-validated like the rest of `db.py`):
- `correlationLlmCreate(correlation_id, priority, rank, explanation, grp, model, generated)`
- `scanCorrelationLlmList(scan_id)` — joins to return triage rows for a scan.

## 7. Configuration & defaults

Global config keys (registered in `sf.py` `sfConfig`, editable in the settings
UI like other `_`-prefixed options):

| Key | Default | Meaning |
|-----|---------|---------|
| `_llm_enabled` | `False` | Master on/off. Off ⇒ feature disabled, button hidden, zero egress. |
| `_llm_api_key` | `""` | OpenRouter API key. May be overridden by env var `FLOODPLAIN_OPENROUTER_API_KEY` (preferred; not persisted). |
| `_llm_model` | a low-cost instruct model (a Haiku-class / GPT-mini-class OpenRouter slug, verified against OpenRouter's current catalog at implementation time) | Model slug; user-overridable to any OpenRouter model. |
| `_llm_timeout` | `30` | Per-request timeout (seconds). |
| `_llm_max_tokens` | `2000` | Response token cap. |
| `_llm_max_correlations` | `200` | Max correlations sent per triage; excess ⇒ top-N by risk + `truncated`. |

**Enabled** ≡ `_llm_enabled` is true **and** a non-empty key is resolvable
(env or config). Otherwise the feature is treated as not configured.

**Secret handling (AETHER §3):** key resolved env-first; never logged, never in
errors/tracebacks, never sent anywhere except the `Authorization` header to the
validated OpenRouter host. Storing it in the local config DB is opt-in and
matches how existing module API keys are stored; the env-var path lets
operators avoid persistence.

## 8. Untrusted-output handling (AETHER §2, §13)

The LLM response is **untrusted input**:
- Required JSON schema: a list of objects `{index:int, priority:enum, rank:int,
  explanation:str, group:str?}`.
- `priority` coerced to the fixed enum; anything else ⇒ `INFO`.
- `index` mapped back to a real correlation id; unknown/missing indices dropped.
- `explanation` truncated to a fixed maximum length.
- Output is **stored as data only** — never `eval`'d, never used to build SQL
  (parameterized inserts), and HTML-escaped on display (the UI's existing
  escaping path).
- A malformed or unparseable response ⇒ `LLMError` ⇒ fail-closed (no partial
  writes), surfaced as a clear error.

## 9. Error handling

- **Fail-closed everywhere:** disabled/no-key ⇒ no egress, clear message; any
  client/validation error ⇒ no DB writes, error returned to caller; the web
  endpoint returns a JSON error and never 500s the app; the CLI exits non-zero
  with a readable message. A triage failure never affects a running/finished
  scan or its correlations.
- **No partial writes:** persistence happens only after the full response is
  validated.
- **Observability (AETHER §9):** log model id, correlation count, duration,
  truncation, and success/failure — but never the key or any payload values.

## 10. Testing strategy

All unit tests run **with `OpenRouterClient` mocked — no network**.

- **Client (`spiderfoot/llm.py`):** request shape (auth header present, JSON
  body, correct URL/host); rejects non-OpenRouter `base_url`; parses valid
  responses; raises `LLMError` on non-2xx, timeout, non-JSON, schema mismatch;
  never logs the key.
- **Orchestrator (`correlation_triage.py`):**
  - disabled / no key ⇒ returns "not configured" and **the client is never
    called** (egress assertion);
  - **egress-contract test** ⇒ payload excludes event values, scan name, target
    (sentinel-string assertion);
  - happy path ⇒ persists expected rows; re-triage overwrites;
  - invalid LLM output ⇒ fail-closed, no rows written;
  - `> _llm_max_correlations` ⇒ top-N sent, `truncated=True`.
- **DB:** `tbl_scan_correlation_llm` is created; FK references the correct
  table; `scanInstanceDelete` removes its rows; new accessors round-trip.
- **Web endpoint:** disabled ⇒ "not configured" + no orchestrator call;
  enabled ⇒ orchestrator invoked, JSON summary returned.

Determinism note: tests assert on *structure and persistence*, not on specific
LLM wording (the client is mocked).

## 11. Files touched

New:
- `spiderfoot/llm.py`
- `spiderfoot/correlation_triage.py`
- `test/unit/spiderfoot/test_llm.py`
- `test/unit/spiderfoot/test_correlation_triage.py`

Modified:
- `spiderfoot/db.py` (schema table + accessors + `scanInstanceDelete` cleanup)
- `sfwebui.py` (endpoint + correlations-view UI)
- `sf.py` (`--triage` flag + `_llm_*` config defaults)
- `spiderfoot/__init__.py` (export new classes if needed)
- `requirements.txt` only if a new dep is required (none expected — `requests`
  is already pinned). No new dependency is the default.
- relevant templates/static for the correlations view button + badges.

## 12. Out of scope / future (tracked, not built)

Auto-run after scans; redacted-sample or full-data egress modes; local-model
backend; LLM-proposed correlations; NL querying; provider abstraction. Each is
its own future spec.
