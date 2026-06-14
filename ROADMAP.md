# Floodplain Development Roadmap

> Status: **Proposed plan — awaiting approval before code changes.**
> Author: development planning pass, 2026-06-13.
> Scope priorities (per maintainer): **security & dependency hardening first**, then bug/CI foundation, then bleeding-edge features (**AI/LLM analysis** and **new data sources**).

---

## 0. Decisions locked (2026-06-13)

- **Versioning — advance the version.** We forked at `SpiderFoot 4.0.0`; treat Floodplain as a new project and **reset to `0.0.1`**, developing toward a **Floodplain `1.0.0`** stable release. Doctrine (SemVer): while pre-1.0 we are in active development as `0.MINOR.PATCH` — bump **MINOR** for new modules/features and breaking changes, **PATCH** for fixes; `1.0.0` marks the first API/UX-stable Floodplain. Advance these in lockstep when applied: `VERSION`, `spiderfoot/__version__.py`, and the README "Stable Release" badge. *(Queued — not yet applied.)*
- **Python floor stays 3.10+.** Matrix `3.10–3.13` unchanged. Only fix the stale "Python 3.7+" line in README FEATURES. *(Revisit a 3.12+ floor later if a dependency forces it.)*
- **Drop Codecov; self-host coverage.** Remove the README badge + the `codecov-action` upload step in `tests.yaml`; surface coverage from `pytest-cov` directly (CI job summary / self-generated artifact, no third-party). *(Queued.)*
- **First work track: bug squashing** (in progress).

> **Lint gate is pinned to Python 3.11 on purpose.** The `tests.yaml` lint job runs flake8 on **3.11**. Under Python 3.12+ the bundled `pycodestyle` raises spurious `E231`/`E702` on PEP 701 f-strings (verified empirically). The codebase is clean on 3.11; bumping the lint job to 3.12+ requires upgrading `flake8`/`pycodestyle` first. Ties into the Python-floor decision above.

---

## 1. Where the fork stands today

Floodplain is a healthy SpiderFoot 4.0 fork. The bones are good; the surface is stale.

- **233 OSINT modules** (`modules/sfp_*.py`), CherryPy web UI (`sfwebui.py`), CLI (`sfcli.py`), SQLite backend (`spiderfoot/db.py`), YAML correlation engine (`spiderfoot/correlation.py`, 37 rules).
- **Core unit tests pass** on Python 3.10 (verified: `test/unit/spiderfoot/` event + target suites, 59 passed / 88 subtests). The codebase is functional, not broken.
- **No dangerous code patterns** in core: no `eval`, no `exec`, no `pickle`, no `shell=True`. External-tool modules (`sfp_tool_*`) use list-form `Popen` (safe invocation style).
- **The rebrand is barely started.** ~4,973 `spiderfoot` references across ~692 Python files; package dir is still `spiderfoot/`, modules still use the `sfp_` prefix, entrypoints are still `sf*.py`, `VERSION` still reads `SpiderFoot 4.0.0`.

The two biggest liabilities are (a) **dependencies pinned below patched majors** (real, scanner-confirmed CVEs) and (b) **dead CI** (deprecated actions + EOL Python in the matrix).

---

## 2. Phase 0 — Security & dependency hardening (do first)

`pip-audit` against `requirements.txt` reports **16 known vulnerabilities across 3 packages**, all caused by upper-bound pins that cap the package below the version where the fix landed.

### 2.1 Vulnerable — capped below the fix (must bump)

| Package | Current pin | Resolves to | Latest stable | Issue |
|---|---|---|---|---|
| `cryptography` | `>=3.4.8,<4` | 3.4.8 | **49.0.0** | 14+ advisories incl. CVE-2023-0286 (X.400 type confusion), CVE-2023-50782 (Bleichenbacher), CVE-2024-0727 (PKCS12 DoS), CVE-2026-26007. **Critical given the AEAD/TLS doctrine.** |
| `pyOpenSSL` | `>=21.0.0,<22` | 21.0.0 | **26.3.0** | CVE-2026-27448. Also far behind the `cryptography` it binds to. |
| `lxml` | `>=4.9.2,<5` | 4.9.4 | **6.1.1** | PYSEC-2026-87. XML parsing is attacker-reachable (HTML/feed/sitemap parsing across modules) — high priority. |

### 2.2 Deprecated / abandoned (must replace)

| Package | Pin | Problem | Action |
|---|---|---|---|
| `PyPDF2` | `>=1.28.6,<2` | **Archived & EOL**; superseded by `pypdf`. | Migrate to `pypdf>=6` (drop-in-ish API; one module + helpers touch it). |
| `ipaddr` | `>=2.2.0,<3` | Google's Python-2-era lib; superseded by stdlib `ipaddress`. | Plan migration to stdlib. |
| `pygexf` | `>=0.2.2,<0.3` | Py2-era, unmaintained; only used for GEXF graph export. | Replace export path with `networkx` GEXF writer (already a dep). |

### 2.3 Very stale but not (yet) flagged

| Package | Pin | Latest | Note |
|---|---|---|---|
| `networkx` | `>=2.6.3,<2.7` | 3.4.2 | Two majors behind; API changes needed but worth it. |
| `requests`, `beautifulsoup4`, `dnspython`, `CherryPy`, `openpyxl`, `Mako`, `phonenumbers` | loose `<N` upper bounds | various | Resolve to recent/patched today, so **not currently vulnerable** — but the loose ranges violate the "pin exact versions" doctrine (§6 supply-chain). |

### 2.4 Phase 0 deliverables

1. **Bump the three vulnerable deps** (`cryptography`, `pyOpenSSL`, `lxml`) to current majors; run the test suite; fix breakage.
2. **Replace `PyPDF2` → `pypdf`**; re-test the PDF parsing path (`sfp_filemeta` / document-metadata modules).
3. **Exact-pin every dependency** and introduce a lockfile (`pip-compile` / `requirements.lock`) so builds are reproducible — directly satisfies doctrine §6.
4. **Add dependency scanning to CI**: `pip-audit` as a required job (fails the build on new CVEs). Optionally Dependabot/`renovate` for automated bump PRs.
5. **Quick supply-chain win**: enable hash-checking installs once exact-pinned.

> Per the doctrine ("availability is a security property" / "minimize attack surface"), I'll bump conservatively one cluster at a time (crypto stack together, since `pyOpenSSL`↔`cryptography` are coupled) rather than a big-bang upgrade, so each change is independently testable and revertable.

---

## 3. Phase 1 — Foundation: CI, baseline, rebrand decision

### 3.1 CI is using sunset tooling
`.github/workflows/`:
- `codeql-analysis.yml`: `codeql-action@v1`, `checkout@v2` — **v1 is retired**; CodeQL runs will fail/deprecate.
- `tests.yaml`: `checkout@v2`, `setup-python@v2`, `codecov-action@v1` — all deprecated; matrix tests **Python 3.7/3.8/3.9** which are **all end-of-life**.

**Action:** upgrade to `checkout@v4`, `setup-python@v5`, `codeql-action@v3`, `codecov-action@v4`; retarget the matrix to **3.10–3.13**; align `README`/classifiers to the same range; add the `pip-audit` job from Phase 0; wire in `bandit` (the `test/bandit/` dir exists but is empty).

### 3.2 Establish a real test baseline
Bring up the full suite (`test/unit` + `test/integration`) in the sandbox, record pass/fail/skip counts and coverage, and treat that as the regression gate before any refactor. Integration module tests (199 files) hit live APIs — wire them to run mocked (`responses` is already a test dep) so they're CI-safe.

### 3.3 The rebrand is a real decision, not a sed pass
This is the one item I want your call on before touching code (see §7). Options range from cosmetic (user-facing strings, `VERSION`, banners) to a full rename of the `spiderfoot/` package, `sfp_` module prefix, and `sf*.py` entrypoints. A full rename is a large breaking change (imports, plugin discovery, third-party modules, muscle memory) for ~4,973 references; a layered approach (rebrand UI + docs now, alias the package, deprecate slowly) is safer.

---

## 4. Phase 2 — Bug squashing

Approach, in priority order:

1. **Lint/static-analysis sweep.** The `flake8` config already selects security plugins (`dlint`/`DUO`, `flake8-bugbear`, `bandit`-style). Run it, triage real findings vs. noise, fix the real ones. Add `bandit` for a security-specific pass.
2. **Argument-injection audit of `sfp_tool_*` modules.** Invocation style is safe (list-form `Popen`), but several pass scan input (`eventData`) straight into tool argv (e.g. `nmap`, `dnstwist`, `nuclei`). Confirm each validates/sanitizes input so a value like `--script=...` or a leading `-` can't smuggle a flag. Add `--` argument terminators where the tool supports it.
3. **Module health triage.** Many modules wrap third-party APIs whose endpoints/auth have drifted since 2022. Build a quick harness to flag modules whose API hosts 404/changed, and fix the high-value ones (Shodan, Censys, crt.sh, HIBP, etc.) first.
4. **Track upstream's open issues.** Mine SpiderFoot's pre-archive issue tracker for known unfixed bugs we inherited.

---

## 5. Phase 3 — New data sources (bleeding-edge feature track A)

Existing modern coverage: `shodan`, `censys`, `certspotter`, `crt`, `dehashed`, `intelx`, `github`, `haveibeenpwned`. Gaps worth filling, each as a standard `SpiderFootPlugin` (low architectural risk — the plugin contract is clean):

- **Attack-surface / host search:** FOFA, ZoomEye, Netlas, Quake — complement Shodan/Censys.
- **Certificate transparency at scale:** direct CT log / certstream ingestion beyond crt.sh.
- **Breach & credential intel:** LeakCheck, Snusbase, HackCheck (paid-key, opt-in) — alongside HIBP/Dehashed.
- **Code & secret exposure:** GitLab (we only have GitHub), plus public-paste and gist secret scanning.
- **Cloud asset discovery:** public S3/GCS/Azure bucket enumeration, ASN→cloud mapping.
- **Crypto/blockchain:** modern explorer modules (we have `sfp_bitcoin`); add multi-chain address/tx enrichment.

Each new module ships with: an integration test (mocked via `responses`), a `meta` block with `useCases`/`categories`, opt-in API-key handling (no key → module self-disables, never errors), and rate-limit/back-off (doctrine §10).

> **Doctrine note:** new modules default to *least data retention* — fetch, emit events, don't persist raw payloads. API keys load from config/secret store, are never logged, and are scoped per-module.

---

## 6. Phase 4 — AI/LLM-assisted analysis (bleeding-edge feature track B)

There are **no AI/LLM modules today** — clean slate. Highest-value, architecturally-clean entry points:

1. **Post-scan LLM summarization.** A new module/stage that consumes the event graph for a scan and produces a natural-language executive summary + prioritized leads. Output as a new event type (e.g. `LLM_ANALYSIS`) so it flows into existing export/UI paths.
2. **Natural-language querying of findings.** UI/CLI affordance: "show me everything linking these two domains" → translated to a query over the SQLite store. Read-only, parameterized queries only (no LLM-generated raw SQL execution — doctrine §2/§13).
3. **LLM-assisted correlation.** Complement the YAML rule engine: surface non-obvious entity relationships the static rules miss, flagged as *suggested* (human-in-the-loop), never auto-actioned.
4. **Entity enrichment/classification.** Triage/score discovered entities (risk, relevance) to cut analyst noise.

**AI safety/architecture guardrails (per doctrine §2, §3, §7, §13):**
- **BYO-key, provider-agnostic.** Support hosted (Anthropic/OpenAI) *and* local (Ollama/llama.cpp) backends; default off; no key → feature disabled.
- **Data minimization & egress control.** Be explicit about what scan data leaves the box. Local-model path for sensitive engagements (red-team/IR data shouldn't auto-ship to a third party). Redact secrets/PII before any prompt.
- **No dynamic execution.** LLM output is treated as untrusted input: never `eval`'d, never run as shell/SQL, schema-validated before use.
- **Cost & abuse bounds.** Token/request caps, timeouts, rate limits.

---

## 7. Decisions I need from you

1. **Rebrand depth:** (a) cosmetic now / full rename later, (b) full rename now (big breaking change), or (c) leave internals as-is and rebrand only user-facing surfaces. *(Recommend a.)*
2. **Dependency upgrade aggressiveness:** bump-to-latest-and-fix-breakage, or minimal bump to just-past-the-CVE? *(Recommend latest for the crypto stack — the gap is too large to defer; conservative for `networkx`.)*
3. **AI provider stance:** cloud-allowed-by-default, local-only-by-default, or both with explicit opt-in? *(Recommend both, default-off, local path first-class.)*
4. **First PR target:** I recommend **Phase 0.1** — bump `cryptography`/`pyOpenSSL`/`lxml`, swap `PyPDF2`→`pypdf`, exact-pin + lockfile, add `pip-audit` CI job — on a feature branch for your review.

---

## 8. Proposed sequencing

```
PR #1  Phase 0  Security deps: crypto stack bump, pypdf swap, exact pins, lockfile, pip-audit CI   ← start here
PR #2  Phase 1  CI modernization (actions + Python 3.10–3.13), bandit, test baseline
PR #3  Phase 1  Rebrand (depth per your decision §7.1)
PR #4  Phase 2  Lint/bandit fixes + sfp_tool_* argument-injection hardening
PR #5+ Phase 3  New data-source modules (batched by category)
PR #N+ Phase 4  AI/LLM analysis (summarization first, behind a default-off flag)
```

Each PR: scoped, independently testable, with tests + a green `pip-audit`. Nothing lands on `master` without review.
