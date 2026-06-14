# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Floodplain is a fork of **SpiderFoot 4.0** — an OSINT (open source intelligence) automation tool. It runs 230+ pluggable collection modules in a publisher/subscriber pipeline against a target (domain, IP, email, phone, username, bitcoin address, etc.), stores findings in SQLite, and applies a YAML-driven correlation engine. It exposes both a CherryPy web UI and a CLI.

The rebrand from "SpiderFoot" to "Floodplain" is **only partially done**: `VERSION` reads `Floodplain 4.0.0` and `sf.py` prints the Floodplain name, but the Python package is still `spiderfoot/`, modules still use the `sfp_` prefix, entrypoints are still `sf*.py`, the data directory is still `~/.spiderfoot/`, and ~5000 `spiderfoot` string references remain across the tree. Do not assume a name is wrong just because it says "spiderfoot" — that is the current expected state. See `ROADMAP.md` for the planned migration order.

## Commands

Python 3.10+ required (CI matrix: 3.10–3.13 on ubuntu + macOS).

```bash
# Install runtime + dev/test deps
pip3 install -r requirements.txt
pip3 install -r test/requirements.txt

# Run the web UI (also the normal way to use the app)
python3 ./sf.py -l 127.0.0.1:5001

# Run a headless CLI scan
python3 ./sf.py -s example.com -t INTERNET_NAME -o json
python3 ./sf.py -M          # list modules
python3 ./sf.py -T          # list event types

# Lint (this is a hard CI gate — must pass with zero violations)
python3 -m flake8 . --count --show-source --statistics

# Run the PR-gating test suite (lint + unit + integration, excludes live-network module tests)
./test/run

# Unit tests only — this is what gates PR merges
python3 -m pytest test/unit -n auto --dist loadfile --cov=. .

# A single test file / test / parametrized case
python3 -m pytest test/unit/spiderfoot/test_spiderfootevent.py
python3 -m pytest test/unit/modules/test_sfp_dnsresolve.py::TestModuleDnsresolve::test_handleEvent
python3 -m pytest -k "watchedEvents"

# Security/supply-chain checks (both are CI gates)
./test/bandit                                  # bandit SAST (CI fails on high-sev/med-confidence)
pip-audit --strict -r requirements.txt         # known-CVE scan of pinned deps
pip-audit --strict -r requirements.lock        # full locked closure (hash-pinned)
```

`flake8` config lives in `setup.cfg` (max line length effectively ignored via E501; `max-complexity=60`; google docstrings; per-file ignores matter — check there before "fixing" a lint suppression). `.pylintrc` also exists but flake8 is the enforced gate.

## CI gates (`.github/workflows/`)

- `tests.yaml` — **the PR merge gate**: flake8 lint + deterministic `test/unit` across the Python/OS matrix. Integration tests are deliberately excluded here.
- `integration.yaml` — runs `test/integration` (spawns real `sf.py` subprocesses, starts a web server, makes live network calls) on push-to-master / weekly / manual only, so its flakiness never blocks a PR.
- `bandit.yml` — SAST, gates on high-severity findings.
- `dependency-audit.yml` — `pip-audit` on requirements changes + weekly.

## Architecture

### Entry points (repo root)
- `sf.py` — main launcher. Loads all modules + correlation rules into `sfConfig`, then either starts the web server (`-l`), runs a CLI scan (`-s`), or runs correlations against an existing scan (`-C`). A CLI scan spawns `startSpiderFootScanner` in a separate `multiprocessing.Process` and polls the DB for completion.
- `sfwebui.py` — CherryPy web application (`SpiderFootWebUi`). Serves the UI and a JSON API; templates in `spiderfoot/templates/` (Mako), static assets in `spiderfoot/static/`.
- `sfcli.py` — interactive remote CLI client that talks to a running web server's API.
- `sflib.py` — the `SpiderFoot` utility class: HTTP fetching, DNS, target/type detection, module dependency resolution (`modulesProducing`/`modulesConsuming`/`eventsToModules`), config serialize/unserialize. Passed to every module as `self.sf`.
- `sfscan.py` — `SpiderFootScanner`: instantiates the selected modules, wires the event pipeline, drives a scan to completion, runs post-scan correlations.

### The `spiderfoot/` package (core engine)
- `plugin.py` — `SpiderFootPlugin`, the base class every module extends. Defines the event model: `watchedEvents()`, `producedEvents()`, `handleEvent()`, `notifyListeners()`, `registerListener()`, `checkForStop()`, and `threadWorker()`. Modules communicate **only** via events; a module never calls another module directly.
- `event.py` — `SpiderFootEvent`: the unit of data passed between modules (`eventType`, `data`, `module`, `sourceEvent`). Events form a parent chain back to the synthetic `ROOT` event; `notifyListeners` walks this chain to suppress duplicate cascades (`storeOnly`).
- `db.py` — `SpiderFootDb`: all SQLite access (scan instances, events, config, correlations). The DB lives at `~/.spiderfoot/spiderfoot.db` (NOT in the app dir — `sf.py` hard-errors if a legacy `spiderfoot.db`/`passwd` is found in the working directory).
- `correlation.py` — `SpiderFootCorrelator`: parses and executes the YAML rules in `correlations/`.
- `target.py` — `SpiderFootTarget`: target value + type + aliases.
- `threadpool.py` — `SpiderFootThreadPool` for intra-module concurrency.
- `helpers.py` — `SpiderFootHelpers`: module/rule loading (`loadModulesAsDict`, `loadCorrelationRulesRaw`), `dataPath()` (`~/.spiderfoot`), target-type detection, scan ID generation, wordlists.
- `logger.py` — multiprocessing-safe logging via a shared queue (`logListenerSetup`/`logWorkerSetup`); modules log through `self.debug/info/error`, which inject the `scanId`.

### Modules (`modules/`, ~233 files, `sfp_*.py`)
Each module is a single file defining a class named identically to the file (`sfp_dnsresolve.py` → `class sfp_dnsresolve(SpiderFootPlugin)`). A module declares:
- `meta` dict — `name`, `summary`, `flags`, `useCases` (`Footprint`/`Investigate`/`Passive`), `categories`, and (for API modules) `dataSource` with `apiKeyInstructions`.
- `opts` / `optdescs` — user-configurable options and their descriptions.
- `setup(self, sfc, userOpts)` — receives the `SpiderFoot` instance and merges user options.
- `watchedEvents()` — event types this module consumes (`["*"]` for all).
- `producedEvents()` — event types this module emits.
- `handleEvent(self, event)` — core logic; calls `self.notifyListeners(SpiderFootEvent(...))` to emit results, and checks `self.checkForStop()` in loops.

The scanner builds the module graph by matching `producedEvents`/`watchedEvents`. `sfp__stor_db` and `sfp__stor_stdout` (double underscore) are special storage sinks always appended to the module list. `sfp_template.py` is the scaffold for new modules and is intentionally excluded from loading. `sfp_tool_*` modules shell out to external binaries (nmap, whatweb, dnstwist, etc.) — always via list-form `Popen`, never `shell=True`.

### Correlation rules (`correlations/`, YAML)
37 pre-defined rules plus `template.yaml`. A rule has `id`, `version`, `meta`, `collections` (what to pull from scan results), optional `aggregation`/`analysis`, and `headline` (how to present a match). `correlations/README.md` is the authoritative reference. Rules run automatically after each scan and can also be run standalone with `sf.py -C <scanID>`.

### Tests (`test/`)
- `test/unit/` — deterministic, network-free; mirrors source layout (`test/unit/spiderfoot/`, `test/unit/modules/` with one `test_sfp_*.py` per module). This is the suite that gates merges.
- `test/integration/` — heavier; `test/integration/modules/` hits live third-party services and is excluded from PR runs (most self-skip without API keys).
- `test/acceptance/` — Robot Framework browser tests against a running web server on port 5001.
- `test/conftest.py` — provides `default_options` / `web_default_options` / `cli_default_options` fixtures; tests use a separate `spiderfoot.test.db`.

## Security doctrine

This repo's hardening posture (exact-pinned deps + `requirements.lock` for hash-verified installs, pip-audit/bandit CI gates, fail-closed input handling) is intentional and called out throughout `requirements.txt`, the workflows, and `ROADMAP.md`. When touching dependencies, keep exact pins and regenerate `requirements.lock`; when touching parsers or external input, preserve fail-closed validation. New external-tool modules must use list-form subprocess invocation.
