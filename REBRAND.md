# Floodplain Rebrand — Scope

> Status: **Scoping only — no code changes proposed yet.** Companion to `ROADMAP.md`.
> Basis: static inventory of the tree at the current commit (counts are `git grep` line matches; categories overlap, so they do **not** sum to the total).

## TL;DR

There are **5,161 case-insensitive `spiderfoot` references across 722 files**, but treating that as one number is the trap. They fall into seven categories with very different cost/value/risk. The genuinely valuable, low-risk rebrand (what users actually see) is a **small** slice. The bulk of the 5,161 is **load-bearing code identifiers** (`SpiderFoot*` classes, the `spiderfoot` package, the `sfp_` module prefix) whose renaming is high-churn, near-zero functional value, and permanently forecloses cherry-picking community patches or hosting third-party modules.

**Three decisions drive the whole effort** (details in [Decisions](#decisions-needed)):
1. Rename the `SpiderFoot*` **class names** to `Floodplain*`? — *Recommend: no (keep, optionally alias).*
2. Rename the **`sfp_` module prefix**? — *Recommend: no.*
3. Rename the **`sf*.py` entrypoints / `~/.spiderfoot` data dir**? — *Recommend: add `floodplain.py` + `~/.floodplain` with fallback, don't hard-rename.*

If all three are "no/additive", the rebrand is ~**1.5–2.5 days** and fully reversible. If all three are "yes", it's a **multi-day, ecosystem-breaking** effort with a permanent maintenance tax, and should be its own isolated project done last.

## Inventory (by category, not additive)

| # | Category | What it is | ~Refs / files | Rename risk | Value |
|---|----------|------------|---------------|-------------|-------|
| A | **Package dir** `spiderfoot/` | `from spiderfoot import …` (566), `resources.open_text('spiderfoot.dicts…')`, logger names `spiderfoot.X`, static root in `sf.py` | 566 imports + resource/logger refs | **High** (atomic, mechanical) | Medium |
| B | **Class names** `SpiderFoot*` | `SpiderFootEvent` 1967, `SpiderFoot` 1437, `SpiderFootTarget` 713, `SpiderFootPlugin` 502, `SpiderFootHelpers` 231, `SpiderFootDb` 172, `SpiderFootWebUi` 118, + others | ~5,200 (largest bucket) | **Very high** | **Near-zero** (internal API) |
| C | **Module prefix** `sfp_` | 233 modules + 231 unit tests + 198 integration tests; loader couples **filename == class name** (`spiderfoot/helpers.py:159-162`) | 662 file renames + 662 class renames + every test import | **Very high** | Near-zero (users see `meta['name']`, not the prefix) |
| D | **Entrypoints** `sf*.py` | `from sflib import` 435, `sfscan`/`sfwebui` 3 each; `sf.py`/`sfcli.py` in README, Docker, docs | 435+ + docs/Docker | High to rename, **low to add alias** | Medium (user-visible command) |
| E | **Runtime/persistence** | `~/.spiderfoot/` data dir, `spiderfoot.db`, env vars `SPIDERFOOT_DATA/_CACHE/_LOGS` (`spiderfoot/helpers.py:85-115`) | 21 path refs, 3 env vars | **Medium — real logic, user-data migration** | Medium |
| F | **User-facing brand strings** | web templates (10), static JS/CSS (4), CLI banner & `--version`, `meta['summary']` text, README | ~30 high-value + README | **Low** | **High — this *is* the rebrand** |
| G | **External URLs / must-preserve** | `spiderfoot.net` docs links (209), `github.com/…spiderfoot` (4), `User-Agent: SpiderFoot` (2), third-party `apiKeyInstructions` | 215 | **Low but must NOT blind-replace** | Mixed |

### Decisive structural facts (verified)
- **DB schema is brand-neutral.** All tables are `tbl_*`, columns generic (`spiderfoot/db.py:40-108`). **No schema migration is required** by any rename. The only persistence coupling is the *file location* `~/.spiderfoot/spiderfoot.db` (Category E).
- **Module loader hard-couples filename to class name:** `modName = filename.split('.')[0]; getattr(mod, modName)()`. Renaming the `sfp_` prefix therefore forces a matching class rename in all 233 modules — they cannot be done independently. The `modules/` package path itself is brand-neutral (`__import__('modules.' + modName)`), so that dir name needs no change.
- **All 233 modules contain the literal `spiderfoot`** — almost entirely via `from spiderfoot import SpiderFootEvent, SpiderFootPlugin` and `class sfp_X(SpiderFootPlugin)`. So Categories A + B account for the vast majority of the module hits; the modules themselves carry little independent brand text.
- **`VERSION` already says `Floodplain 4.0.0`** but `spiderfoot/__version__.py` is `VERSION = (4, 0, 0)` with no name — the two are out of sync; the displayed name comes from string literals in `sf.py`.

## Risk analysis of the expensive categories (B & C)

Renaming classes (B) and the module prefix (C) is where ~90% of the 5,161 lives, and it buys almost nothing:
- **Not user-visible.** Users interact with the web UI, the CLI flags, and `meta['name']` (e.g. "DNS Resolver") — never with `SpiderFootEvent` or `sfp_dnsresolve`.
- **Breaks the contribution path both ways.** Upstream SpiderFoot is abandoned *today*, but the community still publishes modules and the occasional fix. Renamed identifiers make every future `git cherry-pick` or ported module a manual conflict-resolution exercise, forever.
- **Breaks third-party modules.** Anyone with a private `sfp_*.py` against `SpiderFootPlugin` breaks on upgrade.
- **Largest blast radius for the test gate.** 231 unit + 198 integration test files reference these names; the unit suite is the PR merge gate, so the whole rename must land green in one shot.

If brand purity nonetheless requires it, the safe path is **aliasing, not replacing**: keep `class SpiderFootPlugin` and add `FloodplainPlugin = SpiderFootPlugin` (and similar), so both names resolve and old modules keep working. Do this **last**, as an isolated effort.

## Recommended phasing

Each tier is independently shippable, testable, and revertable (per AETHER doctrine §12/§15). Stop after any tier.

### Tier 1 — Visible rebrand (high value, low risk) — ~0.5–1 day
The slice that actually makes the product "Floodplain" to a user:
- Web templates `HEADER/FOOTER/error/...tmpl` + static JS/CSS title/brand strings (Category F).
- CLI banner, `--version`, the startup box in `sf.py:576-581`.
- Sync `spiderfoot/__version__.py` to carry the `Floodplain` name; make `--version` read from one source.
- Docker image/container names in `docker-compose*.yml` + Dockerfile comments.
- README/docs prose (preserve external links — see Tier 0 audit).
- **No code-identifier changes.** Unit suite should pass unchanged.

### Tier 0 (do alongside Tier 1) — External-reference audit (Category G) — ~0.25 day
Classify the 209 `spiderfoot.net` + 4 github + 2 User-Agent refs into **(a)** documentation links → repoint to Floodplain docs once they exist (until then, leave or point to the GitHub repo), **(b)** external-service refs in `apiKeyInstructions` → leave untouched, **(c)** `User-Agent: SpiderFoot` → decide deliberately (OPSEC/fingerprint surface, doctrine §10). This audit prevents Tier 1's prose edits from breaking working links.

### Tier 2 — Data path with backward compatibility (real code) — ~0.5 day
- Add `FLOODPLAIN_DATA/_CACHE/_LOGS` env vars; keep `SPIDERFOOT_*` as fallback.
- Resolve data dir as: explicit env → `~/.floodplain` if it exists → `~/.spiderfoot` if *it* exists (use in place, log a one-time notice) → else create `~/.floodplain`. This preserves existing users' scan history (no schema change needed — Category E).
- Update the legacy-file guards in `sf.py:617-632` accordingly.
- New unit tests for the resolution precedence (this is fail-closed logic worth covering).

### Tier 3 — Package rename `spiderfoot/` → `floodplain/` (high churn, mechanical) — ~1 day
- Automated codemod over the 566 imports + `resources.open_text('spiderfoot.…')` + logger-name strings + the static `tools.staticdir.root` in `sf.py:493`.
- Land as **one atomic commit**; full unit suite must be green.
- **Recommended:** ship a thin `spiderfoot/__init__.py` shim that re-exports from `floodplain` for one or two releases so external/private modules don't break immediately.
- Add `floodplain.py` as the documented entrypoint (thin wrapper or rename-with-`sf.py`-shim) — gets you the `python3 ./floodplain.py` story without breaking Docker/docs that reference `sf.py`.

### Tier 4 — DEFER / DECLINE: class names (B) + `sfp_` prefix (C)
Recommend **not doing this**, or doing it last and via aliasing only. ~5,200 refs + 662 file renames for cosmetic gain plus a permanent upstream-merge tax. Revisit only if a hard branding mandate exists.

## Decisions needed

1. **Class names `SpiderFoot*` → `Floodplain*`?** Recommend **keep** (optionally add aliases). Choosing "rename" roughly triples the total effort and forecloses upstream cherry-picks.
2. **`sfp_` module prefix → e.g. `fp_`?** Recommend **keep**. Forces 233 coupled class renames + ~430 test-file renames for no user-visible gain.
3. **Entrypoints `sf*.py` and data dir `~/.spiderfoot`?** Recommend **additive** (`floodplain.py` alias + `~/.floodplain` with fallback) over hard rename, to avoid breaking Docker, docs, and existing installs.
4. **Sequencing vs. `ROADMAP.md` Phase 0 (security/deps).** Recommend security/deps **first** (per maintainer's stated priority); the rebrand's Tiers 1–2 are independent and can interleave. Defer Tier 3's package rename until after dep bumps land, so two large mechanical changes don't collide in review.
5. **Upstream relationship:** is preserving the ability to port community modules/fixes a goal? If yes, this hardens the case against Tier 4.

## Verification strategy

- **Gate every tier on `python3 -m pytest test/unit -n auto` + `flake8 .`** (the PR gate). Tiers 1–2 should leave unit tests essentially unchanged; Tier 3 requires updating import sites in tests.
- After Tier 3, smoke-test the live paths the unit suite can't cover: `python3 ./sf.py -M` (module load), a real `-s … -t … -o json` CLI scan, and `python3 ./sf.py -l 127.0.0.1:5001` (web UI + static asset serving), since the package rename touches resource loading and the static dir root.
- Keep each tier in its own PR for independent revert (doctrine §15).
