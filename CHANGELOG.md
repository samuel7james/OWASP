# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); dates are commit dates. No version has been tagged/released yet — everything below is `0.1.0`-in-progress.

## [Unreleased]

## Phase 11 — Final Engineering Review

### Fixed
- A stray `print()` inside the async SQLi scanner (`sqli/builtin.py`, WAF-detection warning) — the only remaining raw stdout write left in `owasp_inspector/` outside the CLI layer, which would have corrupted Rich's live spinner display during a scan. Converted to `logging.warning`, matching the convention already used in `core/orchestrator.py`.
- Two stale `TASKS.md` checkboxes found by a systematic sweep for unchecked items inside phases already marked complete: Phase 5's "remaining categories" item still read as deferred, contradicting Phase 8's own completed work (A02/A04/A07/A08 were in fact built there); Phase 2's "dead `UI/*.py` stubs" item was still open despite those files having no source left to revive (only orphaned bytecode, now deleted from disk).

### Removed
- `ScanTarget.credentials` (`core/models.py`) — added in anticipation of wiring authenticated scanning into the CLI, but nothing in `owasp_inspector/` ever read it once the CSRF port's `Authenticator` login flow was explicitly deferred. Confirmed unused repo-wide (beyond its own test assertion) before removing.

### Changed
- Clarified `core/lifecycle.py`'s `Scan` docstring, which incorrectly implied its `pause`/`resume` state-machine methods are what power the CLI's `--resume` flag — that's an unrelated mechanism (`DiscoveryCache`). Kept the methods themselves: unlike `credentials`, they're not tied to a specific deferred feature, just not wired to a caller yet.

### Verified
- Full sweep for dead code (`vulture`, plus manual checks for TODO/FIXME markers, orphaned files, and stray prints) turned up nothing else; every markdown link and anchor across `README.md`/`CONTRIBUTING.md`/`CHANGELOG.md`/`docs/*.md`/`TASKS.md` resolves correctly.
- Full suite (257 passed), `ruff check`/`ruff format --check`, and a from-scratch Docker rebuild + real scan against `example.com` inside the container, all re-run after every change in this phase, not just at the end.

## Phase 10 — Documentation

### Documentation
- README rewrite for the v1 architecture, corrected to accurately reflect what the native SQLi/XSS/CSRF ports do and don't cover (previously overstated: stored/DOM/CSP XSS, SQLMap integration, and CSRF's SameSite/CORS/CRLF checks are not part of the automated engine — see below).
- Added `docs/ARCHITECTURE.md`, `docs/USER_GUIDE.md`, `CONTRIBUTING.md`, and this changelog.

### Fixed
- Two GitHub Actions CI failures caught on the first real run: `aquasecurity/trivy-action@0.28.0` doesn't resolve (needed a `v` prefix), and `semgrep scan --config=auto --error --metrics=off` fails outright (`--config=auto` needs the metrics-gated rule-recommendation service). Upgraded to `trivy-action@v0.36.0` and switched to Semgrep's `p/ci` explicit ruleset.
- Running the corrected Semgrep scan for real (not just editing and hoping) surfaced 26 genuine findings against the new workflow files themselves: every `uses: owner/action@vX` was a mutable, repointable tag, and two `run:` steps interpolated `${{ github.ref_name }}` directly into shell scripts. Every action reference is now pinned to its resolved commit SHA; the affected steps pass values through `env:` instead.

## Phase 9 — DevSecOps

### Added
- Multi-stage `Dockerfile` (`python:3.12-slim` builder + slim runtime, unprivileged user, `ENTRYPOINT` on the flagship `owasp-inspector` command).
- `.github/workflows/ci.yml`: on every PR/push — `ruff check` + `ruff format --check`, `pytest --cov`, CodeQL, Semgrep, `pip-audit` (advisory), gitleaks, and a Docker build + Trivy scan (advisory, SARIF uploaded to the Security tab).
- `.github/workflows/release.yml`: on `v*.*.*` tag push — full test suite, CycloneDX SBOM (JSON + XML), Docker build, a Trivy scan that actually gates the release, a changelog generated from `git log`, and a published GitHub Release with the image tarball and SBOM attached.

### Fixed
- A real packaging bug found by actually building and running the Docker image: `main.py`'s `sys.path` bootstrap resolved `UI/Logic/Data` relative to its own `__file__`, which works for an editable dev install but breaks the moment `main.py` is copied elsewhere by a real `pip install .` — exactly what the Docker build does. Fixed with a minimal fallback to the current working directory when the siblings aren't found next to the installed file.
- Brought `owasp_inspector/`/`tests/` into `ruff format` compliance (91 files, whitespace/wrapping only) and excluded the pre-v1 legacy engine (`Logic/`, `UI/`, `Data/Queries/`, `main.py`) from `ruff` entirely — a repo-wide lint run surfaced pre-existing violations there that reflect the legacy sys.path-shim's structural import order, not a style lapse worth a real refactor.

## Legacy-engine async migration

Revisited a "not done" decision from Phase 8: SQLi, XSS, and CSRF started as thin `asyncio.to_thread` bridges around the pre-v1 synchronous engine. Each was ported to native async as a faithful translation of its primary detection path (not a full rewrite of every legacy feature) — see `docs/ARCHITECTURE.md` for exactly what's ported versus deferred in each.

### Added
- `owasp_inspector/modules/sqli/` — native async port of the built-in SQLi scanner (error-pattern, UNION reflection/column-count, time-based with control-verification, auth-bypass, size-diff, boolean-toggle).
- `owasp_inspector/modules/xss/` — native async port of the reflected-XSS scanner (standard payload sweep plus a context-aware follow-up pass).
- `owasp_inspector/modules/csrf/` — native async port of 10 of the legacy engine's 15 form-level CSRF bypass tests.
- `ParamTarget.defaults` and `ParamTarget.is_form` (discovery model) — existing form/query values and a form-vs-bare-link distinction, both needed so the ported modules can read shared discovery instead of crawling independently.

### Fixed
- **SQLi**: the error-pattern check didn't compare against a pre-payload baseline response. On a live DVWA target with an already-broken backend, every payload against every parameter matched the same pre-existing fatal error — 30+ false positives on an unrelated parameter, found via live testing, not mocks.
- **SQLi**: `response.elapsed` raises under `httpx.MockTransport` (real transports populate it, mocks don't) — fixed by measuring elapsed time directly instead of relying on transport instrumentation.
- **XSS**: a dangerous-construct-survival check treated markers like `"alert("` as proof a payload survived unescaped, even though that substring contains no HTML metacharacters and remains present as harmless text after full HTML-escaping. A bare-canary "reflection-check" payload type also bypassed the exact-match/dangerous-survival gate entirely.
- **CSRF**: the success classifier only fetched a baseline for 2 of 15 bypass tests; extended to all of them and gated the success-pattern match itself on "wasn't already true of the baseline." Also fixed a token-entropy check that flagged any hex-shaped token as "weak" purely by format (hex-encoding random bytes is how most frameworks generate secure tokens) and a related `errors="ignore"` bug that let random garbage decode into a false base64 "hit."
- **CSRF**: DVWA's own CSRF lab uses `<form method="GET">`, which the module's initial POST-only target filter excluded entirely — found via live testing, fixed with the `is_form` field above.

All three ports were verified against real DVWA targets (via an authorized practice-lab instance), not just mocked tests.

## Phase 8 — Performance

### Added
- Crawl parallelization: each same-depth BFS wave fetched concurrently instead of sequentially.
- Connection pooling tuned to each scan profile's concurrency instead of `httpx`'s fixed defaults.
- A permanent, rerunnable memory-profiling script (`scripts/benchmark_discovery.py`) and a regression-guard test with a deliberately generous ceiling.
- The remaining OWASP categories implemented for real: A02 (cookie `Secure` flag, TLS version, sensitive query params, mixed-content), A06 (version-disclosing headers, fingerprinting), A07 (cookie `HttpOnly`/`SameSite`, login-over-HTTP), A08 (missing SRI, exposed source maps).

### Fixed
- `robots.txt` was respected by default during crawling, which silently blinded discovery on a real, fully-authorized target whose `robots.txt` disallowed everything — robots.txt is a crawler-politeness convention, not access control, and this only ever runs after the authorization gate has already approved the scan. `respect_robots` now defaults to `False`, with `--respect-robots` to opt back into the conservative behavior.

## Phase 7 — CLI

### Added
- Typer/Rich CLI: `owasp-inspector <url>` as the flagship one-command entry point (`scan` implied), plus `owasp-inspector history`.

## Phase 6 — Reporting

### Added
- Report generation: JSON, Markdown, HTML, and PDF renderers from one shared `ReportData` model.

### Fixed
- A stored-XSS-in-report bug: the HTML renderer's Jinja environment used `select_autoescape(["html"])`, which matches by template *filename* suffix — the actual template is named `report.html.jinja2`, so autoescaping silently never activated. Finding evidence comes from scanned target content, so this let a target inject markup into its own report. Fixed with unconditional `autoescape=True`.

## Phase 5 — OWASP assessment modules

### Added
- The `Module`/`ScanContext`/`ModuleRegistry` extension point, and the first net-new modules built on shared discovery: IDOR (heuristic), SSRF (heuristic), plus the initial `asyncio.to_thread`-bridged wrappers around the existing SQLi/XSS/CSRF engines.

## Phase 4 — Discovery engine

### Added
- The shared discovery pass (`owasp_inspector/discovery/`): crawl, technology fingerprint, TLS inspection, `robots.txt`/`sitemap.xml` — one pass every module reads from instead of crawling independently.

## Phase 3 — Core engine

### Added
- The async HTTP client, module registry, scan lifecycle, and the authorization gate every scan entry point (new and legacy alike) now goes through before making a request.

## Phase 2 — Foundation and pre-existing fixes

### Fixed
- Seven latent bugs in the pre-existing legacy engine, found during the initial repository audit.

### Added
- Packaging (`pyproject.toml`), `.env.example`, `.gitignore`, and the initial test suite.

## Initial commit

- The original menu-driven, single-vulnerability-class SQLi/XSS/CSRF scanner (`Logic/`, `UI/`, `main.py`) that this project builds on and continues to support via `owasp-inspector-legacy-menu`.
