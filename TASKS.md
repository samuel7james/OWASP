# TASKS.md — OWASP Inspector v1

Living task tracker. Updated at the end of every phase. Checkboxes reflect real state, not intent.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## Phase 1 — Repository Audit
- [x] Full read of every `Logic/`, `UI/`, root `.py` file
- [x] Identify dead code (`UI/FullScan.py` + 6 others, stale `__pycache__`)
- [x] Identify duplicated logic (`_env_float` x3, CSRF success-pattern regex x2, UA-pool constants x2, per-scan result-logging x3)
- [x] Identify and verify 5 concrete defects (hardcoded DB password, CSRF output-path off-by-one, Authenticator arg-order swap, missing `concurrent.futures` import in `blind.py`, dead mixin `__init__`s)
- [x] Map OWASP Top 10 coverage gap
- [x] Write `PROJECT_PLAN.md`
- [x] Write `TASKS.md`
- [ ] **Awaiting user approval of roadmap before Phase 2 starts**

## Phase 2 — Foundation — COMPLETE (pending your review)
- [x] `pyproject.toml` + packaging (`owasp-inspector` console-script entry point, verified working)
- [x] `Logic/config.py`: `pydantic-settings`-based `Settings` class enumerating every env var in use — available now for Phase 3+ code; legacy scanner modules still read `os.getenv` directly and migrate to this in Phase 5 alongside their move into the new module system (deliberate scoping, not an oversight)
- [x] `Logic/logging_config.py`: colored structured logging via stdlib `logging` + `colorama` (now actually used — was a listed-but-unused dependency)
- [x] `Logic/exceptions.py`: typed error hierarchy (`ConfigurationError`, `NetworkError`, `ScanError`, `AuthorizationError`)
- [x] Fixed the 5 confirmed defects from Phase 1, each verified with a manual repro + a regression test:
  - hardcoded DB password fallback removed (`Logic/Recon/database_manager.py`)
  - CSRF `ResultSaver` output-path off-by-one fixed, now writes to `Data/csrf_scan_results/` (`Logic/vulnerability_scan/csrf/__init__.py`)
  - `Authenticator(...)` positional-argument swap fixed via keyword args (`Logic/vulnerability_scan/csrf/csrf_scanner.py`)
  - missing `import concurrent.futures` added (`Logic/vulnerability_scan/sqli/scanners/blind.py`)
  - dead/unreachable-and-broken-if-ever-called mixin `__init__`s removed from `SQLiScanMixin` and `CSRFScanMixin`
- [x] **Bonus finds via first-ever lint pass**: 2 more latent crash bugs caught and fixed — `Logic/vulnerability_scan/xss/scanners/waf.py` used `requests.Session()` with no `requests` import; a bare `except:` in `framework_csrf_scanner.py` narrowed to `except Exception:`; an unused-variable removed in `bypass_strategies.py`
- [x] Removed `__pycache__`/`.pyc` from git tracking (55 files) and scan-output artifact directories (`Data/*_scan_results/`, `Logic/Data/`) from tracking; added `.gitignore` — nothing deleted from disk, only untracked
- [x] De-duplicated `_env_float` (3x → `Logic/env_utils.py`), UA-pool constants (2x → `Logic/user_agents.py`), and CSRF success/error regex + non-state-changing-path sets (3x → `Logic/vulnerability_scan/csrf/patterns.py`)
- [x] `.env.example` documenting all 24 env vars in use today
- [x] `ruff` installed and run: 279 → 67 findings (211 safe mechanical fixes applied: unused imports, import sorting, f-strings, redundant open modes); remaining 67 are style-only (`E701` one-line-if, `E402` import-after-sys.path-setup which is intentional here, one `E741`) — deferred to Phase 11, not bugs
- [x] Added `tests/` (18 tests): import-smoke tests for every entry point, unit tests for `env_utils`, and regression tests for all 5 fixed bugs — **this is the first test suite this repo has ever had**
- [x] Verified end-to-end: `owasp-inspector` console command runs the existing SQLi/XSS/CSRF menu correctly post-refactor
- [ ] Dead `UI/*.py` stubs (`FullScan`, `Multi_Scan`, `benchmark_scan`, `idor_scan`, `machine`, `rce_scan`, `xxe_scan`) — only stale bytecode remains, now untracked from git; decision on reviving these as real modules deferred to Phase 5 planning, not needed for Phase 2

## Phase 3 — Core Engine — COMPLETE (pending your review)
- [x] New `owasp_inspector/` package established (`core/`, `safety/`) — this is the real start of the target architecture from PROJECT_PLAN.md §3; `Logic/config.py`, `Logic/exceptions.py`, `Logic/logging_config.py` relocated here since nothing consumed them yet (safe move, verified with full test/import re-run)
- [x] `core/http.py`: `AsyncHttpClient` — `httpx.AsyncClient`-based, bounded concurrency via semaphore, retry with exponential backoff on network errors and 429/500/502/503/504, UA rotation, transport-injectable for testing (no real network needed in tests)
- [x] `core/ratelimit.py`: per-host minimum-interval `RateLimiter` — the request-budget safety rail so a multi-module scan can't unintentionally DoS a target
- [x] `core/lifecycle.py`: `Scan`/`ScanState` state machine (queued→running→{paused,done,failed}) with a validated transition table and timestamped history (feeds Phase 6 timeline reporting and Phase 7 resume)
- [x] `core/profiles.py`: `fast` / `thorough` (default) / `stealth` profiles controlling concurrency, timeout, retries, and pacing
- [x] `core/models.py` + `core/module.py` + `core/registry.py`: `Finding`/`Severity`/`Confidence`/`ScanTarget` data model, the `Module` ABC every OWASP category will implement (`run(context) -> list[Finding]`), and a `ModuleRegistry` so new categories register themselves instead of the core importing them by name
- [x] **Authorization gate** (`owasp_inspector/safety/authorization.py`): real behavior change, not just infrastructure — every existing scan entry point (`UI/sqli_scan.py`, `UI/xss_scan.py`, `UI/csrf_scan.py`, both interactive-menu and direct-URL-argument paths) now requires an explicit "yes" confirmation before scanning, or the `OWASP_INSPECTOR_AUTHORIZED=1` env var for non-interactive/CI use. Verified end-to-end: decline aborts cleanly back to the menu, accept proceeds, env var skips the prompt.
- [x] 25 new tests added (43 total) covering the HTTP client's retry/backoff/give-up/network-error paths, rate limiter timing, lifecycle transitions (including rejecting invalid ones), profiles, the registry, and every authorization-gate branch
- [x] Verified: full test suite passes, `ruff` clean of new findings, `owasp-inspector` CLI still runs end-to-end with the gate wired in

Deliberate scope note: the new async engine is foundational and not yet wired to replace the legacy synchronous SQLi/XSS/CSRF scan flow — that happens in Phase 5 when those engines migrate into `owasp_inspector/modules/`. Phase 4 (discovery) is the first consumer.

## Phase 4 — Discovery Engine — COMPLETE (pending your review)
- [x] `discovery/target.py`: URL normalization + `probe_target` (tries an https upgrade when http:// fails, same behavior the legacy `probe_target` had, rebuilt on the async client)
- [x] `discovery/fingerprint.py`: technology fingerprinting — **reuses** the existing `Data/Payloads/csrf_payloads/framework_signatures.json` corpus rather than duplicating it (it's just data). Along the way, fixed a real bug in the legacy detector it's replacing: the old code matched header/HTML "patterns" with plain substring `in` checks even though the signature file's patterns are regexes (e.g. `(?i)wsgiserver|gunicorn`) — the new version does real `re.search`, with a substring fallback only if a pattern fails to compile
- [x] `discovery/crawl.py`: the single shared BFS crawl — same-origin, robots-aware, extracts every GET query-param target and POST form target in one pass. This is what lets Phase 5 retire the "each scanner crawls independently" duplication flagged in the Phase 1 audit
- [x] `discovery/sitemap.py`: fetches `/sitemap.xml` (or robots.txt `Sitemap:` hints), stdlib `xml.etree` parsing — no `lxml` dependency reintroduced
- [x] `discovery/robots.py`: fetches and parses `robots.txt` via `urllib.robotparser`, exposes `.allows(url)` that the crawler actually enforces (not just parsed-and-ignored)
- [x] `discovery/tls.py`: certificate + protocol version inspection. Verify-first, so valid certs return real parsed subject/issuer/expiry; falls back to an unverified handshake for self-signed/expired/lab certs (the common case for this tool's authorized-lab/staging scope) so it still reports the negotiated TLS version and surfaces the trust failure as evidence instead of silently returning nothing — caught and fixed via a real-network smoke test against a valid cert and against badssl.com's self-signed test host
- [x] `discovery/engine.py`: `run_discovery()` — one entry point aggregating probe + robots + sitemap + fingerprint + TLS + crawl into a single `DiscoveryResult`, running the independent parts concurrently
- [x] 23 new tests (66 total), all against `httpx.MockTransport` (no real network needed in the suite) plus manual real-network smoke tests against `example.com` and `badssl.com` during development
- [x] Verified: full suite passes, `ruff` clean, `owasp-inspector` CLI still runs unaffected (discovery is not yet wired into the legacy scan flow — that integration is Phase 5, when SQLi/XSS/CSRF modules start reading from `ScanContext.discovery` instead of crawling independently)

## Phase 5 — OWASP Assessment Modules
- [ ] Define `Module` protocol (`run(context) -> list[Finding]`, confidence, evidence, remediation, OWASP reference link)
- [ ] A03 Injection: migrate/fix existing SQLi engine (fix `blind.py` import bug)
- [ ] A03 Injection: migrate existing XSS engine
- [ ] CSRF module: migrate existing engine, fix path bug + arg-order bug
- [ ] A01 Broken Access Control (IDOR) — net-new
- [ ] A05 Security Misconfiguration (headers, TLS, directory listing) — net-new
- [ ] A10 SSRF — net-new
- [ ] A06 Vulnerable/Outdated Components (dependency + CVE lookup) — net-new
- [ ] Remaining categories (A02, A04, A07, A08, A09) — scoped per-category once above land

## Phase 6 — Reporting
- [ ] Findings/evidence data model
- [ ] HTML report (Jinja2 template)
- [ ] Markdown report
- [ ] JSON report (schema-versioned)
- [ ] PDF report (WeasyPrint from HTML)
- [ ] Executive summary + overall risk score algorithm
- [ ] Scan statistics + timeline section

## Phase 7 — CLI Experience
- [ ] Typer command surface: `owasp-inspector <url>`
- [ ] Rich progress bars / stage indicators
- [ ] Colored, helpful error output
- [ ] Resume interrupted scans
- [ ] Scan history (local store)
- [ ] Config profile selection flag

## Phase 8 — Performance
- [ ] Replace remaining sync/thread-pool code with asyncio
- [ ] Connection pooling verification
- [ ] Memory profiling on large targets
- [ ] Startup-time check
- [ ] Benchmark harness + tracked baseline

## Phase 9 — DevSecOps
- [ ] GitHub Actions CI (ruff, pytest+cov, CodeQL, Semgrep, pip-audit, gitleaks)
- [ ] Dockerfile (multi-stage)
- [ ] Trivy image scan in CI
- [ ] SBOM generation on release
- [ ] Automated GitHub Release workflow

## Phase 10 — Documentation
- [ ] README rewrite for new architecture
- [ ] Architecture guide
- [ ] User guide
- [ ] Developer/contributor guide
- [ ] CHANGELOG
- [ ] CONTRIBUTING.md

## Phase 11 — Final Engineering Review
- [ ] Dead code sweep
- [ ] Naming/consistency pass
- [ ] Full doc sync check
- [ ] Full test + build verification
