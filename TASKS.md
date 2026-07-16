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

## Phase 5 — OWASP Assessment Modules — COMPLETE (pending your review)
- [x] `Module` protocol was already defined in Phase 3 (`core/module.py`); this phase is its first real set of implementations, all registered via `@register_module` in `owasp_inspector/modules/`
- [x] **A03 Injection — SQLi**: `modules/sqli.py` wraps the existing (already bug-fixed, Phase 1/2) built-in SQLi engine. Bridges the legacy synchronous engine via `asyncio.to_thread` rather than a full async rewrite — deliberate: the engine already works and is already tested, a rewrite would add risk for no functional benefit
- [x] **A03 Injection — XSS**: `modules/xss.py`, same bridging pattern
- [x] **CSRF**: `modules/csrf.py`, same pattern, categorized under **A01:2021-Broken Access Control** (OWASP 2021 dropped CSRF as its own category; community guidance places it here since it's fundamentally an authorization failure on a state-changing request)
- [x] **A05 Security Misconfiguration** (net-new): `modules/misconfiguration.py` — reads directly from the Phase 4 discovery result (headers + TLS), zero extra requests. First module to actually demonstrate the discovery-engine payoff. Flags missing HSTS/X-Frame-Options/X-Content-Type-Options/CSP and unverifiable TLS certs
- [x] **A06 Vulnerable/Outdated Components** (net-new): `modules/vulnerable_components.py` — extracts version strings from `Server`/`X-Powered-By` headers and surfaces the Phase 4 fingerprint as candidates to check against a CVE database (NVD/OSV.dev). Deliberately does **not** call a live CVE API in v1 — no reliable product/version-to-CVE mapping from header strings alone yet — every finding here is INFO-severity and manual-verification-flagged, not a confirmed vulnerability claim
- [x] **A01 Broken Access Control — IDOR heuristic** (net-new): `modules/idor.py` — tampers numeric ID-like query params found by the crawl and flags a different-but-successful response. Explicitly cannot confirm real IDOR (needs two distinct authenticated identities this engine doesn't have) — every finding is low-confidence and manual-verification-flagged, never a confirmed claim
- [x] **A10 SSRF heuristic** (net-new): `modules/ssrf.py` — safe, non-destructive canary probes (unroutable loopback, cloud metadata endpoint) into URL-suggestive parameter names, flags only on cloud-metadata-like response content. Cannot confirm real SSRF without out-of-band infrastructure this engine doesn't have — same manual-verification-flagged discipline
- [x] `core/orchestrator.py`: `run_scan(url)` — the first real "one URL in, every applicable category assessed automatically" pipeline: runs discovery once, then every registered module concurrently, isolating any single module's failure so it can't sink the rest of the scan
- [x] 26 new tests (92 total): pure-logic tests for the Finding-conversion helper and the two discovery-only modules, `httpx.MockTransport`-backed tests for IDOR/SSRF, monkeypatched-bridge tests for SQLi/XSS/CSRF, and orchestrator tests proving module isolation
- [x] Verified for real: ran the full new-module pipeline against `example.com` (correctly flagged its genuinely-missing security headers, no false positives on vulnerable-components/IDOR/SSRF since there's nothing there to flag) and the CSRF-wrapped legacy engine against the README's own recommended test target — surfaced and fixed one more latent bug in the process: `Logic/Recon/framework_detector.py` read its own cached JSON with plain `utf-8`, which threw on the BOM the file actually had, silently breaking the framework-detection cache on every run
- [ ] Remaining categories (A02 Cryptographic Failures, A04 Insecure Design, A07 Auth Failures, A08 Software/Data Integrity, A09 Logging/Monitoring Failures) — intentionally deferred; each needs its own scoping pass rather than being rushed in alongside these seven, consistent with "one phase at a time, don't half-finish"

Deliberate scope note: SQLi/XSS/CSRF modules still call the legacy engines' own internal `discover_parameters` rather than reading `ScanContext.discovery.targets` — meaning the "each scanner crawls independently" duplication flagged in the Phase 1 audit is not yet eliminated for these three. Unifying that requires validating the legacy engines against the new discovery data shape, which is a real integration task in its own right, not something to force through as a side effect of wrapping. The four net-new modules (misconfiguration, vulnerable-components, IDOR, SSRF) already prove the shared-discovery model works end-to-end; migrating SQLi/XSS/CSRF onto it fully is a good candidate for a focused follow-up.

## Phase 6 — Reporting — COMPLETE (pending your review)
- [x] Findings/evidence data model: already existed (Phase 3 `Finding`); this phase adds `reporting/models.py` (`ReportData`, `RiskScore`) that aggregates a completed scan for rendering
- [x] Wired the Phase 3 `Scan` lifecycle into `core/orchestrator.py` for real (it existed but nothing called it) — `run_scan()` now returns a `ScanResult(scan, discovery, findings)` instead of a bare tuple, giving the report real duration/timeline data instead of nothing
- [x] `reporting/risk.py`: severity-weighted, confidence-discounted risk score (0-100) + A-F grade — a pile of low-confidence heuristic candidates (IDOR/SSRF) can't outweigh a single confirmed critical finding, by design
- [x] `reporting/summary.py`: executive summary generator, explicit about "no findings" not being a guarantee of security
- [x] JSON report: `reporting/serialize.py` — a deliberately explicit, versioned schema (`schema_version: "1.0"`), not a blind `dataclasses.asdict()` dump, so internal-only fields (e.g. the `RobotFileParser` instance living on `RobotsInfo`) never leak into output
- [x] Markdown report: `reporting/renderers/markdown_renderer.py`, grouped by OWASP category
- [x] HTML report: Jinja2 template (`templates/report.html.jinja2`), findings grouped/color-coded by severity, risk grade badge, discovery/tech-stack/timeline sections
- [x] PDF report: **switched from the originally-planned WeasyPrint to `xhtml2pdf`** — verified during this phase that WeasyPrint needs a native GTK/Pango runtime with no pip-installable path on Windows, which would have made PDF export broken out of the box on this project's own dev platform; `xhtml2pdf` is pure Python and confirmed working. Renders from the same HTML template (rewritten without CSS variables/flexbox/`rem` units, since xhtml2pdf's reportlab-based engine only understands a CSS2.1-ish subset with absolute units)
- [x] Scan statistics + timeline: `report.timeline` from the now-wired `Scan` history; discovery stats (pages crawled, injectable targets, robots/TLS status) surfaced in every format
- [x] **Real bug caught and fixed during this phase**: the Jinja2 environment used `select_autoescape(["html"])`, which decides based on the *template filename* ending in `.html` — the template is named `report.html.jinja2`, so it never matched and autoescaping was silently never active. Since finding titles/evidence originate from scanned target content, this was a real stored-XSS-into-the-report risk, not just a cosmetic bug. Fixed to unconditional `autoescape=True` (this environment only ever renders the one report template) and added a regression test
- [x] 21 new tests (113 total): risk-score boundaries/saturation, summary text, builder aggregation, JSON schema shape + serializability, and all four renderers — including a PDF-bytes-are-valid-PDF check and the HTML-escaping regression test
- [x] Verified for real: generated all four formats from a live scan against `example.com` and visually inspected the rendered PDF (professional layout: grade badge, severity table, categorized findings, timeline)

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
