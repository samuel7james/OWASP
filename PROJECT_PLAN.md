# PROJECT_PLAN.md — OWASP Inspector v1

## Status: DRAFT — awaiting approval before Phase 2 implementation begins

---

## 1. Repository Audit

### What exists today
A working Python CLI (~8,000 LOC) with a text menu (`main.py` → `UI/main.py`) offering three scans: SQLi, XSS, CSRF. All three route through a single god object, `Logic/vulnerability_scan/Scanner_vulnerability.py` (813 lines, `URLVulnerabilityChecker(SQLiScanMixin, XSSScanMixin, CSRFScanMixin)`), which owns HTTP session management, parameter/form discovery, WAF-aware request wrapping, curl-repro generation, and Postgres reporting all in one class. Confirmed working end-to-end via manual import test — the tool runs.

Technique depth is genuinely strong already:
- **SQLi**: error/UNION/boolean/time-based/auth-bypass payloads, a dedicated binary-search blind extractor, optional SQLMap handoff with DBMS/technique hinting.
- **XSS**: reflected/stored/DOM/CSP-bypass scanners with exploit chaining.
- **CSRF**: 15 distinct bypass classes (token removal/tamper/reuse/entropy via Shannon+Levenshtein, double-submit, SameSite/CORS/CRLF checks, method-override, PoC HTML auto-generation).
- **WAF bypass** (`Logic/Recon/waf_bypass.py`): two-tier strategy (lightweight anti-detect → stealth headless Chrome via Botasaurus) plus per-vuln payload obfuscation (encoding, case randomization, `${IFS}`/base64 stubs for RCE, path-traversal encodings for LFI).

### Confirmed defects (file:line, verified by direct read/grep, not just first-pass claims)
| Issue | Location | Severity | Note |
|---|---|---|---|
| Hardcoded DB password fallback `"2002"` | `Logic/Recon/database_manager.py:19` | Medium | Baked into a security tool's own source |
| Wrong output directory (off-by-one path resolution) | `Logic/vulnerability_scan/csrf/__init__.py:12-13` vs `csrf_scanner.py:21-22` | Low/confusing | `ResultSaver` resolves 3 dirs up instead of 4, writing to `Logic/Data/csrf_scan_results/` instead of `Data/csrf_scan_results/` — explains the duplicate directory you can see on disk today |
| Positional-argument swap | `csrf/csrf_scanner.py:48` vs `authenticator.py:7` | Medium | Passes `(credentials, timeout, second_credentials)` into a constructor expecting `(credentials, second_credentials, timeout)` — `self.timeout` silently becomes `second_credentials`, breaking auth-flow CSRF tests whenever a real timeout and second credential set are both supplied |
| Missing import, latent `NameError` | `sqli/scanners/blind.py:209` | Medium | Uses `concurrent.futures.ThreadPoolExecutor` with no `import concurrent.futures` anywhere in the file — the blind-SQLi parallel extraction path crashes the moment it's reached |
| Mixin constructors never called | `Scanner_vulnerability.py:41` | Low | `URLVulnerabilityChecker.__init__` never calls `super().__init__()`, so `SQLiScanMixin`/`CSRFScanMixin` `__init__` bodies are dead; works only by accident via `getattr(..., default)` fallbacks |

### Duplication
- `_is_action_successful` + its regex pattern tables copy-pasted verbatim between `csrf/bypass_strategies.py:107-168` and `csrf/global_strategies.py:445-500`.
- `_env_float` helper reimplemented 3x: `Scanner_vulnerability.py:33-37`, `xss/http_client.py:12-16`, `sqli/sqli_context.py:8-12`.
- UA-pool/WAF constants duplicated between `Scanner_vulnerability.py:19-27` and `Recon/http_client.py:7-16`.
- Near-identical result-logging blocks pasted across `UI/sqli_scan.py`, `UI/xss_scan.py`, `UI/csrf_scan.py`.

### Dead code
- `UI/FullScan.py`, `Multi_Scan.py`, `benchmark_scan.py`, `idor_scan.py`, `machine.py`, `rce_scan.py`, `xxe_scan.py` — only stale `.pyc` remain, no source. These represent **abandoned or in-progress feature stubs** (multi-target scanning, benchmarking, IDOR/RCE/XXE coverage) that map directly onto gaps in OWASP Top 10 coverage — worth reviving deliberately rather than resurrecting the old files.
- All `__pycache__/` directories are stale build artifacts that should never have been committed.

### Architecture/maintainability gaps
No `pyproject.toml`/packaging, no `tests/`, no CI, no linter config, no async I/O (pure `requests`/sync `httpx.Client` + `ThreadPoolExecutor`), no plugin registry for vuln modules, inconsistent broad `except Exception: pass` swallowing real errors, `verify=False` TLS pinned everywhere with no explicit user consent/authorization gate.

### Coverage gap vs. OWASP Top 10 (2021)
Currently covers **A03 (Injection: SQLi/XSS)** and partially **A01/A05** (via CSRF/CORS/SameSite checks). Missing: A01 Broken Access Control (IDOR), A02 Cryptographic Failures, A04 Insecure Design, A05 Security Misconfiguration (headers, TLS config, directory listing), A06 Vulnerable Components (dependency/CVE checks), A07 Auth Failures, A08 Software/Data Integrity, A09 Logging/Monitoring failures, A10 SSRF.

---

## 2. Current Architecture

```
main.py → UI/main.py (menu) → UI/{sqli,xss,csrf}_scan.py
                                   └→ Scanner_vulnerability.URLVulnerabilityChecker
                                         (god object: session + crawl + WAF-wrap + report)
                                         ├→ sqli/orchestrator.py → scanners/{builtin,blind,sqlmap}.py
                                         ├→ xss_scan.py (legacy flat) — NOT the xss/ package
                                         └→ csrf/csrf_scanner.py + framework_csrf_scanner.py
Data/ — flat-file + optional Postgres persistence, read directly by scanner modules
```

Single-target, single-scan-type-per-run, synchronous, no shared discovery phase (each scanner does its own crawling independently — duplicated network I/O per scan type).

---

## 3. Proposed Architecture (v1 target)

Clean/hexagonal layering, one direction of dependency (core never imports plugins):

```
owasp_inspector/
  core/            # scan lifecycle, worker pool, retry, rate limiter, config, plugin registry
  discovery/        # fingerprinting, crawl, sitemap, param/endpoint discovery, headers/cookies/TLS
  modules/           # one package per OWASP category, each implementing a common Module protocol
    a01_access_control/
    a02_crypto_failures/
    a03_injection/       # absorbs existing sqli/ + xss/ engines
    a04_insecure_design/
    a05_misconfiguration/
    a06_vulnerable_components/
    a07_auth_failures/
    a08_integrity_failures/
    a09_logging_failures/
    a10_ssrf/
    csrf/               # existing engine, kept as its own module (maps to A01/A05 evidence)
  reporting/          # findings model, HTML/MD/JSON/PDF renderers, executive summary/risk scoring
  cli/               # Typer + Rich entrypoint, progress, profiles, scan history/resume
  safety/            # authorization gate, target-scope allowlist, request budget/DoS guardrails
tests/
docs/
```

Each module implements a shared interface (`run(context) -> list[Finding]`) so the core engine never needs to know module internals — this directly satisfies "modules must remain independent so future categories can be added without modifying the core engine."

---

## 4. Folder Structure

See tree above. Existing `Data/Payloads/*` and `Data/Parameters/*` migrate into `owasp_inspector/modules/a03_injection/data/` (payload corpora belong next to the code that consumes them, not in a top-level `Data/` grab-bag). Existing Postgres query layer (`Data/Queries/*.py`, which is clean and parameterized) becomes `owasp_inspector/core/storage/`.

---

## 5. Technology Decisions

| Concern | Choice | Why |
|---|---|---|
| HTTP | `httpx.AsyncClient` | Existing dep, native async, HTTP/2 |
| Concurrency | `asyncio` + bounded semaphore worker pool | Replaces thread pools; scales to large sites |
| CLI | `Typer` + `Rich` | Modern, typed, gives progress bars/color for free |
| Config | `pydantic-settings` + `.env` | Typed, validated config; replaces scattered `os.getenv` |
| Reporting | Jinja2 templates → HTML/MD/JSON; `xhtml2pdf` for PDF from the same HTML | Revised during Phase 6: WeasyPrint needs a native GTK/Pango runtime with no pip-installable path on Windows — would have made PDF export broken out of the box on this project's own dev platform. `xhtml2pdf` is pure Python (reportlab-based), verified working here. |
| Packaging | `pyproject.toml` (hatchling or setuptools), console-script entry point | Enables `pip install -e .` / `pipx install` |
| Testing | `pytest` + `pytest-asyncio` + `respx` (httpx mocking) + `pytest-cov` | Matches async stack |
| Lint/format | `ruff` (lint) + `ruff format` (replaces black+isort in one tool) | Fast, single dependency |
| DB | keep `psycopg2`/Postgres, optional | Already clean; no change needed |

---

## 6. Security Improvements

1. **Mandatory authorization gate**: before any scan runs, the CLI requires an explicit `--i-have-authorization` flag or an interactive confirmation naming the target — mirrors industry norms (OWASP ZAP, Nuclei, sqlmap-adjacent tools) and directly supports the stated "authorized assessments only" scope. This does not reduce technique depth, it just prevents accidental point-and-click misuse.
2. Fix the 5 confirmed defects above (hardcoded credential, path bug, arg-order bug, missing import, dead `__init__`).
3. Replace `getattr(..., default)`-based fallback error handling with explicit typed exceptions and structured logging (no more silent `except Exception: pass`).
4. Add a **request budget / rate limiter** per target (configurable, sane default) so aggressive multi-module scanning can't become an unintentional DoS against a target — this is a safety rail, not a throttle on technique quality.
5. Centralize the WAF-bypass / payload-obfuscation logic (already good) behind one registry instead of duplicated constants, so it's auditable in one place.
6. Secrets: add `.env.example`, verify `.gitignore` excludes `.env`, never write credentials into report output or logs.

**On "aggressive payloads":** the existing SQLi/XSS/CSRF/WAF-bypass technique set is already comprehensive and will be preserved and extended (adding IDOR, SSRF, misconfiguration, and component-CVE checks). "Aggressive" here means *thorough and evasive against defenses* (WAF bypass, encoding variants, blind/time-based extraction, chained exploits) — not destructive. The engine will not add payloads whose purpose is data destruction, service disruption, or irreversible state changes (e.g., no `DROP TABLE`-class SQLi payloads, no destructive RCE command execution, no automated mass-target scanning). That line matches both professional AppSec-tool norms and the authorized-assessment-only scope this project states for itself.

---

## 7. Performance Improvements

- Single shared discovery phase (crawl once, fan out to all modules) instead of each scanner re-crawling independently — cuts redundant requests significantly for multi-module scans.
- `asyncio` + bounded concurrency replaces sync/thread-pool code, with real backpressure via semaphores instead of unbounded `ThreadPoolExecutor(max_workers=10)` calls scattered per-module.
- Connection pooling/reuse via a single shared `httpx.AsyncClient` per scan.
- Benchmark harness (`pytest-benchmark` or simple timed fixtures) to track scan-time regressions across releases.

---

## 8. DevSecOps Roadmap

GitHub Actions pipeline on every PR: `ruff check` + `ruff format --check` → `pytest --cov` → CodeQL → Semgrep → dependency review / `pip-audit` → Trivy (once Docker image exists) → secret scanning (gitleaks) → SBOM (`cyclonedx-py`) on release tags. Multi-stage Dockerfile (builder + slim runtime). Automated GitHub Release on tag push with changelog generation.

---

## 9. Feature Roadmap (v1, in phase order)

Phase 2 Foundation → Phase 3 Core Engine → Phase 4 Discovery → Phase 5 OWASP Modules (start with fixing/absorbing existing SQLi/XSS/CSRF, then add A01 IDOR, A05 Misconfiguration/headers, A10 SSRF, A06 dependency/CVE checks as the highest-value net-new modules) → Phase 6 Reporting → Phase 7 CLI polish → Phase 8 Performance → Phase 9 DevSecOps → Phase 10 Docs → Phase 11 final review.

---

## 10. Future Roadmap (explicitly NOT v1)

Web dashboard, multi-user auth, team collaboration, SaaS deployment, scheduled scans, cloud agents, API service, distributed scanning, CI/CD integrations for *scanning other people's pipelines*, historical analytics. The `Module` protocol and JSON report schema are designed now so these can attach later without re-architecting the core.

---

## 11. Risks

- **Legal/ethical**: this is a dual-use offensive tool. Mitigated by the authorization gate (§6.1) and explicit non-destructive-payload boundary — this is a design constraint, not a suggestion, and applies to every future module.
- **Scope creep**: 11 phases is a lot; strict "one phase at a time, stop for approval" discipline (already specified) is the main mitigation.
- **Breaking working code while refactoring**: the current tool does run end-to-end today (verified) despite its bugs — refactors must keep a green path at every commit, not just at the end.
- **Botasaurus/headless-Chrome dependency** for WAF bypass is heavy; keep it optional/lazy-loaded as it is today.
