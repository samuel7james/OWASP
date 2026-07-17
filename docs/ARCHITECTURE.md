# Architecture

This document describes how OWASP Inspector v1 (`owasp_inspector/`) is put together: the layers, the extension points, and the design decisions that would otherwise only live in commit messages. It does not cover the legacy menu-driven engine (`Logic/`, `UI/`, `main.py`) beyond how it coexists with v1 — see [Legacy engine](#legacy-engine) at the end.

## The one-line summary

`owasp-inspector <url>` runs **one shared discovery pass**, then **every registered OWASP module concurrently against that same discovery result**, then builds **one report**. No module crawls independently; no module knows about any other module.

```text
CLI (cli/)
  → authorization gate (safety/)
  → orchestrator.run_scan() (core/)
      → discovery.run_discovery()  (discovery/)   — one crawl, shared by everything after it
      → ModuleRegistry.instantiate_all()          — every @register_module class
          → Module.run(ScanContext) concurrently  (modules/)
      → Finding[] merged from all modules
  → reporting.build_report()  (reporting/)
  → renderers write json/markdown/html/pdf         (reporting/renderers/)
```

## Package layout

| Package | Responsibility |
|---|---|
| `owasp_inspector/core/` | HTTP client, settings, module protocol/registry, scan lifecycle, scan profiles, the orchestrator that ties everything together |
| `owasp_inspector/discovery/` | The one shared crawl/fingerprint/TLS/robots/sitemap pass every module reads from |
| `owasp_inspector/modules/` | One file (or package) per OWASP category, each a `Module` subclass |
| `owasp_inspector/reporting/` | Turns `Finding[]` + discovery data into a `ReportData`, then renders it to json/markdown/html/pdf |
| `owasp_inspector/safety/` | The authorization gate — nothing scans without it |
| `owasp_inspector/cli/` | Typer/Rich CLI — the only thing end users invoke directly |

## Core engine (`core/`)

### `AsyncHttpClient` (`core/http.py`)

The one place request policy lives: bounded concurrency (`asyncio.Semaphore`), retry with backoff on 429/5xx, per-host rate limiting, a random User-Agent pool, and a deliberately permissive TLS context (`SECLEVEL=0`, `MINIMUM_SUPPORTED`) — this tool must be able to *reach* targets running old/weak TLS configurations (a common real state for the internal/legacy systems this project's authorized-testing scope covers); `verify=False` alone doesn't do that, it only skips certificate checks. Discovery and every module share the same client class (though each module or discovery gets its own *instance*, sized by the active scan profile).

### `Module` and `ScanContext` (`core/module.py`)

```python
class ScanContext:
    def __init__(self, target: ScanTarget, http, settings, discovery=None): ...

class Module(ABC):
    name: str
    owasp_category: str
    async def run(self, context: ScanContext) -> list[Finding]: ...
```

This is the entire extension surface. The orchestrator only ever calls `run()` — it never inspects a module's internals. `ScanContext.discovery` is where shared crawl data (pages, forms, cookies, fingerprint, TLS) lands so a module never needs to crawl independently.

### `ModuleRegistry` (`core/registry.py`)

```python
@register_module
class MyModule(Module):
    name = "my-check"
    owasp_category = "A0X:2021-Whatever"
    async def run(self, context): ...
```

`@register_module` adds the class to `default_registry` at import time. `owasp_inspector/modules/__init__.py` imports every module file (for that side effect), and the orchestrator imports that package once (`import owasp_inspector.modules  # noqa: F401`). Adding a new OWASP category means adding one new module file — `core/` and the orchestrator never change.

### Orchestrator (`core/orchestrator.py`)

`run_scan(url, profile=..., max_pages=..., resume=..., respect_robots=...)` is the single entry point the CLI calls. It: runs discovery once (or reuses a cached one if `resume=True` and the cache is still fresh), builds one `ScanContext`, instantiates every registered module, and runs them all via `asyncio.gather(..., return_exceptions=True)` — one module raising an exception is logged and skipped, it never sinks the rest of the scan. This is what "modules remain independent" means in practice.

### Scan profiles (`core/profiles.py`)

Three fixed profiles control concurrency/timeout/retries/pacing: `fast` (20 concurrent, no pacing), `thorough` (10 concurrent, 0.1s pacing — the default), `stealth` (2 concurrent, 1.5s pacing, more retries). A profile is resolved once per scan and used to size the shared `AsyncHttpClient`.

### Settings (`core/config.py`)

A single `pydantic_settings.BaseSettings` subclass, loaded from `.env` if present, `extra="ignore"` (unknown env vars don't break anything). Every field has a safe default — the scanner runs with zero configuration. See `.env.example` for the full list.

## Discovery (`discovery/`)

`run_discovery(http, url, max_pages, respect_robots)` is the one crawl pass, run once per scan:

1. **Probe** (`target.py`) — resolve the final URL (follow redirects), bail out early with `DiscoveryResult(ok=False)` if the target isn't reachable.
2. **Concurrently**: fetch `robots.txt`, fingerprint the technology stack (`fingerprint.py`), inspect the TLS certificate/protocol version (`tls.py`), and fetch the page itself for headers/cookies.
3. **Sitemap** (`sitemap.py`) — read `sitemap.xml` if `robots.txt` pointed to one.
4. **Crawl** (`crawl.py`) — breadth-first, same-origin, each depth-wave fetched concurrently via `asyncio.gather` (bounded by the shared client's own semaphore). Extracts `ParamTarget`s from both query-string links and HTML `<form>` elements.

`respect_robots` defaults to **`False`**. This was a deliberate fix, not the original design: `robots.txt` is a crawler-politeness convention for search engines, not an access-control mechanism, and discovery only ever runs after the authorization gate has already confirmed the scan is permitted. Respecting it by default silently blinded the tool on a real, fully-authorized DVWA target whose `robots.txt` contained `Disallow: /`. `--respect-robots` opts back into the conservative behavior for anyone who wants it.

### `ParamTarget` — the shared unit modules consume

```python
@dataclass
class ParamTarget:
    method: Literal["get", "post"]
    url: str
    params: list[str]
    defaults: dict[str, str]
    is_form: bool = False
```

- `defaults` carries existing query-string values or form `value=` attributes, so a module can build a baseline/injected request pair without re-fetching the page first.
- `is_form` distinguishes an actual `<form>` (a deliberate, potentially state-changing action) from a bare crawled link with a query string (e.g. `?page=2`). This matters concretely for CSRF: DVWA's own CSRF lab uses `<form method="GET">`, and without `is_form` there'd be no way to tell that apart from an ordinary paginated link — one is worth testing for CSRF, the other isn't.

### `DiscoveryCache` (`core/discovery_cache.py`)

`--resume` caches a *completed* `DiscoveryResult` to disk, keyed by URL, with a freshness window (default 1 hour). It does **not** checkpoint progress inside a module — modules have no persisted internal state to resume from, and faking that would be exactly the kind of half-finished feature this project avoids. If a scan is killed mid-module, re-running it re-runs every module fresh (discovery is reused if still fresh).

## Modules (`modules/`)

Eleven modules cover nine of the ten OWASP Top 10 (2021) categories (A09 — Logging and Monitoring Failures — is not observable via external HTTP scanning and is deliberately not faked):

| Module | Category | Kind |
|---|---|---|
| `idor.py` | A01 Broken Access Control | Heuristic (single-signal, needs manual verification) |
| `csrf/` | A01 Broken Access Control | Native async, deterministic bypass tests |
| `crypto_failures.py` | A02 Cryptographic Failures | Deterministic, reads discovery data only |
| `sqli/` | A03 Injection | Native async |
| `xss/` | A03 Injection | Native async |
| `insecure_design.py` | A04 Insecure Design | Deterministic (debug-mode/stack-trace detection) |
| `misconfiguration.py` | A05 Security Misconfiguration | Deterministic, reads discovery data + bounded sensitive-path probes |
| `vulnerable_components.py` | A06 Vulnerable and Outdated Components | Informational only, no live CVE lookup |
| `auth_failures.py` | A07 Identification and Authentication Failures | Deterministic |
| `software_integrity.py` | A08 Software and Data Integrity Failures | Deterministic |
| `ssrf.py` | A10 Server-Side Request Forgery | Heuristic (single-signal, needs manual verification) |

"Deterministic" here means the check reads a flag that's either present or not (a missing header, a cookie without `Secure`) — reported as `confirmed`. "Heuristic" means a single signal that's suggestive but not conclusive on its own (IDOR would need a second authenticated identity to be sure; SSRF would need out-of-band callback infrastructure this engine doesn't run) — always flagged as needing manual verification.

### SQLi, XSS, CSRF: what's native, what's deferred

These three started as thin `asyncio.to_thread` bridges around the pre-v1 synchronous engine (`Logic/vulnerability_scan/{sqli,xss,csrf}/`). Each has since been ported to native async — but as a **faithful port of the primary detection path**, not a full 1:1 rewrite of every legacy feature. Each module's own docstring is the authoritative list of what's deferred; the summary:

- **`sqli/`** — every check in `Logic/vulnerability_scan/sqli/scanners/builtin.py` (error-pattern, UNION reflection/column-count, time-based with control-verification, auth-bypass, size-diff, boolean-toggle) is ported. **Not ported**: the cookie-based blind conditional-error extraction solver and the SQLMap integration (`scanners/{blind,sqlmap}.py`).
- **`xss/`** — the reflected-XSS scanner (`scanners/reflected.py`): standard payload sweep plus a context-aware follow-up pass that picks JS-string/event-handler/attribute-breakout payloads based on where an injected canary landed. **Not ported**: Stored XSS, DOM XSS, CSP-bypass, and WAF-evasion scanning (`scanners/{stored,dom,csp,waf}.py`) — each a substantially larger, more specialized engine than reflected XSS.
- **`csrf/`** — 10 of 15 form-level bypass tests from `bypass_strategies.py` (no-token, remove-token, empty-token, method-switch, both method-overrides, header-override, tampered-token, content-type-switch, token-entropy). **Not ported**: the two tests needing a second authenticated session (`CrossSessionTokenTest`, `NonSessionCookieTokenTest` — the legacy `Authenticator`'s login flow assumes a fixed `/login` path unrelated to this engine's discovery-driven design), the two needing a real state-changing action performed twice (`TokenReuseTest`, `CustomHeaderBypassTest`), `GlobalStrategies` (SameSite/Referer/CORS/CRLF/clickjacking/token-leakage checks — a substantially larger, more specialized subsystem), and `PoCGenerator` (writes exploit HTML to disk).

All deferred functionality remains reachable via `owasp-inspector-legacy-menu`.

### The false-positive-by-missing-baseline-comparison lesson

Across all three ports, the single most valuable audit turned out to be the same question asked of every detection check: **does this check verify that the payload actually caused the signal, or does it just check that the signal is present?** A check that does the latter will eventually flag something that was already true before the payload was ever sent. Concretely:

- SQLi's error-pattern check didn't compare against a baseline (pre-payload) response — on a target with an already-broken backend (a database table that doesn't exist), *every* payload against *any* parameter "matched" the same pre-existing fatal error. Found via a live DVWA test where 30+ identical false positives on an unrelated `Submit` parameter drowned out the 12 genuine findings on the actual vulnerable parameter.
- XSS's dangerous-construct check treated markers like `"alert("` as proof a payload survived — but that substring contains no HTML metacharacters, so it's present as inert text even when the server fully HTML-escapes the payload. A generic "bare canary reflected somewhere" payload type also bypassed the whole exact-match/dangerous-survival gate.
- CSRF's classifier only fetched a baseline for 2 of the legacy engine's 15 bypass tests — a page with static "success"-flavored boilerplate would misread as a working bypass on the other 13.

If you're adding a new detection check, ask this question before writing the check, not after finding the false positive.

## Reporting (`reporting/`)

`build_report(scan_result)` produces a `ReportData`: executive summary, an overall risk grade (A–F), findings grouped by OWASP category (each with evidence/remediation/references), a technology/TLS/header discovery summary, and a scan timeline. The risk grade (`risk.py`) is severity-weighted and confidence-discounted — a pile of low-confidence heuristic candidates can't outweigh one confirmed critical.

Renderers (`renderers/`) are independent: `json_renderer.py` and the dataclass-to-dict path in `serialize.py` are the canonical machine-readable form; `markdown_renderer.py` and `html_renderer.py` are Jinja2 templates; `pdf_renderer.py` uses `xhtml2pdf` (pure-Python, no native GTK/Cairo dependency) rendering the same HTML template. `html_renderer.py`'s Jinja environment uses `autoescape=True` unconditionally rather than `select_autoescape(["html"])` — the latter decides based on the template *filename* ending in `.html`, and the actual template is named `report.html.jinja2`, so it never matched and autoescaping was silently off. That was a real stored-XSS-in-report bug: finding titles/evidence come from scanned target content, so unescaped output let a target inject markup into its own report.

## Safety (`safety/`)

`confirm_authorization(url, interactive=...)` is the one gate every scan entry point goes through before making a single request. Interactively, it's a `y/N` prompt. Non-interactively (CI, `--yes`, Docker), it requires `OWASP_INSPECTOR_AUTHORIZED=1` — there is no way to silently skip confirmation from a script; the environment variable has to be a deliberate, visible choice by whoever runs it.

## CLI (`cli/`)

Typer + Rich. `owasp-inspector <url>` is `scan` with the URL as the only required argument — profile/format/output-dir/max-pages/resume/respect-robots are all optional. `owasp-inspector history` reads a local append-only JSON record of past scans (target, grade, score, finding count) — no database required for this; Postgres (if configured) is only used by the legacy menu.

## Legacy engine

`Logic/`, `UI/`, and `main.py` are the pre-v1 engine: flat modules (not a real installable package) that resolve their own imports via a `sys.path` shim in `main.py`, reachable through the `owasp-inspector-legacy-menu` console script or by running `python UI/{sqli,xss,csrf}_scan.py <url>` directly. It's kept around deliberately, not as dead weight: it's where every deferred feature listed above still lives, and it's a separate, independent code path from `owasp_inspector/` — a bug in one cannot silently affect the other. `pyproject.toml`'s `[tool.ruff] exclude` and this repo's CI intentionally don't hold it to the same lint standard as `owasp_inspector/`; see the comment there for why.
