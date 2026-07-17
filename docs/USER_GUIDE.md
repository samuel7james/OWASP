# User Guide

This covers everything past the README's quick start: every CLI flag, every environment variable, Docker usage, report formats, `history`, exit codes for CI, and troubleshooting.

Authorization is required before anything else — see [Authorization](#authorization) below. This tool is for systems you own or have explicit written permission to test. Public practice targets like [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), [DVWA](https://github.com/digininja/DVWA), [WebGoat](https://owasp.org/www-project-webgoat/), and [PortSwigger's Web Security Academy](https://portswigger.net/web-security) labs are good places to try it against something real.

## Installation

```bash
git clone <this repo>
cd owasp-inspector
pip install -e .
```

Python 3.10+ is required (`pyproject.toml`'s `requires-python`). For development (running the test suite, linting), install the `dev` extra instead: `pip install -e ".[dev]"`.

## Authorization

Every scan — the automated engine and the legacy menu alike — requires explicit confirmation before making a single request:

- **Interactively**: a `y/N` prompt naming the target.
- **Non-interactively** (scripts, CI, Docker, `--yes`/`-y`): set `OWASP_INSPECTOR_AUTHORIZED=1`. There's no other way to skip the prompt — this is deliberate, so unattended runs still require someone to have made the choice explicitly.

## Running a scan

```bash
owasp-inspector https://target.com
```

`scan` is the implied subcommand — `owasp-inspector <url>` and `owasp-inspector scan <url>` are equivalent. This runs discovery once (crawl, technology fingerprint, TLS inspection, `robots.txt`/`sitemap.xml`), then every applicable module concurrently against that same discovery result, then writes reports.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--profile, -p` | `thorough` | `fast`, `thorough`, or `stealth` — see [Profiles](#profiles) |
| `--max-pages` | `40` | Crawl page limit during discovery |
| `--format, -f` | `html,json` | Comma-separated: `json`, `markdown`, `html`, `pdf` |
| `--output-dir, -o` | `Data/reports/` | Where reports are written |
| `--yes, -y` | off | Skip the interactive authorization prompt (same as `OWASP_INSPECTOR_AUTHORIZED=1`) |
| `--resume` | off | Reuse the cached discovery result for this exact URL if one completed within the last hour, instead of re-crawling |
| `--respect-robots` | off | Honor `robots.txt` `Disallow` rules during the crawl (see [why this defaults off](ARCHITECTURE.md#discovery-discovery)) |

### Profiles

| Profile | Concurrency | Timeout | Retries | Per-host pacing | When to use it |
|---|---|---|---|---|---|
| `fast` | 20 | 10s | 1 | none | Quick pass, small/responsive target, you don't mind noisier traffic |
| `thorough` (default) | 10 | 30s | 2 | 0.1s | Balanced default for most targets |
| `stealth` | 2 | 30s | 3 | 1.5s | Rate-limited or fragile targets, or when you want minimal request bursts |

### `--resume`

Caches the *discovery* phase only (the crawl, fingerprint, TLS check) — the genuinely expensive, independently-re-runnable part — keyed by URL, for one hour. Every module still runs fresh every time; there's no per-module checkpointing, because modules have no persisted internal progress to resume from. If a scan is killed mid-run, just re-run it: discovery is reused if the cache is still fresh, and every module starts clean.

### Exit codes

`owasp-inspector <url>` exits `0` normally, `1` if authorization is declined or the scan itself fails, and **`2` if the overall risk grade is D or F** — useful as a CI gate (`owasp-inspector https://staging.example.com --yes || echo "risky deploy"`).

## Reports

Each run writes one file per requested format to `--output-dir`, named `<scan_id>.<ext>` (e.g. `20260717T134909Z-3a817821.json`). Every report covers:

- An executive summary and an overall risk grade (A–F), severity-weighted and confidence-discounted — a pile of low-confidence heuristic candidates can't outweigh one confirmed critical.
- Findings grouped by OWASP Top 10 (2021) category, each with evidence, confidence, and remediation guidance.
- A technology/TLS/security-header discovery summary.
- A scan timeline.

Every finding that isn't `confirmed` is explicitly marked `manual_verification_recommended` — this is not a hedge, it's a real signal: the IDOR and SSRF modules in particular are single-signal heuristics that cannot confirm a vulnerability on their own (see the README's [Limitations](../README.md#limitations)).

```bash
owasp-inspector history            # list past scans (target, grade, score, finding count)
owasp-inspector history -n 5       # limit to the 5 most recent
```

History is a local, append-only JSON file — no database required. (Postgres, if configured via `.env`, is only used by the legacy menu; the automated engine's reports and history are always plain files.)

## Environment variables

Copy `.env.example` to `.env`. Every value is optional — the scanner works with none of it set.

| Variable | Default | Purpose |
|---|---|---|
| `DB_HOST`, `DB_DATABASE`, `DB_USER`, `DB_PASSWORD`, `DB_PORT` | `localhost` / `vulnerability_scanner` / `postgres` / *(empty)* / `5432` | Optional Postgres backing for the **legacy menu only** |
| `SCAN_HTTP_TIMEOUT` | `30` | HTTP timeout (seconds) |
| `SCAN_HTTP_TIMEOUT_RETRY` | `60` | Timeout used on retry attempts |
| `SCAN_JITTER` | `0` | Random per-request delay jitter (seconds) |
| `SCAN_CRAWL_TIMEOUT` | `10` | Per-request timeout during crawling |
| `SCAN_CRAWL_THREADS` | `8` | Legacy crawl concurrency (menu scanners) |
| `SCAN_CRAWL_LIMIT` | `40` | Legacy crawl page limit (use `--max-pages` for the automated engine) |
| `SCAN_PARAM_LINK_LIMIT` | `200` | Cap on links considered for parameter extraction |
| `SCAN_TRAINING_CRAWL_LIMIT` | `40` | Legacy crawl limit for the auth-target trainer |
| `SCAN_RECON_TIMEOUT` | `30` | Timeout for recon/fingerprinting requests |
| `SCAN_CONNECT_TIMEOUT`, `SCAN_PROBE_CONNECT_TIMEOUT` | `15` | Connection-establishment timeouts |
| `SCAN_REQUEST_DELAY` | `0` | Fixed delay between requests (seconds) |
| `SCAN_BACKOFF_SECONDS` | `0` | Base backoff for retry attempts |
| `SCAN_PROXY` | *(empty)* | Route traffic through a proxy (e.g. Burp/ZAP) |
| `SCAN_AUTO_PROXY` | `false` | Auto-detect a locally running proxy |
| `SCAN_SQLI_WORKERS` | `10` | Concurrency for SQLi/XSS/CSRF modules |
| `SCAN_SQLI_PROBE_ALL_COOKIES` | `false` | Probe every cookie for SQLi, including tracking/session cookies normally excluded |
| `SCAN_SHOW_CANDIDATES` | `false` | Include lower-confidence candidate findings in legacy-menu output |
| `CSRF_USER`, `CSRF_PASS`, `CSRF_USER2`, `CSRF_PASS2` | *(empty)* | Credentials for the legacy CSRF engine's authenticated/cross-session checks (`owasp-inspector-legacy-menu` only — the automated `csrf` module doesn't use these; see [Architecture](ARCHITECTURE.md#sqli-xss-csrf-whats-native-whats-deferred)) |

`OWASP_INSPECTOR_AUTHORIZED` (not in `.env` — set it as a real environment variable) is the non-interactive authorization flag; see [Authorization](#authorization).

## Docker

```bash
docker build -t owasp-inspector .
docker run --rm -e OWASP_INSPECTOR_AUTHORIZED=1 \
  -v "$(pwd)/reports:/app/Data/reports" \
  owasp-inspector https://target.com --yes -o Data/reports
```

The image's `ENTRYPOINT` is `owasp-inspector`, so any flag documented above works the same way. Mount a host directory over `/app/Data/reports` (or wherever you point `--output-dir`) to get reports out. The container runs as an unprivileged `scanner` user.

The legacy menu is also present in the image, at a different entrypoint:

```bash
docker run --rm -it --entrypoint owasp-inspector-legacy-menu -e OWASP_INSPECTOR_AUTHORIZED=1 owasp-inspector
```

## Legacy menu

The original menu-driven, single-vulnerability-class scanner (`Logic/`, `UI/`) is a separate code path, unaffected by the automated engine, and is where the deferred SQLi/XSS/CSRF functionality listed in [Architecture](ARCHITECTURE.md#sqli-xss-csrf-whats-native-whats-deferred) still lives:

```bash
owasp-inspector-legacy-menu
```

```text
1) SQLi scan
2) XSS scan
3) CSRF scan
4) Exit
```

Point it at a page with actual inputs, not a homepage — `https://target.com/search?q=test` or a login page, not `https://target.com/`. Each scanner can also be run directly, non-interactively:

```bash
python UI/sqli_scan.py https://target.com/page?id=1
python UI/xss_scan.py https://target.com/search?q=test
python UI/csrf_scan.py https://target.com/account
```

All of these still require authorization confirmation (or `OWASP_INSPECTOR_AUTHORIZED=1`).

## Troubleshooting

**"0 findings" almost always means the wrong URL, not a broken scanner.** Homepages and marketing pages typically have no injectable parameters; production targets are often already hardened. Point it at a page with real inputs — a search box, a form, a URL with query parameters.

**The crawl found 0 pages / 0 targets.** Check whether `robots.txt` is disallowing everything (`Disallow: /`) — this shouldn't block the automated engine by default (`--respect-robots` is off unless you asked for it), but does affect the legacy menu's crawler and anyone using `--respect-robots` explicitly.

**A scan against an old/internal server fails to connect at all.** The HTTP client deliberately supports weak/old TLS configurations (`SECLEVEL=0`) precisely so it can reach exactly this kind of authorized-but-outdated target; if it still can't connect, the target is likely unreachable from where the scan is running (network/firewall), not a TLS negotiation problem.

**A module found nothing but I expected a finding.** Check whether it's one of the modules with known deferred scope — see [Architecture](ARCHITECTURE.md#sqli-xss-csrf-whats-native-whats-deferred) for exactly what each of SQLi/XSS/CSRF does and doesn't cover in the automated engine, and use the legacy menu for the rest.

**The scan seems slow / is generating too much traffic.** Use `--profile stealth` for a rate-limited or fragile target, or `--max-pages` to cap the crawl.

**Grade D/F but the scan "passed" in my script.** Check your exit-code handling — see [Exit codes](#exit-codes); `2` specifically means "risk grade is D or F," distinct from `1` (scan error/declined authorization).
