# OWASP Inspector

An automated OWASP Top 10 assessment engine. Give it one URL; it discovers the target and runs every applicable assessment module automatically, then writes a professional report.

```
owasp-inspector https://target.com
```

No scanner selection, no manual workflow — currently covers:

- **A01 Broken Access Control** — CSRF (token/bypass/SameSite/CORS/CRLF checks) and a heuristic IDOR probe
- **A03 Injection** — SQLi (error/union/boolean/time-based, optional SQLMap) and XSS (reflected/stored/DOM/CSP-bypass)
- **A05 Security Misconfiguration** — missing security headers, unverifiable TLS certificates
- **A06 Vulnerable and Outdated Components** — version-disclosing headers, technology fingerprinting
- **A10 Server-Side Request Forgery** — heuristic canary probes

Heuristic modules (IDOR, SSRF) and anything not explicitly confirmed are clearly flagged as needing manual verification — see [Limitations](#limitations).

Use it only on systems you own or have explicit permission to test.

## Quick start

```bash
pip install -e .
owasp-inspector https://target.com
```

You'll be asked to confirm you're authorized to test the target, then the scan runs automatically: discovery (crawl, fingerprinting, TLS/robots/sitemap), every applicable module, then a report. By default it writes an HTML and a JSON report to `Data/reports/`.

```bash
owasp-inspector https://target.com --format json,markdown,html,pdf --profile stealth -o ./my-reports
owasp-inspector history                 # list past scans
owasp-inspector https://target.com -y   # skip the interactive authorization prompt (CI/automation)
```

| Option | Purpose |
|---|---|
| `--format, -f` | Comma-separated: `json`, `markdown`, `html`, `pdf` (default `html,json`) |
| `--profile, -p` | `fast`, `thorough` (default), or `stealth` — controls concurrency, timeouts, and per-host request pacing |
| `--max-pages` | Crawl page limit during discovery (default 40) |
| `--output-dir, -o` | Where reports are written (default `Data/reports/`) |
| `--yes, -y` | Skip the interactive authorization prompt (same as `OWASP_INSPECTOR_AUTHORIZED=1`) |

Copy `.env.example` to `.env` to configure optional Postgres reporting, HTTP tuning, and CSRF authenticated-scan credentials — every value is optional and the scanner works with none of it set.

## Reports

Each scan produces a `ReportData` covering an executive summary, an overall risk grade (A–F, severity-weighted and confidence-discounted so a pile of low-confidence heuristic candidates can't outweigh one confirmed critical), findings grouped by OWASP category with evidence/remediation/references, technology and TLS/header discovery summary, and a scan timeline. Every finding that isn't a `confirmed` result is explicitly marked as needing manual verification.

`owasp-inspector history` lists past scans (target, grade, score, finding count) from a local append-only record — no database required.

## Legacy: single-category menu

The original menu-driven, single-vulnerability-class scanner is still available under a different command, unaffected by the automated engine above:

```bash
owasp-inspector-legacy-menu
```

```
1) SQLi scan
2) XSS scan
3) CSRF scan
4) Exit
```

**Use a page with inputs**, not a site homepage. Good test URLs:

```
https://demo.testfire.net/search.jsp?query=test
https://demo.testfire.net/login.jsp
```

Each scanner can also be run directly:

```bash
python UI/sqli_scan.py https://example.com/page?id=1
python UI/xss_scan.py https://example.com/search?q=test
python UI/csrf_scan.py https://example.com/account
```

All of these also require the authorization confirmation (or `OWASP_INSPECTOR_AUTHORIZED=1`) before scanning.

## Optional tools and settings

| Tool / setting | Purpose |
|----------------|---------|
| **sqlmap** | Deeper SQLi confirmation when enabled in the SQLi module |
| **PostgreSQL** | Stores scan metadata and reports for the legacy menu (optional; scans work without it) |
| `SCAN_HTTP_TIMEOUT=30` | HTTP timeout in seconds for slow targets |

Create a `.env` file in the project root to configure the database:

```env
DB_HOST=localhost
DB_DATABASE=vulnerability_scanner
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432
```

If PostgreSQL is not running, the legacy menu still works — you will see a brief connection notice and results remain in the terminal and log files. (The automated `owasp-inspector <url>` engine doesn't use Postgres at all — its reports and history are files.)

## Limitations

- The tool performs active probing. It can generate many HTTP requests against a target.
- Findings are heuristic. Always verify reported issues manually before reporting them in a bug bounty or audit — every non-`confirmed` finding says so explicitly, and the IDOR/SSRF modules in particular are single-signal probes that cannot confirm a real vulnerability on their own (IDOR would need a second authenticated identity; SSRF would need out-of-band callback infrastructure this engine doesn't have).
- **0 findings usually means the wrong URL, not a broken scanner.** Homepages and marketing sites often have no injectable parameters; production sites are typically hardened.
- Network firewalls, WAFs, or unreachable hosts will produce empty results.
- It does not yet cover A02, A04, A07, A08, or A09 — see `TASKS.md` for the roadmap.

## License and responsibility

You are responsible for how you use this software. Unauthorized scanning of third-party systems may be illegal. Obtain written permission before testing any application you do not own.
