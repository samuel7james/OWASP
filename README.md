# OWASP Inspector

An automated OWASP Top 10 assessment engine. Give it one URL; it discovers the target and runs every applicable assessment module automatically, then writes a professional report.

```
owasp-inspector https://target.com
```

No scanner selection, no manual workflow — currently covers 9 of the 10 OWASP Top 10 (2021) categories:

- **A01 Broken Access Control** — CSRF (missing/removable/tampered token, method-based bypasses, token-entropy analysis) and a heuristic IDOR probe
- **A02 Cryptographic Failures** — cookies missing `Secure`, deprecated TLS versions, sensitive data in URLs, mixed-content form submission
- **A03 Injection** — SQLi (error-based, UNION, boolean/time-based blind, auth-bypass) and reflected XSS (context-aware payload sweep)
- **A04 Insecure Design** — framework debug-mode/stack-trace disclosure (Django, Flask/Werkzeug, PHP, ASP.NET, Rails, raw Java/Node traces)
- **A05 Security Misconfiguration** — missing security headers, unverifiable TLS certificates, exposed `.git`/`.env`/`.DS_Store`
- **A06 Vulnerable and Outdated Components** — version-disclosing headers, technology fingerprinting
- **A07 Identification and Authentication Failures** — session cookies missing `HttpOnly`/`SameSite`, login forms over plain HTTP
- **A08 Software and Data Integrity Failures** — cross-origin scripts/stylesheets loaded without Subresource Integrity, exposed source maps
- **A10 Server-Side Request Forgery** — heuristic canary probes

**A09 (Security Logging and Monitoring Failures) is not covered, on purpose.** It's about server-side log completeness and alerting — not something observable from outside via HTTP probing no matter how the target is scanned. Real DAST tools don't claim to test it either; this engine won't fake a check just to fill the slot.

Heuristic modules (IDOR, SSRF, and the URL-sensitive-parameter check) and anything not explicitly confirmed are clearly flagged as needing manual verification — see [Limitations](#limitations).

A few specialized checks from the original engine haven't been ported into this automated flow yet — stored/DOM/CSP-bypass XSS, SQLMap integration, CSRF's SameSite/CORS/CRLF/clickjacking checks, and second-session-based CSRF bypasses. They're still available through the [legacy menu](#legacy-single-category-menu) below; see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for what's deferred in each module and why.

Use it only on systems you own or have explicit permission to test.

**More docs:** [Architecture](docs/ARCHITECTURE.md) · [User Guide](docs/USER_GUIDE.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Screenshots

Real output from a real scan — `owasp-inspector` run against a small, deliberately-vulnerable local Flask app (unpatched SQL string concatenation, an unescaped reflected parameter, a token-less form, missing security headers) written just to produce these two images. Not a staged mockup and not a scan of anyone else's site.

<p align="center"><img src="docs/screenshots/terminal.svg" alt="Terminal output of an owasp-inspector scan showing a findings-by-severity table and an F (100/100) risk grade" width="820"></p>

<p align="center"><img src="docs/screenshots/html_report.png" alt="The HTML report's executive summary, risk grade, and severity breakdown" width="820"></p>

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
owasp-inspector https://target.com --resume   # reuse cached discovery instead of re-crawling
```

| Option | Purpose |
|---|---|
| `--format, -f` | Comma-separated: `json`, `markdown`, `html`, `pdf` (default `html,json`) |
| `--profile, -p` | `fast`, `thorough` (default), or `stealth` — controls concurrency, timeouts, and per-host request pacing |
| `--max-pages` | Crawl page limit during discovery (default 40) |
| `--output-dir, -o` | Where reports are written (default `Data/reports/`) |
| `--yes, -y` | Skip the interactive authorization prompt (same as `OWASP_INSPECTOR_AUTHORIZED=1`) |
| `--resume` | Reuse the cached discovery result for this exact URL (if one completed in the last hour) instead of re-crawling. Only the discovery phase is cached — modules always run fresh, since they have no persisted internal progress to resume from. |
| `--respect-robots` | Honor `robots.txt` `Disallow` rules during the crawl. **Off by default** — robots.txt is a crawler-politeness convention for search engines, not access control, and this only runs after you've confirmed authorization. A real authorized test target with `Disallow: /` in its robots.txt otherwise blinds the crawl entirely. |

Copy `.env.example` to `.env` to configure optional Postgres reporting, HTTP tuning, and CSRF authenticated-scan credentials — every value is optional and the scanner works with none of it set.

## Docker

```bash
docker build -t owasp-inspector .
docker run --rm -e OWASP_INSPECTOR_AUTHORIZED=1 -v "$(pwd)/reports:/app/Data/reports" \
  owasp-inspector https://target.com --yes -o Data/reports
```

The interactive authorization prompt doesn't work in a non-interactive container, so `OWASP_INSPECTOR_AUTHORIZED=1` (or `--yes`) is required — the image never defaults this on for you. Mount a host directory over `/app/Data/reports` to get reports out of the container. See [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md#docker) for the legacy-menu entry point and more detail.

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
- A09 (Logging and Monitoring Failures) is not covered — see above, it isn't observable via external HTTP scanning at all, not a gap in effort.
- `--resume` only skips re-crawling; it does not resume a scan mid-module. If the process is killed while a module is running, re-run the scan (discovery will be reused if still fresh).

## License and responsibility

You are responsible for how you use this software. Unauthorized scanning of third-party systems may be illegal. Obtain written permission before testing any application you do not own.
