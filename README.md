# Web Vulnerability Scanner (SQLi, XSS, CSRF)

A Python command-line tool for testing web applications against three common vulnerability classes:

- **SQL injection (SQLi)** — error-based, boolean, and optional SQLMap confirmation
- **Cross-site scripting (XSS)** — reflected, stored, DOM, CSP bypass, and payload fuzzing
- **Cross-site request forgery (CSRF)** — token checks, framework-aware tests, and PoC HTML generation

Use it only on systems you own or have explicit permission to test.

## Quick start

```bash
pip install -r requirements.txt
python main.py
```

Or install it as a package and use the console command:

```bash
pip install -e .
owasp-inspector
```

Copy `.env.example` to `.env` to configure optional Postgres reporting, HTTP tuning, and CSRF authenticated-scan credentials — every value is optional and the scanner works with none of it set.

You will see a short menu:

```
1) SQLi scan
2) XSS scan
3) CSRF scan
4) Exit
```

Each option asks for a target URL only.

**Use a page with inputs**, not a site homepage. Good test URLs:

```
https://demo.testfire.net/search.jsp?query=test
https://demo.testfire.net/login.jsp
```

The scanner probes connectivity, discovers forms/query params, retries with a longer timeout if the first pass finds nothing, then runs the vulnerability checks.

## What each scan does

### SQLi scan

1. Crawls the target page for GET/POST parameters and forms.
2. Runs built-in SQLi checks using payloads from `Data/Payloads/sqli_payloads.json`.
3. Optionally runs **SQLMap** automatically if built-in checks find nothing (requires `sqlmap` on PATH).

Results are printed to the terminal, appended to `Data/sqli_scan_results/results.txt`, and optionally saved to PostgreSQL if a database is configured.

### XSS scan

1. Discovers injectable parameters the same way as the SQLi scan.
2. Runs the built-in XSS engine (reflected, stored, DOM, WAF-aware, and advanced payload fuzzing).
3. Writes a summary to `Data/xss_scan_results/results.txt`.

### CSRF scan

1. Detects the web framework (PHP, Django, Laravel, etc.) using signature files.
2. Finds forms and state-changing endpoints.
3. Tests for missing tokens, weak validation, SameSite issues, and common bypasses.
4. Saves findings to `Data/csrf_scan_results/results.txt` and PoC HTML files under `Data/csrf_scan_results/poc_exploits/`.

## Optional tools and settings

| Tool / setting | Purpose |
|----------------|---------|
| **sqlmap** | Deeper SQLi confirmation when enabled in the SQLi scan |
| **PostgreSQL** | Stores scan metadata and reports (optional; scans work without it) |
| `SCAN_HTTP_TIMEOUT=30` | HTTP timeout in seconds for slow targets |

Create a `.env` file in the project root to configure the database:

```env
DB_HOST=localhost
DB_DATABASE=vulnerability_scanner
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432
```

If PostgreSQL is not running, the scanner still works — you will see a brief connection notice and results remain in the terminal and log files.

## Command-line usage

Each scanner can also be run directly:

```bash
python UI/sqli_scan.py https://example.com/page?id=1
python UI/xss_scan.py https://example.com/search?q=test
python UI/csrf_scan.py https://example.com/account
```

## Limitations

- The tool performs active probing. It can generate many HTTP requests against a target.
- Findings are heuristic. Always verify reported issues manually before reporting them in a bug bounty or audit.
- **0 findings usually means the wrong URL, not a broken scanner.** Homepages and marketing sites often have no injectable parameters; production sites are typically hardened.
- Network firewalls, WAFs, or unreachable hosts will produce empty results — the scanner prints a connectivity warning when the target cannot be reached.
- Confirmed vs candidate findings: the terminal report shows both; candidates need manual verification (`SCAN_SHOW_CANDIDATES=1` prints all candidates in the DB report).
- It focuses on SQLi, XSS, and CSRF only.

## License and responsibility

You are responsible for how you use this software. Unauthorized scanning of third-party systems may be illegal. Obtain written permission before testing any application you do not own.
