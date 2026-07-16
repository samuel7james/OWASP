import argparse
import os
import sys
from datetime import datetime

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Data"))
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
    sys.path.append(os.path.join(root, "UI"))

from scan_utils import (
    confirm_scan_authorization,
    discover_parameters,
    finalize_findings,
    resolve_scan_url,
    warn_if_no_parameters,
)
from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

from owasp_inspector.core.exceptions import AuthorizationError

RESULTS_LOG = os.path.join(root, "Data", "sqli_scan_results", "results.txt")


def _log_results(url, confirmed, candidates=None):
    os.makedirs(os.path.dirname(RESULTS_LOG), exist_ok=True)
    candidates = candidates or []
    with open(RESULTS_LOG, "a", encoding="utf-8") as handle:
        handle.write(
            f"\n--- {datetime.now().isoformat(timespec='seconds')} | {url} | "
            f"{len(confirmed)} confirmed, {len(candidates)} candidate(s) ---\n"
        )
        for item in confirmed:
            handle.write(f"  [confirmed/{item.get('confidence', '?')}] {item.get('type', 'issue')} param={item.get('parameter', '')}\n")
        for item in candidates:
            handle.write(f"  [{item.get('status', 'candidate')}/{item.get('confidence', '?')}] {item.get('type', 'issue')} param={item.get('parameter', '')}\n")


def run_standalone_sqli(url):
    print(f"\n{'='*60}")
    print("      STANDALONE SQLi SCANNER")
    print(f"{'='*60}")

    confirm_scan_authorization(url)

    url, _ = resolve_scan_url(url)
    print(f"[*] Target: {url}")

    checker = URLVulnerabilityChecker()
    checker.current_target_url = url

    targets = discover_parameters(checker, url)
    if not warn_if_no_parameters(targets):
        checker.generate_report(url)
        print(f"\n{'='*60}\n      SCAN COMPLETE\n{'='*60}")
        return

    param_file = os.path.join(root, "Data", "Parameters", "sqli_parameters.txt")
    os.makedirs(os.path.dirname(param_file), exist_ok=True)
    with open(param_file, "w") as f:
        for meth in ['get', 'post', 'cookie']:
            for t in targets.get(meth, []):
                turl = t['url']
                plist = ",".join(t.get('params', []))
                if meth == 'get':
                    qs = "&".join(f"{p}=*" for p in t.get('params', []))
                    f.write(f"GET|{turl}?{qs}||{plist}\n")
                elif meth == 'post':
                    qs = "&".join(f"{p}=*" for p in t.get('params', []))
                    f.write(f"POST|{turl}|{qs}|{plist}\n")
                else:
                    qs = "&".join(f"{p}=*" for p in t.get('params', []))
                    f.write(f"COOKIE|{turl}|{qs}|{plist}\n")
    print(f"    [*] Saved discovered targets to {param_file}")

    print("\n[+] Starting built-in SQLi checks...")
    sqli_vulns = checker.check_sqli_builtin(url, targets)
    if sqli_vulns:
        print(f"    [!] Built-in checks found {len(sqli_vulns)} potential SQLi!")
    else:
        print("    [-] Built-in checks: No findings.")

    native_sqli = any('SQL Injection' in v['type'] and v.get('confidence') == 'high' for v in sqli_vulns)

    if not native_sqli:
        print("\n[+] Optional SQLMap pass...")
        try:
            checker.check_sql_injection_with_sqlmap()
        except Exception as e:
            print(f"    [-] SQLMap skipped/failed: {e}")
    elif native_sqli:
        print("    [*] High-confidence SQLi found — skipping SQLMap.")

    confirmed, candidates = finalize_findings(checker)
    print(f"\n[*] Summary: {len(confirmed)} confirmed, {len(candidates)} candidate/suspected")
    _log_results(url, confirmed, candidates)
    checker.generate_report(url)

    print(f"\n{'='*60}\n      SCAN COMPLETE\n{'='*60}")


def main():
    target = input("\nEnter URL Target: ").strip()
    if not target:
        return
    run_standalone_sqli(target)


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            parser = argparse.ArgumentParser(description="Standalone SQLi Scanner")
            parser.add_argument("url", help="Target URL to scan")
            args = parser.parse_args()
            run_standalone_sqli(args.url)
        else:
            main()
    except AuthorizationError as exc:
        print(f"[-] {exc}")
        sys.exit(1)
