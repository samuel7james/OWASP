import os
import sys
import argparse
from datetime import datetime

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
    sys.path.append(os.path.join(root, "Data"))
    sys.path.append(os.path.join(root, "UI"))

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker
from scan_utils import resolve_scan_url, discover_parameters, warn_if_no_parameters, finalize_findings

RESULTS_LOG = os.path.join(root, "Data", "xss_scan_results", "results.txt")


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


def run_standalone_xss(url):
    print(f"\n{'='*60}")
    print(f"      STANDALONE XSS SCANNER")
    print(f"{'='*60}")

    url, _ = resolve_scan_url(url)
    print(f"[*] Target: {url}")

    checker = URLVulnerabilityChecker()
    checker.current_target_url = url

    targets = discover_parameters(checker, url)
    if not warn_if_no_parameters(targets):
        checker.generate_report(url)
        print(f"\n{'='*60}\n      SCAN COMPLETE\n{'='*60}")
        return

    print(f"\n[+] Starting built-in XSS checks...")
    checker.check_xss_builtin(url, targets)
    checker.check_xss_advanced_payloads(url, targets)

    confirmed, candidates = finalize_findings(checker)
    print(f"\n[*] Summary: {len(confirmed)} confirmed, {len(candidates)} candidate/suspected")
    _log_results(url, confirmed, candidates)
    checker.generate_report(url)

    print(f"\n{'='*60}\n      SCAN COMPLETE\n{'='*60}")


def main():
    target = input("\nEnter URL Target: ").strip()
    if not target:
        return
    run_standalone_xss(target)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone XSS Scanner")
        parser.add_argument("url", help="Target URL to scan")
        args = parser.parse_args()
        run_standalone_xss(args.url)
    else:
        main()
