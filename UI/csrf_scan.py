import argparse
import os
import sys
from datetime import datetime

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
    sys.path.append(os.path.join(root, "Data"))
    sys.path.append(os.path.join(root, "UI"))

from Recon.framework_detector import detect_framework
from scan_utils import (
    confirm_scan_authorization,
    discover_parameters,
    finalize_findings,
    resolve_scan_url,
    warn_if_no_parameters,
)
from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

from owasp_inspector.core.exceptions import AuthorizationError

RESULTS_LOG = os.path.join(root, "Data", "csrf_scan_results", "results.txt")


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


def run_standalone_csrf(url):
    print(f"\n{'='*60}")
    print("      STANDALONE CSRF SCANNER")
    print(f"{'='*60}")

    confirm_scan_authorization(url)

    url, _ = resolve_scan_url(url)
    print(f"[*] Target: {url}")

    print("\n[+] Phase 1: Framework Detection...")
    framework_info = detect_framework(url)
    fw_name = framework_info.get('framework', 'unknown')
    fw_conf = framework_info.get('confidence', 'none')
    print(f"    [*] Detected Framework: {fw_name} (confidence: {fw_conf})")
    if framework_info.get('evidence'):
        for ev in framework_info['evidence'][:5]:
            print(f"        - {ev}")

    print("\n[+] Phase 2: CSRF Vulnerability Scanning...")
    checker = URLVulnerabilityChecker(interactive=False)
    checker.current_target_url = url

    targets = discover_parameters(checker, url)
    if not warn_if_no_parameters(targets):
        checker.generate_report(url)
        print(f"\n{'='*60}\n      SCAN COMPLETE\n{'='*60}")
        return

    print("\n[+] Starting CSRF vulnerability checks...")
    checker.check_csrf_vulnerabilities(url, targets=targets)

    confirmed, candidates = finalize_findings(checker)
    print(f"\n[*] Summary: {len(confirmed)} confirmed, {len(candidates)} candidate/suspected")
    _log_results(url, confirmed, candidates)
    checker.generate_report(url)

    print(f"\n{'='*60}\n      SCAN COMPLETE\n{'='*60}")


def main():
    target = input("\nEnter URL Target: ").strip()
    if not target:
        return
    run_standalone_csrf(target)


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            parser = argparse.ArgumentParser(description="Standalone CSRF Scanner")
            parser.add_argument("url", help="Target URL to scan")
            args = parser.parse_args()
            run_standalone_csrf(args.url)
        else:
            main()
    except AuthorizationError as exc:
        print(f"[-] {exc}")
        sys.exit(1)
