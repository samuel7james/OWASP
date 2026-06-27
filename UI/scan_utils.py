"""Shared helpers for SQLi, XSS, and CSRF standalone scanners."""
import os

from Recon.http_client import probe_target


def resolve_scan_url(url, cookie=None):
    """Probe the target and return the reachable URL (after redirects)."""
    timeout = float(os.getenv("SCAN_HTTP_TIMEOUT", "30"))
    result = probe_target(url, cookie=cookie, timeout=timeout)
    if result.get("ok"):
        final = (result.get("final_url") or url).strip()
        if final.rstrip("/") != url.rstrip("/"):
            print(f"[*] Resolved target: {final}")
        return final, True
    print(f"\n[!] Pre-scan probe failed ({result.get('error', 'timeout')})")
    print("    Continuing — parameter discovery will retry with longer timeouts.")
    return url, False


def injectable_param_count(targets):
    return len(targets.get("get", [])) + len(targets.get("post", []))


def discover_parameters(checker, url):
    """Discover parameters with automatic retry on empty results."""
    targets = checker.discover_parameters(url)
    if injectable_param_count(targets) > 0:
        return targets

    print("\n    [*] Retrying parameter discovery with extended timeout...")
    checker._http_timeout = float(os.getenv("SCAN_HTTP_TIMEOUT_RETRY", "45"))
    os.environ.setdefault("SCAN_CRAWL_TIMEOUT", "30")
    return checker.discover_parameters(url)


def warn_if_no_parameters(targets):
    n = injectable_param_count(targets)
    if n == 0:
        print("\n[!] No injectable GET/POST parameters found — scan cannot test anything.")
        print("    Paste a page with inputs, not a bare homepage. Examples:")
        print("      https://demo.testfire.net/search.jsp?query=test")
        print("      https://demo.testfire.net/login.jsp")
        return False
    print(f"\n[+] Ready to test {n} injectable endpoint(s)")
    return True


def finalize_findings(checker):
    from vulnerability_scan.findings import split_findings

    confirmed, candidates = split_findings(checker.vulnerabilities_found)
    _, existing = split_findings(getattr(checker, "scan_candidates", []))
    checker.vulnerabilities_found = confirmed
    checker.scan_candidates = existing + candidates
    return confirmed, candidates
