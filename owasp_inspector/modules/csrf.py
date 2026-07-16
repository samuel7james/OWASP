from __future__ import annotations

import asyncio

from owasp_inspector.core.models import Finding
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module
from owasp_inspector.modules import _legacy_bootstrap  # noqa: F401  (sys.path side effect)
from owasp_inspector.modules._legacy_common import convert_legacy_finding


def _run_sync(url: str) -> list[dict]:
    from Scanner_vulnerability import URLVulnerabilityChecker
    from vulnerability_scan.findings import split_findings

    checker = URLVulnerabilityChecker()
    checker.current_target_url = url
    targets = checker.discover_parameters(url)
    checker.check_csrf_vulnerabilities(url, targets)
    confirmed, candidates = split_findings(checker.vulnerabilities_found)
    return confirmed + candidates


@register_module
class CsrfModule(Module):
    """Wraps the existing CSRF engine (token/bypass/SameSite/CORS/CRLF checks)
    behind the Module interface. Categorized under A01 (Broken Access
    Control) — the OWASP 2021 Top 10 dropped CSRF as its own category and
    community guidance places it there, since it's fundamentally a failure
    to enforce authorization on a state-changing request.
    """

    name = "csrf"
    owasp_category = "A01:2021-Broken Access Control"

    async def run(self, context: ScanContext) -> list[Finding]:
        raw_findings = await asyncio.to_thread(_run_sync, context.target.url)
        return [
            convert_legacy_finding(f, module=self.name, owasp_category=self.owasp_category, target_url=context.target.url)
            for f in raw_findings
        ]
