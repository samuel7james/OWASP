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
    checker.check_sqli_builtin(url, targets)
    confirmed, candidates = split_findings(checker.vulnerabilities_found)
    return confirmed + candidates


@register_module
class SqliModule(Module):
    """Wraps the existing built-in SQLi engine (Logic/vulnerability_scan/sqli/)
    behind the Module interface. Runs the legacy synchronous engine in a
    thread rather than a full async rewrite — that engine already works and
    is already tested; a rewrite would add risk for no functional benefit.
    """

    name = "sqli"
    owasp_category = "A03:2021-Injection"

    async def run(self, context: ScanContext) -> list[Finding]:
        raw_findings = await asyncio.to_thread(_run_sync, context.target.url)
        return [
            convert_legacy_finding(f, module=self.name, owasp_category=self.owasp_category, target_url=context.target.url)
            for f in raw_findings
        ]
