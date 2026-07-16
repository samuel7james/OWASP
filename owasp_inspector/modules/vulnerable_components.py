from __future__ import annotations

import re

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)/(\d+(?:\.\d+)+)")
_REFERENCE = "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"


@register_module
class VulnerableComponentsModule(Module):
    """Flags version-disclosing headers and the Phase 4 technology fingerprint
    as candidates to check against a CVE database. Deliberately does not call
    a live CVE API in v1 (would need an offline/rate-limited-friendly data
    source and a real product/version-to-CVE mapping to be trustworthy) — every
    finding here is informational and explicitly manual-verification-flagged.
    """

    name = "vulnerable-components"
    owasp_category = "A06:2021-Vulnerable and Outdated Components"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        findings: list[Finding] = []
        headers_lower = {k.lower(): v for k, v in discovery.headers.items()}

        for header_name in ("server", "x-powered-by"):
            value = headers_lower.get(header_name)
            if not value:
                continue
            for product, version in _VERSION_RE.findall(value):
                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title=f"Version-disclosing component detected: {product} {version}",
                        severity=Severity.INFO,
                        confidence=Confidence.LOW,
                        description=(
                            f"The `{header_name}` header advertises {product} version {version}. "
                            "This does not confirm a vulnerability by itself."
                        ),
                        url=discovery.final_url,
                        evidence=f"{header_name}: {value}",
                        remediation=(
                            f"Check {product} {version} against a CVE database (NVD, OSV.dev) and "
                            "upgrade if a known vulnerability applies. Consider suppressing version "
                            "strings from response headers regardless of outcome."
                        ),
                        references=[_REFERENCE],
                        manual_verification_recommended=True,
                    )
                )

        if discovery.fingerprint.technology != "unknown":
            findings.append(
                Finding(
                    module=self.name,
                    owasp_category=self.owasp_category,
                    title=f"Technology fingerprint: {discovery.fingerprint.technology}",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    description="Detected via header/cookie/HTML signatures — cross-check the specific version in use against CVE databases.",
                    url=discovery.final_url,
                    evidence="; ".join(discovery.fingerprint.evidence) or None,
                    remediation="Identify the exact version in use and verify it against NVD/OSV.dev.",
                    references=[_REFERENCE],
                    manual_verification_recommended=True,
                )
            )

        return findings
