from __future__ import annotations

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_SECURITY_HEADERS = {
    "strict-transport-security": (
        "Missing HSTS header",
        Severity.MEDIUM,
        "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains` to enforce HTTPS on every visit.",
        ["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
    ),
    "x-frame-options": (
        "Missing X-Frame-Options header",
        Severity.LOW,
        "Add `X-Frame-Options: DENY` (or a CSP `frame-ancestors` directive) to prevent clickjacking.",
        ["https://owasp.org/www-community/attacks/Clickjacking"],
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        Severity.LOW,
        "Add `X-Content-Type-Options: nosniff` to stop MIME-sniffing-based attacks.",
        ["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy header",
        Severity.MEDIUM,
        "Define a restrictive CSP to reduce the impact of any XSS/data-injection that does occur.",
        ["https://owasp.org/www-community/controls/Content_Security_Policy"],
    ),
}

_ONLY_APPLIES_TO_HTTPS = {"strict-transport-security"}


@register_module
class MisconfigurationModule(Module):
    """Reads directly from the Phase 4 discovery result (headers + TLS) —
    no additional requests of its own. First module to actually demonstrate
    the discovery-engine payoff: one shared crawl/probe, many modules read.
    """

    name = "security-misconfiguration"
    owasp_category = "A05:2021-Security Misconfiguration"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        findings: list[Finding] = []
        headers_lower = {k.lower(): v for k, v in discovery.headers.items()}
        is_https = discovery.final_url.startswith("https://")

        for header, (title, severity, remediation, refs) in _SECURITY_HEADERS.items():
            if header in _ONLY_APPLIES_TO_HTTPS and not is_https:
                continue
            if header in headers_lower:
                continue
            findings.append(
                Finding(
                    module=self.name,
                    owasp_category=self.owasp_category,
                    title=title,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    description=f"Response from {discovery.final_url} did not include the `{header}` header.",
                    url=discovery.final_url,
                    evidence=f"Headers observed: {sorted(headers_lower)}",
                    remediation=remediation,
                    references=refs,
                )
            )

        if is_https and discovery.tls.error:
            findings.append(
                Finding(
                    module=self.name,
                    owasp_category=self.owasp_category,
                    title="TLS certificate not verifiable",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=discovery.tls.error,
                    url=discovery.final_url,
                    evidence=f"Negotiated TLS version: {discovery.tls.version}",
                    remediation="Install a valid certificate from a trusted CA; ensure hostname and expiry are correct.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                )
            )

        return findings
