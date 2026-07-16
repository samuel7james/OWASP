from __future__ import annotations

import re
import urllib.parse

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_REFERENCE = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"

_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_SENSITIVE_PARAM_RE = re.compile(
    r"^(password|passwd|pwd|token|api_?key|secret|access_?token|session_?id|ssn|credit_?card)$",
    re.IGNORECASE,
)


@register_module
class CryptoFailuresModule(Module):
    """Reads from the Phase 4 discovery result: cookie Secure flags, TLS
    protocol version, and sensitive-looking query parameters. All findings
    here are deterministic (a flag is either present in the response or it
    isn't) rather than heuristic probes, so they're reported as confirmed.
    """

    name = "crypto-failures"
    owasp_category = "A02:2021-Cryptographic Failures"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        findings: list[Finding] = []
        is_https = discovery.final_url.startswith("https://")

        if is_https:
            for cookie in discovery.cookie_flags:
                if not cookie.secure:
                    findings.append(
                        Finding(
                            module=self.name,
                            owasp_category=self.owasp_category,
                            title=f"Cookie '{cookie.name}' missing Secure flag",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            description=(
                                f"Cookie '{cookie.name}' is set over HTTPS without the Secure flag, so it "
                                "can also be transmitted over an unencrypted HTTP connection if one exists."
                            ),
                            url=discovery.final_url,
                            remediation="Set the `Secure` attribute on every cookie issued over HTTPS.",
                            references=[_REFERENCE],
                        )
                    )

        if discovery.tls.inspected and discovery.tls.version in _WEAK_TLS_VERSIONS:
            findings.append(
                Finding(
                    module=self.name,
                    owasp_category=self.owasp_category,
                    title=f"Deprecated TLS protocol version negotiated: {discovery.tls.version}",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=f"The server negotiated {discovery.tls.version}, which has known cryptographic weaknesses.",
                    url=discovery.final_url,
                    remediation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 server-side; require TLS 1.2 or newer.",
                    references=[_REFERENCE],
                )
            )

        for url in discovery.crawled_urls:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param in query:
                if _SENSITIVE_PARAM_RE.match(param):
                    findings.append(
                        Finding(
                            module=self.name,
                            owasp_category=self.owasp_category,
                            title=f"Sensitive-looking parameter '{param}' passed in URL",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"URL contains a parameter named '{param}', which commonly carries sensitive "
                                "data. URLs are logged by proxies, browser history, and server access logs."
                            ),
                            url=url,
                            parameter=param,
                            remediation="Pass sensitive values in a POST body or header, never in the URL/query string.",
                            references=[_REFERENCE],
                            manual_verification_recommended=True,
                        )
                    )

        for target in discovery.targets:
            if target.method != "post" or not discovery.final_url.startswith("https://"):
                continue
            if target.url.startswith("http://"):
                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title="Form on an HTTPS page submits over plain HTTP",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description=f"A form is served over HTTPS but its action ({target.url}) is plain HTTP — mixed content.",
                        url=target.url,
                        remediation="Ensure every form action uses HTTPS; never downgrade to HTTP for submission.",
                        references=[_REFERENCE],
                    )
                )

        return findings
