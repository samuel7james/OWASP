from __future__ import annotations

import re
import urllib.parse
import uuid

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
_REFERENCE = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"

_GIT_HEAD_RE = re.compile(r"^ref:\s+refs/")
_ENV_LINE_RE = re.compile(r"^[A-Z_][A-Z0-9_]*=", re.MULTILINE)
_DS_STORE_MAGIC = b"\x00\x00\x00\x01Bud1"

# (path, content-matcher, title, severity) — each matcher is a strong,
# format-specific signature (not just "got a 200") to avoid false positives
# from soft-404 pages that return 200 for anything.
_SENSITIVE_PATH_CHECKS = [
    ("/.git/HEAD", lambda r: bool(_GIT_HEAD_RE.match(r.text.strip())), "Exposed .git repository (HEAD readable)", Severity.HIGH),
    ("/.git/config", lambda r: "[core]" in r.text, "Exposed .git repository (config readable)", Severity.HIGH),
    ("/.env", lambda r: bool(_ENV_LINE_RE.search(r.text)) and "<html" not in r.text.lower(), "Exposed .env file", Severity.CRITICAL),
    ("/.DS_Store", lambda r: r.content.startswith(_DS_STORE_MAGIC), "Exposed .DS_Store file", Severity.LOW),
]


@register_module
class MisconfigurationModule(Module):
    """Missing security headers and TLS trust issues read directly from the
    Phase 4 discovery result (zero extra requests) plus a bounded set of
    sensitive-path exposure checks with a soft-404 baseline probe first, so a
    server that returns 200 for everything doesn't produce false positives.
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
                    references=[_REFERENCE],
                )
            )

        findings.extend(await self._check_sensitive_paths(context))
        return findings

    async def _check_sensitive_paths(self, context: ScanContext) -> list[Finding]:
        base_url = context.discovery.final_url
        canary_path = f"/__owasp_inspector_probe_{uuid.uuid4().hex}"
        baseline = await context.http.get(urllib.parse.urljoin(base_url, canary_path))
        if baseline is not None and baseline.status_code == 200:
            return []  # soft-404: server returns 200 for anything, these checks would be unreliable

        findings: list[Finding] = []
        for path, matcher, title, severity in _SENSITIVE_PATH_CHECKS:
            url = urllib.parse.urljoin(base_url, path)
            response = await context.http.get(url)
            if response is None or response.status_code != 200:
                continue
            try:
                matched = matcher(response)
            except Exception:
                continue
            if not matched:
                continue
            findings.append(
                Finding(
                    module=self.name,
                    owasp_category=self.owasp_category,
                    title=title,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    description=f"{url} is publicly accessible and matches the expected format of a sensitive file.",
                    url=url,
                    remediation=f"Remove or block public access to {path}; it should never be deployed to a web-accessible path.",
                    references=[_REFERENCE],
                )
            )
        return findings
