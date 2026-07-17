from __future__ import annotations

import re

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_REFERENCE = "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"

_SESSION_COOKIE_RE = re.compile(r"(sess|jsessionid|phpsessid|connect\.sid|auth|token)", re.IGNORECASE)
_LOGIN_PATH_RE = re.compile(r"(login|signin|sign-in|log-in|auth)", re.IGNORECASE)


@register_module
class AuthFailuresModule(Module):
    """Session-cookie hygiene (HttpOnly/SameSite — an XSS-to-session-hijack
    path, squarely an authentication failure per OWASP's A07 description) and
    login-over-plain-HTTP detection. Deterministic, not probabilistic: a flag
    is either present or it isn't, so these are reported as confirmed.
    """

    name = "auth-failures"
    owasp_category = "A07:2021-Identification and Authentication Failures"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        findings: list[Finding] = []

        for cookie in discovery.cookie_flags:
            if not _SESSION_COOKIE_RE.search(cookie.name):
                continue
            if not cookie.httponly:
                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title=f"Session cookie '{cookie.name}' missing HttpOnly flag",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"'{cookie.name}' looks like a session/auth cookie but lacks HttpOnly, so "
                            "JavaScript (including injected via any XSS) can read it and exfiltrate the session."
                        ),
                        url=discovery.final_url,
                        remediation="Set the `HttpOnly` attribute on every session/authentication cookie.",
                        references=[_REFERENCE],
                    )
                )
            if not cookie.samesite or cookie.samesite.lower() == "none":
                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title=f"Session cookie '{cookie.name}' missing SameSite protection",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"'{cookie.name}' has no SameSite attribute (or SameSite=None), so it is sent "
                            "on cross-site requests — a CSRF/session-riding risk."
                        ),
                        url=discovery.final_url,
                        remediation="Set `SameSite=Lax` (or `Strict`) on session cookies unless cross-site delivery is a deliberate, documented requirement.",
                        references=[_REFERENCE],
                    )
                )

        for target in discovery.targets:
            if target.method == "post" and _LOGIN_PATH_RE.search(target.url) and target.url.startswith("http://"):
                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title="Login form submits credentials over plain HTTP",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        description=f"A form at {target.url} looks like a login endpoint and is not served over HTTPS.",
                        url=target.url,
                        remediation="Serve all authentication endpoints exclusively over HTTPS.",
                        references=[_REFERENCE],
                    )
                )

        return findings
