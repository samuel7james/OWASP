from __future__ import annotations

import re
import urllib.parse

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_SSRF_PARAM_RE = re.compile(
    r"(url|uri|link|src|source|dest|destination|redirect|callback|feed|fetch|proxy|target|next|continue)$",
    re.IGNORECASE,
)

# Safe, non-destructive probes: an unroutable loopback port (should never
# succeed) and the well-known cloud metadata address (classic SSRF target,
# read-only, no exploitation attempted beyond a single GET/POST).
_CANARY_VALUES = ["http://127.0.0.1:0/", "http://169.254.169.254/latest/meta-data/"]

_METADATA_MARKERS = ("ami-id", "instance-id", "iam/security-credentials", "computeMetadata", "instance/")


def _inject_query_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    query[param] = [value]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query, doseq=True)))


def _suspicious_evidence(text: str, canary: str) -> str | None:
    if any(marker in text for marker in _METADATA_MARKERS):
        return f"Response body contains cloud-metadata-like content after probing with {canary}"
    return None


@register_module
class SsrfModule(Module):
    """Heuristic SSRF probe: sends safe canary URLs into parameters whose
    names suggest server-side URL fetching and looks for cloud-metadata-like
    content in the response.

    Cannot confirm real SSRF without out-of-band callback infrastructure this
    engine doesn't have — every finding is low-confidence and explicitly
    manual-verification-flagged.
    """

    name = "ssrf"
    owasp_category = "A10:2021-Server-Side Request Forgery"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()

        for target in discovery.targets:
            for param in target.params:
                if not _SSRF_PARAM_RE.search(param):
                    continue
                key = (target.method, target.url, param)
                if key in seen:
                    continue
                seen.add(key)

                for canary in _CANARY_VALUES:
                    if target.method == "get":
                        response = await context.http.get(_inject_query_param(target.url, param, canary))
                    else:
                        response = await context.http.post(target.url, data={param: canary})
                    if response is None:
                        continue

                    evidence = _suspicious_evidence(response.text, canary)
                    if not evidence:
                        continue

                    findings.append(
                        Finding(
                            module=self.name,
                            owasp_category=self.owasp_category,
                            title=f"Potential SSRF via '{param}' parameter",
                            severity=Severity.HIGH,
                            confidence=Confidence.LOW,
                            description=(
                                f"Parameter '{param}' accepts URL-like input, and probing it with "
                                f"{canary} produced a response suggesting the server fetched it."
                            ),
                            url=target.url,
                            parameter=param,
                            evidence=evidence,
                            remediation=(
                                "Validate and allowlist any server-side-fetched URLs/hosts; block "
                                "requests to private, link-local, and cloud-metadata address ranges."
                            ),
                            references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                            manual_verification_recommended=True,
                        )
                    )
        return findings
