from __future__ import annotations

import hashlib
import re
import urllib.parse

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_ID_PARAM_RE = re.compile(r"^(id|uid|user_?id|account_?id|order_?id|invoice_?id|profile_?id)$", re.IGNORECASE)


def _candidate_id_urls(url: str) -> list[tuple[str, str, str]]:
    """Return (param, original_value, tampered_url) for each numeric ID-like query param."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    out = []
    for param, values in query.items():
        if not _ID_PARAM_RE.match(param) or not values or not values[0].isdigit():
            continue
        value = values[0]
        new_query = dict(query)
        new_query[param] = [str(int(value) + 1)]
        tampered_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)))
        out.append((param, value, tampered_url))
    return out


def _body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


@register_module
class IdorModule(Module):
    """Heuristic horizontal-access-control probe: tampers numeric ID-like query
    parameters found during the crawl and flags cases where a different 200 OK
    response comes back without re-authenticating.

    This cannot confirm real IDOR — that requires two distinct authenticated
    identities to prove unauthorized cross-account access, which this engine
    doesn't have in v1. Every finding is low-confidence and explicitly
    manual-verification-flagged.
    """

    name = "idor"
    owasp_category = "A01:2021-Broken Access Control"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()

        for url in discovery.crawled_urls:
            for param, original_value, tampered_url in _candidate_id_urls(url):
                if tampered_url in seen:
                    continue
                seen.add(tampered_url)

                baseline = await context.http.get(url)
                tampered = await context.http.get(tampered_url)
                if baseline is None or tampered is None:
                    continue
                if baseline.status_code != 200 or tampered.status_code != 200:
                    continue
                if _body_hash(baseline.text) == _body_hash(tampered.text):
                    continue

                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title=f"Potential IDOR via '{param}' parameter",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        description=(
                            f"Changing '{param}' from {original_value} to a different value returned a "
                            "different 200 OK response without re-authenticating. This alone does not "
                            "confirm unauthorized access to another user's data."
                        ),
                        url=url,
                        parameter=param,
                        evidence=f"Baseline URL: {url}\nTampered URL: {tampered_url}",
                        remediation=(
                            "Verify server-side that the authenticated user is authorized to access the "
                            "specific record referenced by this identifier, not just that a record exists."
                        ),
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                        manual_verification_recommended=True,
                    )
                )
        return findings
