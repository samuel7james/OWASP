from __future__ import annotations

import urllib.parse

from bs4 import BeautifulSoup

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_REFERENCE = "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"


def _is_cross_origin(resource_url: str, page_netloc: str) -> bool:
    return urllib.parse.urlparse(resource_url).netloc not in ("", page_netloc)


@register_module
class SoftwareIntegrityModule(Module):
    """Two concrete, externally-observable A08 signals: cross-origin
    scripts/stylesheets loaded without Subresource Integrity (if that CDN is
    compromised or MITM'd, the browser executes whatever it serves with no
    integrity check — the exact failure mode A08 names CDN usage without
    SRI as an example of), and exposed `.map` source-map files.
    """

    name = "software-integrity"
    owasp_category = "A08:2021-Software and Data Integrity Failures"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        response = await context.http.get(discovery.final_url)
        if response is None:
            return []

        page_netloc = urllib.parse.urlparse(discovery.final_url).netloc
        soup = BeautifulSoup(response.text, "html.parser")
        findings: list[Finding] = []
        checked_map_urls: set[str] = set()

        for tag, attr in (("script", "src"), ("link", "href")):
            for element in soup.find_all(tag):
                resource_url = element.get(attr)
                if not resource_url:
                    continue
                if tag == "link" and element.get("rel") not in (["stylesheet"], ["stylesheet", "preload"]):
                    if "stylesheet" not in (element.get("rel") or []):
                        continue

                absolute_url = urllib.parse.urljoin(discovery.final_url, resource_url)
                if not _is_cross_origin(absolute_url, page_netloc):
                    continue
                if element.get("integrity"):
                    continue

                findings.append(
                    Finding(
                        module=self.name,
                        owasp_category=self.owasp_category,
                        title="Cross-origin resource loaded without Subresource Integrity (SRI)",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"{discovery.final_url} loads {absolute_url} from a third-party origin with "
                            "no `integrity` attribute — if that origin is compromised, the browser executes "
                            "whatever it returns with no verification."
                        ),
                        url=discovery.final_url,
                        remediation="Add an `integrity` (SRI hash) and `crossorigin` attribute to every cross-origin <script>/<link> tag, or self-host the resource.",
                        references=[_REFERENCE],
                    )
                )

                if resource_url.endswith(".js") and absolute_url not in checked_map_urls:
                    checked_map_urls.add(absolute_url)
                    map_response = await context.http.get(absolute_url + ".map")
                    if (
                        map_response is not None
                        and map_response.status_code == 200
                        and "sourcesContent" in (map_response.text or "")
                    ):
                        findings.append(
                            Finding(
                                module=self.name,
                                owasp_category=self.owasp_category,
                                title="Exposed JavaScript source map with embedded source",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                description=f"{absolute_url}.map is publicly accessible and contains original source content.",
                                url=absolute_url + ".map",
                                remediation="Do not deploy `.map` files (or the `sourcesContent` they embed) to production.",
                                references=[_REFERENCE],
                                manual_verification_recommended=True,
                            )
                        )

        return findings
