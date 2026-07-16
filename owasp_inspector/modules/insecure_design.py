from __future__ import annotations

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

_REFERENCE = "https://owasp.org/Top10/A04_2021-Insecure_Design/"

# (label, signature substrings) — a debug/diagnostic page left reachable in
# what should be a production deployment is a design/configuration decision,
# not a single bug: it means the framework's debug mode itself was left on.
_DEBUG_SIGNATURES: list[tuple[str, list[str]]] = [
    ("Django debug page", ["Technical 500", "Exception Type:", "Exception Value:", "django.core.handlers"]),
    ("Werkzeug/Flask debugger", ["Werkzeug Debugger", "werkzeug.exceptions", "The debugger caught an exception"]),
    ("PHP error disclosure", ["Fatal error:", "<b>Warning</b>:", "on line <b>"]),
    ("ASP.NET error page", ["Server Error in '/' Application", "Runtime Error", "Exception Details:"]),
    ("Rails debug page", ["ActionController::", "Rails.root:", "app/controllers"]),
    ("Java stack trace", ["Exception in thread", "at java.", "javax.servlet.ServletException"]),
    ("Node.js stack trace", ["at Object.<anonymous>", "at Module._compile", "UnhandledPromiseRejection"]),
]

_MAX_PAGES_TO_CHECK = 5


@register_module
class InsecureDesignModule(Module):
    """Fetches a bounded sample of discovered pages and looks for verbose
    framework debug/error output — a real, safe, deterministic signal (no
    payloads sent, just reading what pages already return). This is one
    concrete, externally-observable proxy for "insecure design": a
    production deployment with debug mode left enabled reflects a design/
    configuration decision, not a one-off bug. It cannot, and does not
    claim to, cover the rest of what A04 means (business-logic flaws,
    missing threat modeling) — that needs a human.
    """

    name = "insecure-design"
    owasp_category = "A04:2021-Insecure Design"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        urls_to_check = [discovery.final_url, *discovery.crawled_urls][:_MAX_PAGES_TO_CHECK]
        seen_signatures: set[str] = set()
        findings: list[Finding] = []

        for url in dict.fromkeys(urls_to_check):
            response = await context.http.get(url)
            if response is None:
                continue

            for label, signatures in _DEBUG_SIGNATURES:
                if label in seen_signatures:
                    continue
                if any(sig in response.text for sig in signatures):
                    seen_signatures.add(label)
                    findings.append(
                        Finding(
                            module=self.name,
                            owasp_category=self.owasp_category,
                            title=f"Debug/diagnostic output exposed: {label}",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            description=(
                                f"{url} returned content matching known {label} output — framework debug "
                                "mode appears enabled, which can leak source paths, environment details, "
                                "and internals useful for further attacks."
                            ),
                            url=url,
                            remediation="Disable framework debug mode in production and return generic error pages instead.",
                            references=[_REFERENCE],
                        )
                    )

        return findings
