from __future__ import annotations

from owasp_inspector.reporting.models import ReportData


def build_executive_summary(report: ReportData) -> str:
    total = len(report.findings)
    if total == 0:
        return (
            f"No findings were identified against {report.final_url} during this automated assessment. "
            "This does not guarantee the absence of vulnerabilities — categories requiring authenticated, "
            "multi-account, or business-logic testing are outside what automated scanning alone can confirm."
        )

    severity_parts = [f"{count} {name}" for name, count in report.risk.severity_counts.items() if count]
    counts_str = ", ".join(severity_parts)

    return (
        f"This automated assessment of {report.final_url} identified {total} finding(s) ({counts_str}), "
        f"yielding an overall risk grade of {report.risk.grade} ({report.risk.score}/100). "
        f"{report.risk.confirmed_count} finding(s) are confirmed; "
        f"{report.risk.manual_verification_count} require manual verification before being treated as "
        "confirmed vulnerabilities. Findings are grouped by OWASP Top 10 (2021) category below, each with "
        "evidence, confidence, and remediation guidance."
    )
