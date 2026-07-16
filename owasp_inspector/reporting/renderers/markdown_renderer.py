from __future__ import annotations

from owasp_inspector.core.models import Finding
from owasp_inspector.reporting.models import ReportData


def _group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.owasp_category, []).append(finding)
    return grouped


def render_markdown(report: ReportData) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# OWASP Inspector Report — {report.final_url}")
    add("")
    add(f"**Scan ID:** {report.scan_id}  ")
    add(f"**Generated:** {report.generated_at.isoformat()}  ")
    if report.duration_seconds is not None:
        add(f"**Duration:** {report.duration_seconds:.1f}s  ")
    add("")

    add("## Executive Summary")
    add("")
    add(report.executive_summary)
    add("")

    add("## Overall Risk")
    add("")
    add(f"**Grade:** {report.risk.grade} &nbsp;&nbsp; **Score:** {report.risk.score}/100")
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for severity, count in report.risk.severity_counts.items():
        if count:
            add(f"| {severity} | {count} |")
    add("")

    add("## Technology Stack")
    add("")
    fp = report.discovery.fingerprint
    if fp.technology != "unknown":
        add(f"- **Detected:** {fp.technology} (confidence: {fp.confidence})")
    else:
        add("- No technology fingerprint matched.")
    add("")

    add("## Discovery Summary")
    add("")
    add(f"- Pages crawled: {len(report.discovery.crawled_urls)}")
    add(f"- Injectable parameter targets found: {report.discovery.injectable_param_count}")
    add(f"- robots.txt fetched: {report.discovery.robots.fetched}")
    add(f"- TLS inspected: {report.discovery.tls.inspected}" + (f" ({report.discovery.tls.error})" if report.discovery.tls.error else ""))
    add("")

    add("## Findings")
    add("")
    if not report.findings:
        add("No findings.")
    else:
        by_category = _group_by_category(report.findings)
        for category in sorted(by_category):
            add(f"### {category}")
            add("")
            for finding in by_category[category]:
                flag = " _(manual verification recommended)_" if finding.manual_verification_recommended else ""
                add(f"- **[{finding.severity.value.upper()}/{finding.confidence.value}] {finding.title}**{flag}")
                add(f"  - URL: `{finding.url}`")
                if finding.parameter:
                    add(f"  - Parameter: `{finding.parameter}`")
                if finding.evidence:
                    add(f"  - Evidence: {finding.evidence}")
                if finding.remediation:
                    add(f"  - Remediation: {finding.remediation}")
                if finding.references:
                    add(f"  - References: {', '.join(finding.references)}")
                add("")

    add("## Scan Timeline")
    add("")
    for event in report.timeline:
        detail = f" ({event['detail']})" if event.get("detail") else ""
        add(f"- `{event['at']}` — {event['state']}{detail}")

    return "\n".join(lines)
