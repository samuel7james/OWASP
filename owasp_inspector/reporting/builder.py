from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from owasp_inspector.reporting.models import SCHEMA_VERSION, ReportData
from owasp_inspector.reporting.risk import calculate_risk
from owasp_inspector.reporting.summary import build_executive_summary

if TYPE_CHECKING:
    from owasp_inspector.core.orchestrator import ScanResult


def build_report(scan_result: ScanResult) -> ReportData:
    """Aggregate a completed scan into the report model every renderer consumes."""
    risk = calculate_risk(scan_result.findings)

    report = ReportData(
        schema_version=SCHEMA_VERSION,
        scan_id=scan_result.scan.scan_id,
        target_url=scan_result.discovery.target_url,
        final_url=scan_result.discovery.final_url,
        generated_at=datetime.now(timezone.utc),
        duration_seconds=scan_result.scan.duration_seconds,
        findings=scan_result.findings,
        discovery=scan_result.discovery,
        risk=risk,
        executive_summary="",
        timeline=[
            {"state": event.state.value, "at": event.at.isoformat(), "detail": event.detail}
            for event in scan_result.scan.history
        ],
    )
    report.executive_summary = build_executive_summary(report)
    return report
