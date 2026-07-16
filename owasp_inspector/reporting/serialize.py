from __future__ import annotations

from owasp_inspector.core.models import Finding
from owasp_inspector.discovery.models import DiscoveryResult
from owasp_inspector.reporting.models import ReportData


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "module": finding.module,
        "owasp_category": finding.owasp_category,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "description": finding.description,
        "url": finding.url,
        "parameter": finding.parameter,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "references": finding.references,
        "manual_verification_recommended": finding.manual_verification_recommended,
        "found_at": finding.found_at.isoformat(),
    }


def _discovery_to_dict(discovery: DiscoveryResult) -> dict:
    return {
        "target_url": discovery.target_url,
        "final_url": discovery.final_url,
        "ok": discovery.ok,
        "status_code": discovery.status_code,
        "headers": discovery.headers,
        "cookies": discovery.cookies,
        "fingerprint": {
            "technology": discovery.fingerprint.technology,
            "confidence": discovery.fingerprint.confidence,
            "evidence": discovery.fingerprint.evidence,
        },
        "tls": {
            "inspected": discovery.tls.inspected,
            "version": discovery.tls.version,
            "subject": discovery.tls.subject,
            "issuer": discovery.tls.issuer,
            "not_after": discovery.tls.not_after,
            "error": discovery.tls.error,
        },
        "robots": {
            "fetched": discovery.robots.fetched,
            "disallowed_paths": discovery.robots.disallowed_paths,
            "sitemap_urls": discovery.robots.sitemap_urls,
        },
        "sitemap_urls": discovery.sitemap_urls,
        "crawled_urls": discovery.crawled_urls,
        "target_count": len(discovery.targets),
        "injectable_param_count": discovery.injectable_param_count,
    }


def report_to_dict(report: ReportData) -> dict:
    """Explicit, versioned schema for the JSON report — deliberately not a
    blind `dataclasses.asdict()` dump, so internal-only fields (e.g. the
    RobotFileParser instance on RobotsInfo) never leak into the output and
    the schema stays stable independent of internal dataclass shape."""
    return {
        "schema_version": report.schema_version,
        "scan_id": report.scan_id,
        "target_url": report.target_url,
        "final_url": report.final_url,
        "generated_at": report.generated_at.isoformat(),
        "duration_seconds": report.duration_seconds,
        "executive_summary": report.executive_summary,
        "risk": {
            "score": report.risk.score,
            "grade": report.risk.grade,
            "severity_counts": report.risk.severity_counts,
            "confirmed_count": report.risk.confirmed_count,
            "manual_verification_count": report.risk.manual_verification_count,
        },
        "discovery": _discovery_to_dict(report.discovery),
        "findings": [_finding_to_dict(f) for f in report.findings],
        "timeline": report.timeline,
    }
