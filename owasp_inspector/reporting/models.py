from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from owasp_inspector.core.models import Finding
from owasp_inspector.discovery.models import DiscoveryResult

SCHEMA_VERSION = "1.0"


@dataclass
class RiskScore:
    score: int  # 0 (no risk found) - 100 (severe)
    grade: str  # A (best) .. F (worst)
    severity_counts: dict[str, int]
    confirmed_count: int
    manual_verification_count: int


@dataclass
class ReportData:
    schema_version: str
    scan_id: str
    target_url: str
    final_url: str
    generated_at: datetime
    duration_seconds: float | None
    findings: list[Finding]
    discovery: DiscoveryResult
    risk: RiskScore
    executive_summary: str
    timeline: list[dict] = field(default_factory=list)
