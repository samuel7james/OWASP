from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ScanTarget:
    """The normalized target a scan runs against, plus any auth/session context modules need."""

    url: str
    cookie: str | None = None


@dataclass
class Finding:
    """A single evidence-backed result produced by an assessment module.

    `owasp_category` is the Top-10 id this maps to (e.g. "A03:2021-Injection"),
    kept as a plain string rather than an enum so new categories/years can be
    added without touching this model.
    """

    module: str
    owasp_category: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    url: str
    parameter: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    manual_verification_recommended: bool = False
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
