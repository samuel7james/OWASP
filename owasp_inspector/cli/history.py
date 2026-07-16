from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from owasp_inspector.reporting.models import ReportData

_DEFAULT_HISTORY_DIR = Path("Data") / "scan_history"
_HISTORY_FILENAME = "history.jsonl"


@dataclass
class ScanHistoryEntry:
    scan_id: str
    target_url: str
    final_url: str
    generated_at: str
    grade: str
    score: int
    finding_count: int
    report_paths: list[str]


class ScanHistoryStore:
    """Append-only local scan history (JSON Lines) — no database required.

    Genuine resume-from-checkpoint (persisting partial discovery/module state
    mid-scan) is intentionally not implemented: scans complete in seconds to
    minutes with this engine's architecture, not the hours/days a checkpoint
    system exists to protect. Building that machinery now would be exactly
    the kind of speculative feature the engineering standards for this
    project warn against. History gives you a record of past scans instead.
    """

    def __init__(self, history_dir: Path | None = None):
        self.history_dir = history_dir or _DEFAULT_HISTORY_DIR
        self.history_file = self.history_dir / _HISTORY_FILENAME

    def append(self, report: ReportData, report_paths: list[str]) -> ScanHistoryEntry:
        entry = ScanHistoryEntry(
            scan_id=report.scan_id,
            target_url=report.target_url,
            final_url=report.final_url,
            generated_at=report.generated_at.isoformat(),
            grade=report.risk.grade,
            score=report.risk.score,
            finding_count=len(report.findings),
            report_paths=report_paths,
        )
        self.history_dir.mkdir(parents=True, exist_ok=True)
        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
        return entry

    def list_all(self) -> list[ScanHistoryEntry]:
        if not self.history_file.exists():
            return []
        entries = []
        with open(self.history_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(ScanHistoryEntry(**json.loads(line)))
        return entries
