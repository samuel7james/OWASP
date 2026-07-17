from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from owasp_inspector.core.exceptions import ScanError

_ALLOWED_TRANSITIONS = {
    "queued": {"running", "failed"},
    "running": {"paused", "done", "failed"},
    "paused": {"running", "failed"},
    "done": set(),
    "failed": set(),
}


class ScanState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    DONE = "done"
    FAILED = "failed"


@dataclass
class ScanEvent:
    state: ScanState
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    detail: str | None = None


class Scan:
    """Tracks a single scan run's state transitions for timeline reporting.

    Not what powers the CLI's `--resume` flag — that reuses a cached
    `DiscoveryResult` (see `core/discovery_cache.py`) and has nothing to do
    with this class's PAUSED state, which no caller currently transitions
    into. `pause`/`resume` exist as a complete, tested state machine ready
    for a future caller (e.g. a rate-limit backoff or a manual-interrupt
    handler) rather than as speculative/unused API that should be deleted;
    unlike a feature deferred at a specific commit, there's no single
    "wire this up" point to defer to.
    """

    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.state = ScanState.QUEUED
        self.history: list[ScanEvent] = [ScanEvent(ScanState.QUEUED)]

    def transition(self, new_state: ScanState, detail: str | None = None) -> None:
        allowed = _ALLOWED_TRANSITIONS[self.state.value]
        if new_state.value not in allowed:
            raise ScanError(f"Invalid scan state transition: {self.state.value} -> {new_state.value}")
        self.state = new_state
        self.history.append(ScanEvent(new_state, detail=detail))

    def start(self) -> None:
        self.transition(ScanState.RUNNING)

    def pause(self, detail: str | None = None) -> None:
        self.transition(ScanState.PAUSED, detail)

    def resume(self) -> None:
        self.transition(ScanState.RUNNING)

    def complete(self) -> None:
        self.transition(ScanState.DONE)

    def fail(self, detail: str | None = None) -> None:
        self.transition(ScanState.FAILED, detail)

    @property
    def duration_seconds(self) -> float | None:
        if len(self.history) < 2:
            return None
        return (self.history[-1].at - self.history[0].at).total_seconds()
