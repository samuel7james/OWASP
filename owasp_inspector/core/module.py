from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from owasp_inspector.core.models import Finding, ScanTarget


class ScanContext:
    """Shared, read-mostly state handed to every module during a scan run.

    Discovery output (crawled pages, forms, parameters, fingerprints) lands
    here in Phase 4 so modules never need to crawl independently.
    """

    def __init__(self, target: ScanTarget, http, settings, discovery=None):
        self.target = target
        self.http = http
        self.settings = settings
        self.discovery = discovery


class Module(ABC):
    """Base class every OWASP assessment module implements.

    The core engine only ever calls `run()` — it never inspects a module's
    internals — so new categories can be added by registering a new `Module`
    subclass without changing `core/` at all.
    """

    name: str
    owasp_category: str

    @abstractmethod
    async def run(self, context: ScanContext) -> list[Finding]: ...
