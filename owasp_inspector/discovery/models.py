from __future__ import annotations

import urllib.robotparser
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class ProbeResult:
    ok: bool
    final_url: str
    status_code: int | None
    error: str | None = None


@dataclass
class Fingerprint:
    technology: str = "unknown"
    confidence: str = "none"
    evidence: list[str] = field(default_factory=list)


@dataclass
class TlsInfo:
    inspected: bool = False
    version: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    error: str | None = None


@dataclass
class RobotsInfo:
    fetched: bool = False
    disallowed_paths: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    parser: urllib.robotparser.RobotFileParser | None = field(default=None, repr=False, compare=False)

    def allows(self, url: str, user_agent: str = "*") -> bool:
        if not self.fetched or self.parser is None:
            return True
        return self.parser.can_fetch(user_agent, url)


@dataclass
class ParamTarget:
    method: Literal["get", "post"]
    url: str
    params: list[str] = field(default_factory=list)


@dataclass
class DiscoveryResult:
    target_url: str
    final_url: str
    ok: bool
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    tls: TlsInfo = field(default_factory=TlsInfo)
    robots: RobotsInfo = field(default_factory=RobotsInfo)
    sitemap_urls: list[str] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    targets: list[ParamTarget] = field(default_factory=list)

    @property
    def injectable_param_count(self) -> int:
        return sum(len(t.params) for t in self.targets)
