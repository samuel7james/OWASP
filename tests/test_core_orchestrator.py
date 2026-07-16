from owasp_inspector.core import orchestrator as orchestrator_module
from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module
from owasp_inspector.core.registry import ModuleRegistry
from owasp_inspector.discovery.models import DiscoveryResult


class _GoodModule(Module):
    name = "good"
    owasp_category = "A00:Test"

    async def run(self, context):
        return [
            Finding(
                module=self.name, owasp_category=self.owasp_category, title="found it",
                severity=Severity.LOW, confidence=Confidence.LOW, description="d",
                url=context.target.url,
            )
        ]


class _BrokenModule(Module):
    name = "broken"
    owasp_category = "A00:Test"

    async def run(self, context):
        raise RuntimeError("simulated module failure")


async def _fake_discovery(http, url, max_pages=40):
    return DiscoveryResult(target_url=url, final_url=url, ok=True)


async def test_orchestrator_aggregates_findings_from_all_modules(monkeypatch):
    monkeypatch.setattr(orchestrator_module, "run_discovery", _fake_discovery)
    registry = ModuleRegistry()
    registry.register(_GoodModule)

    result = await orchestrator_module.run_scan("https://example.com", registry=registry)

    assert result.discovery.ok is True
    assert len(result.findings) == 1
    assert result.findings[0].module == "good"
    assert result.scan.state.value == "done"
    assert result.scan.duration_seconds is not None


async def test_orchestrator_isolates_a_failing_module(monkeypatch):
    monkeypatch.setattr(orchestrator_module, "run_discovery", _fake_discovery)
    registry = ModuleRegistry()
    registry.register(_GoodModule)
    registry.register(_BrokenModule)

    result = await orchestrator_module.run_scan("https://example.com", registry=registry)

    # The broken module's exception must not prevent the good module's findings
    # from coming back, and must not raise out of run_scan.
    assert len(result.findings) == 1
    assert result.findings[0].module == "good"
    assert result.scan.state.value == "done"


async def test_orchestrator_marks_scan_failed_on_unhandled_exception(monkeypatch):
    async def _broken_discovery(http, url, max_pages=40):
        raise RuntimeError("network stack exploded")

    monkeypatch.setattr(orchestrator_module, "run_discovery", _broken_discovery)
    registry = ModuleRegistry()

    try:
        await orchestrator_module.run_scan("https://example.com", registry=registry)
        raise AssertionError("expected RuntimeError to propagate")
    except RuntimeError:
        pass
