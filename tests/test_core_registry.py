import pytest

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.module import Module
from owasp_inspector.core.registry import ModuleRegistry


class _DummyModule(Module):
    name = "dummy"
    owasp_category = "A00:Test"

    async def run(self, context):
        return [
            Finding(
                module=self.name,
                owasp_category=self.owasp_category,
                title="dummy finding",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="d",
                url=context.target.url,
            )
        ]


def test_register_and_instantiate():
    registry = ModuleRegistry()
    registry.register(_DummyModule)
    assert registry.get("dummy") is _DummyModule
    instances = registry.instantiate_all()
    assert len(instances) == 1
    assert isinstance(instances[0], _DummyModule)


def test_duplicate_registration_raises():
    registry = ModuleRegistry()
    registry.register(_DummyModule)
    with pytest.raises(ValueError):
        registry.register(_DummyModule)


async def test_module_run_produces_findings():
    from owasp_inspector.core.models import ScanTarget
    from owasp_inspector.core.module import ScanContext

    registry = ModuleRegistry()
    registry.register(_DummyModule)
    module = registry.instantiate_all()[0]
    context = ScanContext(target=ScanTarget(url="https://example.com"), http=None, settings=None)
    findings = await module.run(context)
    assert len(findings) == 1
    assert findings[0].url == "https://example.com"
