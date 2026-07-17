# Contributing

## Setup

```bash
git clone <this repo>
cd owasp-inspector
pip install -e ".[dev]"
```

This installs the project plus `pytest`, `pytest-asyncio`, `pytest-cov`, and `ruff`.

## Running checks locally

```bash
ruff check .              # lint
ruff format --check .     # formatting (use `ruff format .` to fix in place)
pytest                    # full suite
pytest --cov=owasp_inspector --cov-report=term-missing   # with coverage
```

CI (`.github/workflows/ci.yml`) runs all of this plus CodeQL, Semgrep, `pip-audit`, a gitleaks secret scan, and a Docker build + Trivy scan on every PR — matching these locally before pushing saves a round-trip.

`Logic/`, `UI/`, `Data/Queries/`, and `main.py` are excluded from `ruff` (see the comment in `pyproject.toml`'s `[tool.ruff]` section) — they're the pre-v1 legacy engine, a flat module layout with a structural reason for import-order lint violations that isn't worth a real refactor to satisfy a linter. Don't extend that exclusion to anything under `owasp_inspector/`; that package is held to full lint on purpose.

## Where things live

New OWASP-category checks, HTTP/discovery behavior, reporting, and the CLI all live under `owasp_inspector/` — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full layout and the extension points. Read that before adding a module; the short version:

```python
# owasp_inspector/modules/my_check.py
from owasp_inspector.core.models import Finding
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module

@register_module
class MyCheckModule(Module):
    name = "my-check"
    owasp_category = "A0X:2021-..."

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []
        # read discovery.targets / discovery.cookies / discovery.headers, or
        # make your own requests via context.http (an AsyncHttpClient)
        return [...]
```

Import the new file from `owasp_inspector/modules/__init__.py` so `@register_module` actually runs. That's the entire integration surface — the orchestrator never needs to know your module exists beyond that.

## Testing conventions

- Network calls in tests go through `httpx.MockTransport`, never a real network request. Look at any `tests/test_modules_*.py` or `tests/test_*_context.py` file for the pattern: build an `AsyncHttpClient(transport=httpx.MockTransport(handler))`, where `handler` is a small function computing a response from the request.
- Async tests are plain `async def test_...(): ...` — `pytest-asyncio` is configured in `auto` mode (`pyproject.toml`'s `[tool.pytest.ini_options]`), no `@pytest.mark.asyncio` decorator needed.
- 257 tests across 51 test files as of this writing. Coverage matters less than the next point.

### The one discipline that matters most here: prove the absence of false positives, not just the presence of true positives

This project's core lesson, learned three times over during the SQLi/XSS/CSRF async ports, is that a detection check which doesn't verify a payload *actually caused* a signal — rather than just checking the signal is *present* — will eventually flag something that was already true before the payload was ever sent. Concretely, every one of these was a real bug found in already-working, already-tested code:

- SQLi's error-pattern check didn't compare against a pre-payload baseline response, so a target with an already-broken backend turned every payload against every parameter into an identical false "confirmed" finding.
- XSS's dangerous-construct check treated a marker like `"alert("` as proof a payload survived unescaped — but that substring contains no HTML metacharacters, so it's present as harmless text even when the server fully HTML-escapes the payload.
- CSRF's success classifier only checked a baseline for 2 of 15 bypass tests; a page with static "success"-flavored boilerplate text misread as a working bypass on the other 13.

When you add or modify a detection check, add a test that proves it does **not** fire on the case that looks similar but isn't real — an already-present error message, an escaped/neutralized payload, a static string that happens to match your success pattern. If you're porting or touching heuristic logic from `Logic/`, read it looking specifically for this shape of bug before trusting it; don't assume it's correct just because it's already shipping.

### Live verification for anything touching request/response detection logic

Mocked tests catch logic bugs; they can't catch "this assumption about how a real server responds is wrong." Before considering detection-logic work done, run it against a real, currently-authorized practice target (DVWA, Juice Shop, a PortSwigger lab) and specifically look for both a true positive on something genuinely vulnerable and a clean (zero-finding) result on something genuinely defended. Several real bugs in this project — the SQLi baseline-comparison gap, a `response.elapsed` `RuntimeError` under mocks that real transports never hit, a `robots.txt`-driven crawl going silent on a fully-authorized target — were only found this way.

## Commit and PR conventions

- Keep commits scoped: a false-positive fix, a new module, and a docs update are three commits, not one, even in the same session.
- If you generated or modified anything under `owasp_inspector/modules/` for a legacy-engine port, state in the PR description what was ported faithfully, what was deliberately deferred (and why), and what was verified live versus only mocked — see any of the SQLi/XSS/CSRF port sections in [`TASKS.md`](TASKS.md) for the expected shape of that writeup.
- Don't claim something is "done" or "verified" if it was only reviewed as text. If you can't actually run it (no Docker available, no live target reachable), say so explicitly rather than asserting success.

## Reporting security issues in this tool itself

This is a dual-use offensive security tool; if you find a way it could be misused beyond its stated authorized-testing scope, or a vulnerability in the tool's own code (e.g. something that could compromise the machine running a scan), open an issue describing it — there's no separate private disclosure channel for this project yet.
