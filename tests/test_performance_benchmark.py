"""Not a micro-benchmark suite — one regression guard using the real harness
in scripts/benchmark_discovery.py, with a generous ceiling. This exists to
catch a severe accidental regression (e.g. the wave-concurrent crawl reverting
to sequential fetching, or an O(n^2) path creeping into wave filtering), not
to track tight timing — CI machines vary too much for a tight bound to be
anything but flaky.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from benchmark_discovery import run_benchmark  # noqa: E402

_PAGE_COUNT = 200
# Generous: a regression to sequential fetching alone would roughly double
# this on typical hardware, well before hitting a mocked target's near-zero
# latency ceiling — this is about catching a structural regression, not
# enforcing a tight performance target.
_CEILING_SECONDS = 5.0


async def test_discovery_benchmark_stays_within_generous_ceiling(capsys):
    start = time.perf_counter()
    await run_benchmark(_PAGE_COUNT)
    elapsed = time.perf_counter() - start

    output = capsys.readouterr().out
    assert f"pages crawled:         {_PAGE_COUNT}" in output
    assert elapsed < _CEILING_SECONDS, f"discovery of {_PAGE_COUNT} mocked pages took {elapsed:.2f}s — possible performance regression"
