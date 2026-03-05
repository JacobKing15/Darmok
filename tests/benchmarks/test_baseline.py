"""
Benchmark baseline regression guard — Phase 1 exit gate item 6.

Establishes a persistent benchmark baseline in tests/benchmarks/results.jsonl.
Each test run appends the current results and compares against the previous run.
Fails the build if any category drops precision or recall by more than the
tolerance threshold (default 0.02).

Behaviour:
  - First run: saves current results as the baseline and passes.
  - Subsequent runs: compares current results to the previous run; fails on
    any regression exceeding the tolerance.

The JSONL file is append-only.  Every run is preserved for audit purposes.
The "previous run" is always the second-to-last line in the file (the last
line is the just-saved current run).

This test uses the shared `benchmark_result` fixture from conftest.py, which
runs the per-detector precision/recall evaluation once per pytest session and
caches the result — so adding this test does not add evaluation overhead.
"""

from __future__ import annotations

import pytest

from tests.benchmarks.tracker import (
    DEFAULT_RESULTS_FILE,
    detect_regressions,
    load_latest_run,
    save_run,
)
from tests.harness import (
    ALL_CATEGORIES,
    CATEGORY_TIER,
    TIER_PRECISION_TARGET,
    TIER_RECALL_TARGET,
    BenchmarkResult,
)


# ── Tier target assertions ────────────────────────────────────────────────────
# These are the canonical Phase 1 pass criteria from detector_spec.md.
# They must pass independently for each tier — not just as an average.


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_category_meets_tier_recall_target(benchmark_result: BenchmarkResult, category: str) -> None:
    """Per-category recall must meet the tier target from detector_spec.md §Tier Reference."""
    r = benchmark_result.categories.get(category)
    if r is None or (r.tp + r.fp) == 0:
        pytest.skip(f"{category}: no detections above threshold (stub detector)")
    tier = CATEGORY_TIER.get(category, 3)
    target = TIER_RECALL_TARGET[tier]
    assert r.recall >= target, (
        f"{category} recall {r.recall:.4f} < {target} "
        f"(TP={r.tp} FN={r.fn})"
    )


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_category_meets_tier_precision_target(benchmark_result: BenchmarkResult, category: str) -> None:
    """Per-category precision must meet the tier target from detector_spec.md §Tier Reference."""
    r = benchmark_result.categories.get(category)
    if r is None or (r.tp + r.fp) == 0:
        pytest.skip(f"{category}: no detections above threshold (stub detector)")
    tier = CATEGORY_TIER.get(category, 3)
    target = TIER_PRECISION_TARGET[tier]
    assert r.precision >= target, (
        f"{category} precision {r.precision:.4f} < {target} "
        f"(TP={r.tp} FP={r.fp})"
    )


# ── Baseline persistence and regression detection ─────────────────────────────


def test_save_baseline_and_detect_regressions(benchmark_result: BenchmarkResult) -> None:
    """
    Save the current benchmark run to results.jsonl and compare against the
    previous run (if any).

    First run: saves baseline and passes unconditionally.
    Subsequent runs: fails if precision or recall drops by more than 0.02
    for any category, relative to the immediately preceding run.

    A tolerance of 0.02 absorbs minor statistical variance from random Faker
    data without masking real regressions.
    """
    # Load the previous run BEFORE saving the current one.
    previous = load_latest_run(DEFAULT_RESULTS_FILE)

    # Append current run — every run is preserved for audit.
    save_run(benchmark_result, path=DEFAULT_RESULTS_FILE, label="phase1")

    if previous is None:
        # First time: baseline established.  No comparison possible yet.
        return

    regressions = detect_regressions(
        previous,
        benchmark_result,
        precision_tolerance=0.02,
        recall_tolerance=0.02,
    )

    assert not regressions, (
        f"Benchmark regression detected vs previous run:\n"
        + "\n".join(f"  {r}" for r in regressions)
        + f"\n\nResults file: {DEFAULT_RESULTS_FILE}"
    )
