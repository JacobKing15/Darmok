#!/usr/bin/env python
# Standalone benchmark runner — generates synthetic test data, runs all
# implemented detectors, and prints the tiered dashboard from detector_spec.md.
# Also runs the full-pipeline benchmark (overlap resolution active) as the
# Phase 1 exit gate check.
#
# Usage (from project root):
#   python benchmark/run.py
#
# This script is intentionally independent of pytest so the dashboard can be
# run at any time without the test suite overhead.

from __future__ import annotations

import io
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

# Force UTF-8 output on Windows (box-drawing characters require it)
if isinstance(sys.stdout, io.TextIOWrapper):
    sys.stdout.reconfigure(encoding="utf-8")

from darmok.detectors.api_keys import ApiKeyDetector, JwtDetector, PrivateKeyDetector
from darmok.detectors.credit_cards import CreditCardDetector
from darmok.detectors.email import EmailDetector
from darmok.detectors.ip_address import IpAddressDetector
from darmok.detectors.urls import UrlCredentialDetector
from darmok.pipeline import Pipeline
from tests.benchmarks.dashboard import print_dashboard
from tests.harness import (
    ALL_CATEGORIES,
    AUTO_REDACT_THRESHOLD,
    CATEGORY_TIER,
    TIER_PRECISION_TARGET,
    TIER_RECALL_TARGET,
    BenchmarkResult,
    CategoryResult,
    evaluate,
)
from tests.synthetic_data.generate import generate_all


def _pipeline_evaluate(test_cases):
    """
    Full-pipeline evaluation with overlap resolution active.
    Returns (BenchmarkResult, overlap_conflicts_count).
    """
    tp_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    fp_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    fn_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    overlap_conflicts = 0

    for case in test_cases:
        pipeline = Pipeline()

        # Count pre-resolution candidates to measure overlap conflicts
        candidates = []
        for det in pipeline._detectors:
            for r in det.detect(case.text):
                if r.confidence >= AUTO_REDACT_THRESHOLD:
                    candidates.append(r)
        resolved = pipeline.detect_resolved(case.text)
        overlap_conflicts += max(0, len(candidates) - len(resolved))

        for category in ALL_CATEGORIES:
            detected = {r.raw_value for r in resolved if r.category == category}
            truth    = {e.value    for e in case.entities if e.category == category}
            tp_map[category] += len(detected & truth)
            fp_map[category] += len(detected - truth)
            fn_map[category] += len(truth    - detected)

    cat_results: dict[str, CategoryResult] = {}
    for cat in ALL_CATEGORIES:
        tp, fp, fn = tp_map[cat], fp_map[cat], fn_map[cat]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        cat_results[cat] = CategoryResult(
            category=cat, tp=tp, fp=fp, fn=fn,
            precision=precision, recall=recall, f1=f1,
            test_count=len(test_cases),
        )

    result = BenchmarkResult(
        categories=cat_results,
        total_test_cases=len(test_cases),
        confidence_threshold=AUTO_REDACT_THRESHOLD,
    )
    return result, overlap_conflicts


def _print_pipeline_dashboard(result: BenchmarkResult, overlap_conflicts: int) -> None:
    W = 70
    col_sep = "┼" + "─" * 14 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 20 + "┤"

    print("┌" + "─" * (W - 2) + "┐")
    print("│" + " FULL PIPELINE — overlap resolution active ".center(W - 2) + "│")
    print("├" + "─" * (W - 2) + "┤")
    print(f"│  Overlap conflicts resolved: {overlap_conflicts:<39}│")
    print("├" + "─" * 14 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 20 + "┤")
    print("│" + " Detector     " + "│" + "  Recall  " + "│" + "  Target  " + "│" + "  Precis. " + "│" + " Status             " + "│")
    print("├" + col_sep[1:])

    all_pass = True
    for cat in ALL_CATEGORIES:
        r = result.categories[cat]
        tier     = CATEGORY_TIER.get(cat, 3)
        r_target = TIER_RECALL_TARGET[tier]
        p_target = TIER_PRECISION_TARGET[tier]
        passed   = r.recall >= r_target and r.precision >= p_target
        if not passed:
            all_pass = False
        status = "✓ PASS" if passed else "✗ FAIL"
        label  = cat.replace("_", "").title()[:12]
        print(
            f"│ {label:<12}  │"
            f"  {r.recall:.3f}   │"
            f"  ≥ {r_target:.2f}  │"
            f"  {r.precision:.3f}  │"
            f" {status:<18} │"
        )

    print("└" + "─" * 14 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 20 + "┘")
    gate = "✓ ALL PASS — Phase 1 exit gate met" if all_pass else "✗ FAIL — exit gate NOT met"
    print(f"Phase 1 exit gate (item 2/7): {gate}")


def main() -> None:
    n_per_category = 50
    print(f"Generating {n_per_category} test cases per category + 100 negative cases...")
    test_cases = generate_all(n_per_category=n_per_category)
    print(f"Total test cases: {len(test_cases)}\n")

    # ── Per-detector benchmark ────────────────────────────────────────────────
    detectors = [
        PrivateKeyDetector(),
        JwtDetector(),
        ApiKeyDetector(),
        UrlCredentialDetector(),
        EmailDetector(),
        IpAddressDetector(),
        CreditCardDetector(),
    ]
    result = evaluate(test_cases, detectors, confidence_threshold=AUTO_REDACT_THRESHOLD)
    print_dashboard(result)

    # ── Full-pipeline benchmark ───────────────────────────────────────────────
    print()
    pipeline_result, overlap_conflicts = _pipeline_evaluate(test_cases)
    _print_pipeline_dashboard(pipeline_result, overlap_conflicts)


if __name__ == "__main__":
    main()
