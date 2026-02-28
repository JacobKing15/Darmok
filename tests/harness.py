# Core evaluation engine — precision/recall per category and tier,
# ground truth types, and benchmark result containers used by all
# test and benchmark tooling.

from __future__ import annotations

from dataclasses import dataclass, field

# ── Category labels (snake_case per detector_spec.md) ─────────────────────────

ALL_CATEGORIES: tuple[str, ...] = (
    "private_key",
    "jwt",
    "api_key",
    "url_credential",
    "email",
    "ip_address",
    "credit_card",
)

# ── Tier assignments (detector_spec.md §Tier Reference) ───────────────────────

CATEGORY_TIER: dict[str, int] = {
    "private_key":    1,
    "jwt":            1,
    "api_key":        1,
    "url_credential": 1,
    "email":          2,
    "ip_address":     2,
    "credit_card":    2,
}

# Tier recall and precision targets (§Tiered Recall Targets)
TIER_RECALL_TARGET: dict[int, float]    = {1: 0.99, 2: 0.95, 3: 0.90}
TIER_PRECISION_TARGET: dict[int, float] = {1: 0.90, 2: 0.95, 3: 0.95}

AUTO_REDACT_THRESHOLD = 0.85  # confidence >= this → auto-redact (all tiers, inclusive)

# ── Ground truth types ────────────────────────────────────────────────────────


@dataclass
class GroundTruthEntity:
    """A single known-sensitive value embedded in a test prompt."""
    value: str      # exact string the detector should return (matched to d.raw_value)
    category: str   # snake_case: one of ALL_CATEGORIES


@dataclass
class TestCase:
    """A synthetic prompt with embedded entities and full ground truth labels."""
    name: str
    prompt_type: str  # devops_log | code_snippet | support_email | config | mixed
    text: str
    entities: list[GroundTruthEntity] = field(default_factory=list)


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class CategoryResult:
    category: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    test_count: int


@dataclass
class TierResult:
    tier: int
    recall: float
    precision: float
    recall_target: float
    precision_target: float
    passed: bool


@dataclass
class BenchmarkResult:
    categories: dict[str, CategoryResult]
    tiers: dict[int, TierResult] = field(default_factory=dict)
    total_test_cases: int = 0
    confidence_threshold: float = AUTO_REDACT_THRESHOLD


# ── Evaluation engine ─────────────────────────────────────────────────────────


def _precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    # When there are no detections, precision is vacuously 1.0 (no false alarms).
    # When there is no ground truth, recall is vacuously 1.0 (nothing to miss).
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return precision, recall, f1


def evaluate(
    test_cases: list[TestCase],
    detectors: list,  # list[BaseDetector] — kept as list to avoid import cycle
    confidence_threshold: float = AUTO_REDACT_THRESHOLD,
) -> BenchmarkResult:
    """
    Run all detectors against every test case and compute per-category metrics.

    Matching rule: a detection is a true positive when its raw_value and category
    exactly match a ground truth entity in the same test case.  Set-based
    comparison per case — duplicate values within a single case count once.

    Any detection above threshold whose category does not appear in the ground
    truth for that case is counted as a false positive for that category.
    """
    tp_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    fp_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    fn_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}

    for case in test_cases:
        # Collect all detections above the confidence threshold
        above_threshold: list = []
        for detector in detectors:
            above_threshold.extend(
                d for d in detector.detect(case.text)
                if d.confidence >= confidence_threshold
            )

        for category in ALL_CATEGORIES:
            detected_values = {d.raw_value for d in above_threshold if d.category == category}
            truth_values    = {e.value    for e in case.entities   if e.category == category}

            tp = len(detected_values & truth_values)
            fp = len(detected_values - truth_values)
            fn = len(truth_values    - detected_values)

            tp_map[category] += tp
            fp_map[category] += fp
            fn_map[category] += fn

    # Per-category results
    cat_results: dict[str, CategoryResult] = {}
    for category in ALL_CATEGORIES:
        tp, fp, fn = tp_map[category], fp_map[category], fn_map[category]
        precision, recall, f1 = _precision_recall_f1(tp, fp, fn)
        cat_results[category] = CategoryResult(
            category=category,
            tp=tp, fp=fp, fn=fn,
            precision=precision,
            recall=recall,
            f1=f1,
            test_count=len(test_cases),
        )

    # Tier rollup — aggregate TP/FP/FN across all categories in each tier
    tier_tp: dict[int, int] = {1: 0, 2: 0, 3: 0}
    tier_fp: dict[int, int] = {1: 0, 2: 0, 3: 0}
    tier_fn: dict[int, int] = {1: 0, 2: 0, 3: 0}
    for category, r in cat_results.items():
        t = CATEGORY_TIER.get(category, 3)
        tier_tp[t] += r.tp
        tier_fp[t] += r.fp
        tier_fn[t] += r.fn

    tier_results: dict[int, TierResult] = {}
    for t in (1, 2, 3):
        tp, fp, fn = tier_tp[t], tier_fp[t], tier_fn[t]
        precision, recall, _ = _precision_recall_f1(tp, fp, fn)
        r_target = TIER_RECALL_TARGET[t]
        p_target = TIER_PRECISION_TARGET[t]
        tier_results[t] = TierResult(
            tier=t,
            recall=recall,
            precision=precision,
            recall_target=r_target,
            precision_target=p_target,
            passed=(recall >= r_target and precision >= p_target),
        )

    return BenchmarkResult(
        categories=cat_results,
        tiers=tier_results,
        total_test_cases=len(test_cases),
        confidence_threshold=confidence_threshold,
    )
