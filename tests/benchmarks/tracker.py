# Benchmark result persistence — appends runs to a JSONL file and detects
# precision/recall regressions between runs.

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tests.harness import BenchmarkResult, CategoryResult

BENCHMARK_DIR = Path(__file__).parent
DEFAULT_RESULTS_FILE = BENCHMARK_DIR / "results.jsonl"


def save_run(
    result: BenchmarkResult,
    path: Path = DEFAULT_RESULTS_FILE,
    label: str = "",
) -> None:
    """
    Append a benchmark run to the JSONL results file.
    Each line is a self-contained JSON object — safe to append without locking.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "total_test_cases": result.total_test_cases,
        "confidence_threshold": result.confidence_threshold,
        "categories": {
            cat: {
                "tp": r.tp,
                "fp": r.fp,
                "fn": r.fn,
                "precision": round(r.precision, 4),
                "recall": round(r.recall, 4),
                "f1": round(r.f1, 4),
            }
            for cat, r in result.categories.items()
        },
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def load_runs(path: Path = DEFAULT_RESULTS_FILE) -> list[dict]:
    """Load all benchmark runs from the JSONL results file. Returns [] if file missing."""
    if not path.exists():
        return []
    runs = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                runs.append(json.loads(line))
    return runs


def _result_from_record(record: dict) -> BenchmarkResult:
    categories = {
        cat: CategoryResult(
            category=cat,
            tp=data["tp"],
            fp=data["fp"],
            fn=data["fn"],
            precision=data["precision"],
            recall=data["recall"],
            f1=data["f1"],
            test_count=record["total_test_cases"],
        )
        for cat, data in record["categories"].items()
    }
    # tiers defaults to {} — historical records pre-date tier rollup
    return BenchmarkResult(
        categories=categories,
        total_test_cases=record["total_test_cases"],
        confidence_threshold=record["confidence_threshold"],
    )


def load_latest_run(path: Path = DEFAULT_RESULTS_FILE) -> BenchmarkResult | None:
    """Return the most recent benchmark run as a BenchmarkResult, or None."""
    runs = load_runs(path)
    if not runs:
        return None
    return _result_from_record(runs[-1])


def detect_regressions(
    old: BenchmarkResult,
    new: BenchmarkResult,
    precision_tolerance: float = 0.02,
    recall_tolerance: float = 0.02,
) -> list[str]:
    """
    Compare two benchmark runs. Return a list of human-readable regression descriptions.
    A regression is a drop in precision or recall exceeding the given tolerance.
    Tolerance of 0.02 allows minor statistical variance without false alarms.
    """
    regressions: list[str] = []
    for category in old.categories:
        if category not in new.categories:
            regressions.append(f"{category}: missing from new run")
            continue
        old_r = old.categories[category]
        new_r = new.categories[category]
        if new_r.precision < old_r.precision - precision_tolerance:
            drop = old_r.precision - new_r.precision
            regressions.append(
                f"{category}: precision regression  "
                f"{old_r.precision:.3f} → {new_r.precision:.3f}  (Δ −{drop:.3f})"
            )
        if new_r.recall < old_r.recall - recall_tolerance:
            drop = old_r.recall - new_r.recall
            regressions.append(
                f"{category}: recall regression  "
                f"{old_r.recall:.3f} → {new_r.recall:.3f}  (Δ −{drop:.3f})"
            )
    return regressions
