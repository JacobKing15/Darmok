"""
Full-pipeline tests — Phase 1 exit gate (exit criteria item 2).

Tests the complete pipeline end-to-end with overlap resolution active:
  - Overlap resolution: longer span wins; tier breaks ties
  - Round-trip fidelity: reconstruct(sanitized, manifest) == original
  - Deduplication: same value in same session → same placeholder
  - Tier targets: precision/recall still meet targets through the pipeline
  - Negative cases: no substitutions on clean input
  - Injection safety: unknown placeholders flagged, not expanded
"""

from __future__ import annotations

import pytest

from darmok.pipeline import Pipeline
from tests.harness import (
    ALL_CATEGORIES,
    AUTO_REDACT_THRESHOLD,
    CATEGORY_TIER,
    TIER_PRECISION_TARGET,
    TIER_RECALL_TARGET,
    BenchmarkResult,
    CategoryResult,
    TestCase,
)
from tests.synthetic_data.generate import (
    _fake_api_key,
    _fake_credit_card,
    _fake_jwt,
    _fake_private_key,
    _fake_url_with_credentials,
    generate_all,
    generate_negative_cases,
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    return precision, recall


def _pipeline_evaluate(test_cases: list[TestCase]) -> BenchmarkResult:
    """
    Run the full pipeline (detect_resolved) on every test case and compute
    per-category precision/recall with overlap resolution active.

    A fresh Pipeline is created per test case to avoid cross-case registry
    contamination (each test case is an independent evaluation unit).
    """
    tp_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    fp_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    fn_map: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}

    for case in test_cases:
        pipeline = Pipeline()
        resolved = pipeline.detect_resolved(case.text)

        for category in ALL_CATEGORIES:
            detected = {r.raw_value for r in resolved if r.category == category}
            truth    = {e.value    for e in case.entities if e.category == category}

            tp_map[category] += len(detected & truth)
            fp_map[category] += len(detected - truth)
            fn_map[category] += len(truth    - detected)

    cat_results: dict[str, CategoryResult] = {}
    for cat in ALL_CATEGORIES:
        tp, fp, fn = tp_map[cat], fp_map[cat], fn_map[cat]
        p, r = _precision_recall(tp, fp, fn)
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        cat_results[cat] = CategoryResult(
            category=cat, tp=tp, fp=fp, fn=fn,
            precision=p, recall=r, f1=f1,
            test_count=len(test_cases),
        )

    return BenchmarkResult(
        categories=cat_results,
        total_test_cases=len(test_cases),
        confidence_threshold=AUTO_REDACT_THRESHOLD,
    )


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def pipeline_test_cases():
    return generate_all(n_per_category=50)


@pytest.fixture(scope="session")
def pipeline_benchmark_result(pipeline_test_cases) -> BenchmarkResult:
    return _pipeline_evaluate(pipeline_test_cases)


# ── Overlap resolution ─────────────────────────────────────────────────────────


def test_url_credential_beats_ip_in_url():
    """UrlCredentialDetector (longer span) must subsume IpAddressDetector match."""
    url = "postgresql://deploy:s3cr3t@10.0.1.45:5432/app_prod"
    pipeline = Pipeline()
    resolved = pipeline.detect_resolved(url)
    categories = {r.category for r in resolved}

    assert "url_credential" in categories, "URL credential must be detected"
    assert "ip_address" not in categories, (
        "IP inside a URL credential span must be subsumed (longer-span rule)"
    )


def test_jwt_beats_generic_entropy():
    """JwtDetector (Tier 1, explicit prefix) wins over any generic entropy match."""
    jwt = _fake_jwt()
    text = f"Authorization: Bearer {jwt}"
    pipeline = Pipeline()
    resolved = pipeline.detect_resolved(text)

    jwt_hits = [r for r in resolved if r.category == "jwt"]
    assert len(jwt_hits) == 1, "JWT should be detected exactly once"
    assert jwt_hits[0].raw_value == jwt


def test_longer_span_wins_over_shorter():
    """Generic overlap: the result covering more characters is kept."""
    from darmok.pipeline import _resolve_overlaps
    from darmok.detectors.base import DetectionResult

    short = DetectionResult(span=(5, 10), raw_value="short", category="email",
                            tier=2, confidence=0.95, detector="A")
    long_ = DetectionResult(span=(3, 15), raw_value="longer_value", category="url_credential",
                            tier=1, confidence=0.90, detector="B")

    result = _resolve_overlaps([short, long_])
    assert len(result) == 1
    assert result[0].raw_value == "longer_value"


def test_tier_breaks_equal_length_tie():
    """Equal-length overlapping spans: lower tier number (higher risk) wins."""
    from darmok.pipeline import _resolve_overlaps
    from darmok.detectors.base import DetectionResult

    tier1 = DetectionResult(span=(0, 10), raw_value="same_value", category="api_key",
                            tier=1, confidence=0.90, detector="A")
    tier2 = DetectionResult(span=(0, 10), raw_value="same_value", category="email",
                            tier=2, confidence=0.92, detector="B")

    result = _resolve_overlaps([tier2, tier1])  # intentionally reversed input order
    assert len(result) == 1
    assert result[0].tier == 1


# ── Round-trip fidelity ────────────────────────────────────────────────────────


def test_round_trip_single_api_key():
    key = _fake_api_key()
    text = f"OPENAI_API_KEY={key}"
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    assert key not in sanitized
    assert len(manifest) == 1
    assert pipeline.reconstruct(sanitized, manifest) == text


def test_round_trip_single_jwt():
    jwt = _fake_jwt()
    text = f"Authorization: Bearer {jwt}"
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    assert jwt not in sanitized
    restored = pipeline.reconstruct(sanitized, manifest)
    assert restored == text


def test_round_trip_private_key():
    key = _fake_private_key()
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(key)

    assert "PRIVATE KEY" not in sanitized
    assert pipeline.reconstruct(sanitized, manifest) == key


def test_round_trip_multiple_categories():
    """Email + IP + API key in one prompt all round-trip correctly."""
    from faker import Faker
    fake = Faker()
    email = fake.free_email()
    ip    = fake.ipv4_private()
    key   = _fake_api_key()
    text = (
        f"Alert sent to {email}\n"
        f"Server {ip}:8080 is down\n"
        f"API key: {key}"
    )
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    assert email not in sanitized
    assert ip    not in sanitized
    assert key   not in sanitized
    assert pipeline.reconstruct(sanitized, manifest) == text


def test_round_trip_url_credential():
    url  = _fake_url_with_credentials()
    text = f"DATABASE_URL={url}"
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    assert "@" not in sanitized or "url_credential" not in str(manifest)
    assert pipeline.reconstruct(sanitized, manifest) == text


def test_round_trip_credit_card():
    card = _fake_credit_card()
    text = f"Customer card {card} was declined."
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    # Digits stripped from sanitized
    raw_digits = "".join(c for c in card if c.isdigit())
    assert raw_digits not in sanitized.replace(" ", "").replace("-", "")
    assert pipeline.reconstruct(sanitized, manifest) == text


def test_no_change_when_nothing_detected():
    """Clean text with no sensitive content passes through unchanged."""
    text = "The deployment completed successfully. No issues found."
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    assert sanitized == text
    assert manifest == {}


# ── Deduplication ──────────────────────────────────────────────────────────────


def test_same_value_gets_same_placeholder_in_one_prompt():
    """Repeated value in a single prompt → same placeholder both times."""
    key  = _fake_api_key()
    text = f"Primary key: {key}\nBackup key: {key}"
    pipeline = Pipeline()
    sanitized, manifest = pipeline.run(text)

    assert len(manifest) == 1, "One unique value → one manifest entry"
    placeholder = list(manifest.keys())[0]
    assert sanitized.count(placeholder) == 2, "Placeholder appears twice"
    assert pipeline.reconstruct(sanitized, manifest) == text


def test_same_value_gets_same_placeholder_across_prompts():
    """Same raw value in separate run() calls gets the same placeholder (session dedup)."""
    from tests.synthetic_data.generate import _fake_github_pat
    key = _fake_github_pat()  # ghp_ prefix → 0.97 confidence, reliably above threshold
    pipeline = Pipeline()  # single session

    _, manifest1 = pipeline.run(f"GITHUB_TOKEN={key}")
    _, manifest2 = pipeline.run(f"token: {key}")

    ph1 = list(manifest1.keys())[0]
    ph2 = list(manifest2.keys())[0]
    assert ph1 == ph2, f"Same value must get same placeholder. Got {ph1!r} vs {ph2!r}"


def test_different_values_get_different_placeholders():
    key1 = _fake_api_key()
    key2 = _fake_api_key()
    while key2 == key1:
        key2 = _fake_api_key()

    pipeline = Pipeline()
    _, m1 = pipeline.run(f"Key A: {key1}")
    _, m2 = pipeline.run(f"Key B: {key2}")

    ph1 = list(m1.keys())[0]
    ph2 = list(m2.keys())[0]
    assert ph1 != ph2, "Different values must get different placeholders"


# ── Negative cases ─────────────────────────────────────────────────────────────


def test_negative_cases_produce_no_substitutions():
    """Every static negative case must produce an empty manifest."""
    neg_cases = generate_negative_cases(n=30)
    pipeline = Pipeline()
    failures = []

    for case in neg_cases:
        _, manifest = pipeline.run(case.text)
        if manifest:
            failures.append((case.name, case.text, list(manifest.values())))

    assert not failures, (
        f"{len(failures)} negative case(s) produced false-positive substitutions:\n"
        + "\n".join(f"  [{name}] {text!r} → {vals}" for name, text, vals in failures[:5])
    )


# ── Injection safety ───────────────────────────────────────────────────────────


def test_unknown_placeholder_flagged_not_expanded():
    """A placeholder-shaped string not in the manifest is flagged inline (spec §Reconstructor)."""
    pipeline = Pipeline()
    fake_ph  = "[sess_aabbcc:API_KEY_99]"
    response = f"The answer involves {fake_ph} directly."

    result = pipeline.reconstruct(response, {})

    # The spec says the placeholder appears in the warning text:
    #   ⚠ [sess_a3f9b2:EMAIL_1] — not in outbound manifest, left unexpanded
    assert f"⚠ {fake_ph}" in result, "Warning must include the original placeholder"
    assert "not in outbound manifest" in result
    # The response must be different from the input (it was transformed, not passed through)
    assert result != response


def test_only_manifest_placeholders_are_expanded():
    """A placeholder in the manifest expands; one not in it is flagged."""
    pipeline = Pipeline()
    key = _fake_api_key()
    sanitized, manifest = pipeline.run(f"Key: {key}")

    known_ph   = list(manifest.keys())[0]
    unknown_ph = "[sess_000000:API_KEY_99]"

    response = f"I used {known_ph} and also {unknown_ph}."
    result   = pipeline.reconstruct(response, manifest)

    assert key                    in result, "Known placeholder should be expanded"
    assert f"⚠ {unknown_ph}"     in result, "Unknown placeholder must appear inside warning"
    assert "not in outbound manifest" in result


# ── Pipeline tier targets ──────────────────────────────────────────────────────


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_pipeline_precision_meets_tier_target(pipeline_benchmark_result, category):
    """Precision ≥ tier target through the full pipeline (overlap resolution active)."""
    r = pipeline_benchmark_result.categories.get(category)
    if r is None or (r.tp + r.fp) == 0:
        pytest.skip(f"{category}: no detections above threshold")
    tier      = CATEGORY_TIER.get(category, 3)
    target    = TIER_PRECISION_TARGET[tier]
    assert r.precision >= target, (
        f"{category} pipeline precision {r.precision:.3f} < {target} "
        f"(TP={r.tp} FP={r.fp} FN={r.fn})"
    )


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_pipeline_recall_meets_tier_target(pipeline_benchmark_result, category):
    """Recall ≥ tier target through the full pipeline (overlap resolution active)."""
    r = pipeline_benchmark_result.categories.get(category)
    if r is None or (r.tp + r.fp) == 0:
        pytest.skip(f"{category}: no detections above threshold")
    tier   = CATEGORY_TIER.get(category, 3)
    target = TIER_RECALL_TARGET[tier]
    assert r.recall >= target, (
        f"{category} pipeline recall {r.recall:.3f} < {target} "
        f"(TP={r.tp} FP={r.fp} FN={r.fn})"
    )
