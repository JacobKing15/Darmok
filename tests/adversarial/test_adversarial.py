# Adversarial test suite — verifies that out-of-scope obfuscation patterns and
# look-alike values do not trigger auto-redaction above the confidence threshold.
# All tests here should PASS even with stub (empty) detectors, and must continue
# to pass once real detector implementations are added.

import pytest

from tests.adversarial.fixtures import ALL_ADVERSARIAL_CASES, AdversarialCase
from tests.harness import AUTO_REDACT_THRESHOLD


@pytest.mark.parametrize(
    "case",
    ALL_ADVERSARIAL_CASES,
    ids=[c.name for c in ALL_ADVERSARIAL_CASES],
)
def test_no_false_positive_above_threshold(case: AdversarialCase, all_detectors) -> None:
    """
    No detection above AUTO_REDACT_THRESHOLD is permitted for case.category_not_expected.

    Passing with stub detectors (returning []) is expected and correct — this suite
    protects against regressions introduced during implementation.
    """
    above_threshold = []
    for detector in all_detectors:
        above_threshold.extend(
            d
            for d in detector.detect(case.text)
            if d.confidence >= AUTO_REDACT_THRESHOLD
            and d.category == case.category_not_expected
        )

    assert not above_threshold, (
        f"False positive on '{case.name}':\n"
        f"  Category:  {case.category_not_expected}\n"
        f"  Threshold: {AUTO_REDACT_THRESHOLD}\n"
        f"  Input:     {case.text!r}\n"
        f"  Hits:      {[(d.raw_value, round(d.confidence, 3)) for d in above_threshold]}\n"
        f"  Spec note: {case.description}"
    )
