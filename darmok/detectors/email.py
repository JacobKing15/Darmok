"""
Email address detector — regex pattern match with domain validity checks
and surrounding context heuristics.

Stub — implementation pending (build order step 5).
"""

from __future__ import annotations

from darmok.detectors.base import BaseDetector, DetectionResult


class EmailDetector(BaseDetector):
    """
    Detects email addresses using RFC-5321-approximate pattern matching.

    Pattern: [a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}

    Confidence rules (from detector_spec.md §Detector 5):
      Valid pattern + real TLD + context suggests communication → 0.92
      Valid pattern + real TLD, no strong context signal        → 0.80
      Known placeholder domain (example.com, test.com, etc.)   → 0.25
      Code comment or documentation string                      → 0.55
      user@localhost or user@127.0.0.1                          → 0.30

    Context boosts: from:, to:, cc:, contact, email, sent by, assigned to
    Context suppression: example.com domains, example/sample/test in context

    Stub — implementation pending.
    """

    def detect(self, text: str) -> list[DetectionResult]:
        return []
