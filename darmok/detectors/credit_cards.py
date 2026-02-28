"""
Credit card number detector — pattern matching with Luhn validation.

All matches must pass the Luhn algorithm before being flagged.

Stub — implementation pending (build order step 7).
"""

from __future__ import annotations

from darmok.detectors.base import BaseDetector, DetectionResult


class CreditCardDetector(BaseDetector):
    """
    Detects Visa, Mastercard, Amex, and Discover credit card numbers.

    All matches are validated with the Luhn algorithm before being flagged.
    Supports space-separated, dash-separated, and unformatted numbers.

    Confidence rules (from detector_spec.md §Detector 7):
      Luhn-valid + known prefix + payment context → 0.95
      Luhn-valid + known prefix, neutral context  → 0.85
      Luhn-valid + unknown prefix                 → 0.70
      Luhn-valid + example/test markers           → 0.25

    Context boosts: card, payment, billing, charge, visa, mastercard,
                    amex, cvv, expiry, expire

    Stub — implementation pending.
    """

    def detect(self, text: str) -> list[DetectionResult]:
        return []
