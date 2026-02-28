"""
Credit card number detector — pattern matching with Luhn validation.

All matches must pass the Luhn algorithm before being flagged.
"""

from __future__ import annotations

import re
from collections import deque

from darmok.detectors.base import BaseDetector, DetectionResult

# ── Card number patterns ───────────────────────────────────────────────────────
# Source: detector_spec.md §Detector 7
# Each alternative matches a known card type with optional space/dash separators.
# \b boundaries prevent matching numbers embedded inside longer digit strings.

_CC_RE = re.compile(r"""(?x)
    \b
    (?:
        # Visa — 4xxx, 16 digits (4-4-4-4)
        4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}
        |
        # Mastercard — 51xx–55xx, 16 digits (4-4-4-4)
        5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}
        |
        # Amex — 34xx / 37xx, 15 digits (4-6-5)
        3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}
        |
        # Discover — 6011 / 65xx, 16 digits (4-4-4-4)
        6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}
    )
    \b
""")

# ── Luhn validation ────────────────────────────────────────────────────────────


def _luhn_valid(raw: str) -> bool:
    """
    Return True iff the digit sequence in `raw` passes the Luhn check.
    Non-digit characters (spaces, dashes) are ignored.
    """
    digits = [int(c) for c in raw if c.isdigit()]
    if not digits:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Context helpers ────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"\w+")
_CTX_WINDOW = 10  # tokens either side (config §context_windows.credit_card)


def _context_tokens(text: str, start: int, end: int) -> list[str]:
    """Return up to _CTX_WINDOW tokens immediately before and after [start, end]."""
    buf: deque[str] = deque(maxlen=_CTX_WINDOW)
    after: list[str] = []
    for m in _TOKEN_RE.finditer(text):
        s, e, t = m.start(), m.end(), m.group()
        if e <= start:
            buf.append(t)
        elif s >= end and len(after) < _CTX_WINDOW:
            after.append(t)
    return list(buf) + after


# Payment context keywords → boost to 0.95 (spec §Detector 7 §Context Boost)
_CC_BOOST_KEYWORDS = frozenset({
    "card", "payment", "billing", "charge", "visa", "mastercard",
    "amex", "cvv", "expiry", "expire", "declined", "refund", "transaction",
})

# Suppression: example / test context → 0.25 (spec §Detector 7 §Confidence Rules)
_CC_SUPPRESS_KEYWORDS = frozenset({
    "example", "sample", "placeholder", "dummy", "fake", "test",
})


def _cc_confidence(text: str, start: int, end: int) -> float:
    """
    Confidence rules from detector_spec.md §Detector 7.

    All callers already hold a Luhn-valid + known-prefix match, so the
    only differentiator is surrounding context.

    Suppression overrides boost (Confidence Composition Rules).

      Example/test markers in context  → 0.25
      Payment context keywords         → 0.95
      Neutral context                  → 0.85
    """
    ctx = _context_tokens(text, start, end)
    ctx_text = " ".join(t.lower() for t in ctx)

    # Suppression first (overrides boost per Confidence Composition Rules)
    for kw in _CC_SUPPRESS_KEYWORDS:
        if kw in ctx_text:
            return 0.25

    # Payment context boost
    for kw in _CC_BOOST_KEYWORDS:
        if kw in ctx_text:
            return 0.95

    return 0.85  # known-prefix, neutral context


class CreditCardDetector(BaseDetector):
    """
    Detects Visa, Mastercard, Amex, and Discover credit card numbers.

    All regex matches are validated with the Luhn algorithm before being returned.
    Supports space-separated, dash-separated, and unformatted numbers.

    Confidence rules (detector_spec.md §Detector 7):
      Luhn-valid + known prefix + payment context  → 0.95
      Luhn-valid + known prefix, neutral context   → 0.85
      Luhn-valid, example/test markers in context  → 0.25

    Context boost keywords: card, payment, billing, charge, visa, mastercard,
                            amex, cvv, expiry, expire, declined, refund, transaction
    Context suppress keywords: example, sample, placeholder, dummy, fake, test
    """

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for m in _CC_RE.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            assert text[start:end] == raw, "span invariant violated"
            if not _luhn_valid(raw):
                continue
            confidence = _cc_confidence(text, start, end)
            results.append(DetectionResult(
                span=(start, end),
                raw_value=raw,
                category="credit_card",
                tier=2,
                confidence=confidence,
                detector=self.__class__.__name__,
                placeholder=None,
            ))
        return results
