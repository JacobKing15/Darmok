"""
Email address detector — regex pattern match with domain validity checks
and surrounding context heuristics.
"""

from __future__ import annotations

import re
from collections import deque

from darmok.detectors.base import BaseDetector, DetectionResult

# RFC-5321-approximate pattern (detector_spec.md §Detector 5)
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# Known placeholder/example domains — suppress to 0.25 (below auto-redact threshold)
_PLACEHOLDER_DOMAINS = frozenset({
    "example.com", "example.org", "test.com", "foo.com", "bar.com",
    "email.com", "domain.com", "yourdomain.com", "yourcompany.com",
})

# Loopback / literal localhost — suppress to 0.30
_LOOPBACK_DOMAINS = frozenset({"localhost", "127.0.0.1"})

# Context suppression keywords: presence → 0.25
_EMAIL_SUPPRESS_KEYWORDS = frozenset({
    "example", "sample", "placeholder", "your_email", "test",
})

# Context boost keywords: presence → 0.92 (real communication context).
# Includes the spec-listed set (from:, to:, cc:, contact, email, sent by,
# assigned to) plus common DevOps notification terms (notify, alert, admin)
# that appear in operational templates and unambiguously indicate real
# communication rather than documentation.
_EMAIL_BOOST_KEYWORDS = frozenset({
    "from", "to", "cc", "contact", "email", "reply",
    "sent", "assigned", "notify", "alert", "admin", "address", "user",
})

# Token extractor — shared with context helpers
_TOKEN_RE = re.compile(r"\w+")

_CTX_WINDOW = 10  # tokens either side (detector_spec.md §Token Definition)


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


def _email_confidence(domain: str, text: str, start: int, end: int) -> float:
    """
    Confidence rules from detector_spec.md §Detector 5.

    Priority order (highest to lowest precedence):
      1. Loopback domain (localhost / 127.0.0.1)   → 0.30
      2. Placeholder domain                         → 0.25
      3. Suppression context keyword                → 0.25
      4. Communication boost keyword in context     → 0.92
      5. Default (valid TLD, no signal)             → 0.80
    """
    domain_lower = domain.lower()

    # Loopback
    if domain_lower in _LOOPBACK_DOMAINS:
        return 0.30

    # Placeholder domain — exact match or subdomain suffix
    for ph in _PLACEHOLDER_DOMAINS:
        if domain_lower == ph or domain_lower.endswith("." + ph):
            return 0.25

    ctx_tokens = _context_tokens(text, start, end)
    ctx_text = " ".join(t.lower() for t in ctx_tokens)

    # Context-based suppression (overrides boost per Confidence Composition Rules)
    for kw in _EMAIL_SUPPRESS_KEYWORDS:
        if kw in ctx_text:
            return 0.25

    # Communication context boost
    for kw in _EMAIL_BOOST_KEYWORDS:
        if kw in ctx_text:
            return 0.92

    return 0.80


class EmailDetector(BaseDetector):
    """
    Detects email addresses using RFC-5321-approximate pattern matching.

    Pattern: [a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}

    Confidence rules (from detector_spec.md §Detector 5):
      Real TLD + communication context (from, to, contact, email, ...)  → 0.92
      Real TLD, no strong context signal                                 → 0.80
      Known placeholder domain (example.com, test.com, ...)             → 0.25
      Context contains example/sample/placeholder/test                  → 0.25
      user@localhost or user@127.0.0.1                                  → 0.30
    """

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for m in _EMAIL_RE.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            assert text[start:end] == raw, "span invariant violated"
            # Skip `password@host` patterns inside URL credentials.
            # In a URL like `scheme://user:password@host`, the char immediately
            # before the local part is ':' — not a valid email context.
            if start > 0 and text[start - 1] == ":":
                continue
            # Extract domain (everything after the @)
            domain = raw.split("@", 1)[1]
            confidence = _email_confidence(domain, text, start, end)
            results.append(DetectionResult(
                span=(start, end),
                raw_value=raw,
                category="email",
                tier=2,
                confidence=confidence,
                detector=self.__class__.__name__,
                placeholder=None,
            ))
        return results
