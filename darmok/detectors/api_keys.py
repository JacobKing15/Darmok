"""
API key, JWT, and private key detectors.

All three detectors live here per the spec file layout.

Build order (detector_spec.md §Implementation Order):
  1. PrivateKeyDetector — implemented
  2. JwtDetector        — stub, pending
  3. ApiKeyDetector     — stub, pending
"""

from __future__ import annotations

import re

from darmok.detectors.base import BaseDetector, DetectionResult


# ── PrivateKeyDetector ────────────────────────────────────────────────────────


_PEM_TYPES = r"(?:(?:RSA |EC |OPENSSH |DSA |PGP )?(?:PRIVATE KEY|CERTIFICATE|PUBLIC KEY))"

# Full PEM block: BEGIN marker + body + END marker (non-greedy body match)
_FULL_PEM_RE = re.compile(
    r"-----BEGIN " + _PEM_TYPES + r"-----[\s\S]*?-----END " + _PEM_TYPES + r"-----",
)

# Standalone BEGIN marker (used to find begin-only matches after full blocks are removed)
_BEGIN_ONLY_RE = re.compile(
    r"-----BEGIN " + _PEM_TYPES + r"-----",
)

# Comment-line detection: line starts with #, //, or * (after optional whitespace)
_COMMENT_LINE_RE = re.compile(r"^[ \t]*(#|//|\*)")


class PrivateKeyDetector(BaseDetector):
    """
    Detects PEM-format private keys, certificates, and public keys.

    Patterns (from detector_spec.md §Detector 1):
      -----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----
      -----BEGIN CERTIFICATE-----
      -----BEGIN PUBLIC KEY-----

    Confidence rules:
      Full PEM block (BEGIN + body + END) → 0.99
      BEGIN marker only (no matching END)  → 0.90
      BEGIN marker in a comment/docstring  → 0.85 (still redact)

    No suppression rules — PEM markers are unambiguous.
    """

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        full_block_starts: set[int] = set()

        # Pass 1: full PEM blocks
        for m in _FULL_PEM_RE.finditer(text):
            start, end = m.start(), m.end()
            full_block_starts.add(start)
            raw = m.group(0)
            assert text[start:end] == raw, "span invariant violated"
            results.append(DetectionResult(
                span=(start, end),
                raw_value=raw,
                category="private_key",
                tier=1,
                confidence=self._confidence(text, start, full_block=True),
                detector=self.__class__.__name__,
                placeholder=None,
            ))

        # Pass 2: standalone BEGIN markers not covered by a full block
        for m in _BEGIN_ONLY_RE.finditer(text):
            if m.start() in full_block_starts:
                continue
            start, end = m.start(), m.end()
            raw = m.group(0)
            results.append(DetectionResult(
                span=(start, end),
                raw_value=raw,
                category="private_key",
                tier=1,
                confidence=self._confidence(text, start, full_block=False),
                detector=self.__class__.__name__,
                placeholder=None,
            ))

        return results

    def _confidence(self, text: str, start: int, full_block: bool) -> float:
        """
        Base confidence modified by context.

        Comment/docstring context lowers confidence to 0.85 (still redact —
        spec says 'BEGIN marker in a comment or documentation string → 0.85').
        """
        base = 0.99 if full_block else 0.90
        if _is_comment_line(text, start):
            return 0.85
        return base


# ── JwtDetector ───────────────────────────────────────────────────────────────


class JwtDetector(BaseDetector):
    """
    Detects JSON Web Tokens by their three-segment base64url structure.

    Pattern: eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+

    Stub — implementation pending (build order step 2).
    """

    def detect(self, text: str) -> list[DetectionResult]:
        return []


# ── ApiKeyDetector ────────────────────────────────────────────────────────────


class ApiKeyDetector(BaseDetector):
    """
    Detects vendor-prefixed API keys and high-entropy credential strings.

    Providers: Anthropic (sk-ant-), OpenAI (sk-proj-, sk-), GitHub (ghp_, gho_,
    ghs_, github_pat_), Bearer tokens, and generic high-entropy strings.

    Stub — implementation pending (build order step 3).
    """

    def detect(self, text: str) -> list[DetectionResult]:
        return []


# ── Shared helpers ────────────────────────────────────────────────────────────


def _is_comment_line(text: str, pos: int) -> bool:
    """Return True if pos falls on a line that starts with a comment marker."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end_raw = text.find("\n", pos)
    line_end = line_end_raw if line_end_raw != -1 else len(text)
    line = text[line_start:line_end]
    return bool(_COMMENT_LINE_RE.match(line))
