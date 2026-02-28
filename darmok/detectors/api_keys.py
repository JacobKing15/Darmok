"""
API key, JWT, and private key detectors.

All three detectors live here per the spec file layout.

Build order (detector_spec.md §Implementation Order):
  1. PrivateKeyDetector — implemented ✓
  2. JwtDetector        — implemented ✓
  3. ApiKeyDetector     — implemented ✓
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections import deque

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


# Three-segment base64url JWT: eyJ<header>.<payload>.<signature>
# The eyJ prefix is base64url for '{"' — reliable discriminator.
_JWT_RE = re.compile(
    r"eyJ[a-zA-Z0-9_-]+"       # header segment (starts with eyJ)
    r"\.[a-zA-Z0-9_-]+"        # payload segment
    r"\.[a-zA-Z0-9_-]+"        # signature segment
)


def _decode_b64url(segment: str) -> bytes | None:
    """Decode a base64url segment (no padding required). Returns None on failure."""
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=False)
    except Exception:
        return None


def _jwt_confidence(header_segment: str) -> float:
    """
    Confidence rules (detector_spec.md §Detector 2):
      header decodes to valid JSON → 0.99
      all segments valid base64url → 0.97
      header does not decode cleanly → 0.72
    """
    raw_bytes = _decode_b64url(header_segment)
    if raw_bytes is None:
        return 0.72
    try:
        json.loads(raw_bytes.decode("utf-8"))
        return 0.99
    except (ValueError, UnicodeDecodeError):
        return 0.97  # decoded but not JSON — still valid base64url


class JwtDetector(BaseDetector):
    """
    Detects JSON Web Tokens by their three-segment base64url structure.

    Pattern: eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+

    Confidence rules (detector_spec.md §Detector 2):
      header decodes to valid JSON → 0.99
      all segments valid base64url → 0.97
      header does not decode cleanly → 0.72
    """

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for m in _JWT_RE.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            header_segment = raw.split(".")[0]
            confidence = _jwt_confidence(header_segment)
            results.append(DetectionResult(
                span=(start, end),
                raw_value=raw,
                category="jwt",
                tier=1,
                confidence=confidence,
                detector=self.__class__.__name__,
                placeholder=None,
            ))
        return results


# ── ApiKeyDetector ────────────────────────────────────────────────────────────


# Context window helpers shared by ApiKeyDetector
_CTX_TOKEN_RE = re.compile(r"\w+")

_API_BOOST_KEYWORDS = frozenset({
    "key", "token", "secret", "api", "auth", "credential", "bearer", "authorization",
})
_API_SUPPRESS_KEYWORDS = frozenset({
    "example", "placeholder", "redacted", "dummy", "fake", "test", "todo",
    "your_key_here",
})
_API_TEST_VALUE_PREFIXES = ("sk-ant-test", "ghp_test")

# Vendor-specific patterns — ordered most-specific first to prevent
# shorter patterns from shadowing longer ones at the same position.
# Each entry: (compiled_regex, base_confidence)
_VENDOR_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    # Anthropic — sk-ant- prefix, variable length
    (re.compile(r"\bsk-ant-[a-zA-Z0-9\-]{20,}"), 0.97),
    # Stripe live / test
    (re.compile(r"\bsk_live_[a-zA-Z0-9]{24,}"), 0.97),
    (re.compile(r"\bsk_test_[a-zA-Z0-9]{24,}"), 0.97),
    # OpenAI new-style
    (re.compile(r"\bsk-proj-[a-zA-Z0-9]{20,}"), 0.97),
    # GitHub — fine-grained PAT before short PAT to avoid prefix collision
    (re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{82}\b"), 0.97),
    (re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"), 0.97),
    (re.compile(r"\bgho_[a-zA-Z0-9]{36}\b"), 0.97),
    (re.compile(r"\bghs_[a-zA-Z0-9]{36}\b"), 0.97),
    # AWS access key ID
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), 0.97),
    # OpenAI legacy — sk- with no sub-prefix, medium confidence (needs context boost)
    (re.compile(r"\bsk-[a-zA-Z0-9]{48}\b"), 0.72),
]

# Bearer token: group(1) is the credential value (raw_value excludes "Bearer ")
_BEARER_RE = re.compile(r"Bearer ([a-zA-Z0-9\-._~+/]{20,})")


def _api_context_tokens(text: str, start: int, end: int, window: int = 10) -> list[str]:
    """
    Return up to `window` tokens immediately before and after the span [start, end].
    Tokens that overlap the span are excluded (spec §Token Definition).
    """
    buf: deque[str] = deque(maxlen=window)
    after: list[str] = []
    for m in _CTX_TOKEN_RE.finditer(text):
        s, e, t = m.start(), m.end(), m.group()
        if e <= start:
            buf.append(t)          # deque(maxlen) keeps only last `window` tokens
        elif s >= end and len(after) < window:
            after.append(t)
    return list(buf) + after


def _api_apply_context(base: float, text: str, start: int, end: int, raw: str) -> float:
    """
    Apply context suppression and boost rules (spec §Detector 3 §Context Disambiguation).

    Suppression overrides boost — if both conditions apply, suppression wins.
    Suppressed confidence floor: 0.20.
    Boost: +0.15, capped at 1.0.
    """
    # Value-level suppression: known test fixture prefixes
    raw_lower = raw.lower()
    for prefix in _API_TEST_VALUE_PREFIXES:
        if raw_lower.startswith(prefix):
            return 0.20

    ctx_tokens = _api_context_tokens(text, start, end)
    ctx_text = " ".join(t.lower() for t in ctx_tokens)

    # Suppress
    for kw in _API_SUPPRESS_KEYWORDS:
        if kw in ctx_text:
            return 0.20

    # Boost
    for kw in _API_BOOST_KEYWORDS:
        if kw in ctx_text:
            return min(1.0, base + 0.15)

    return base


class ApiKeyDetector(BaseDetector):
    """
    Detects vendor-prefixed API keys and Bearer credential tokens.

    Providers covered (detector_spec.md §Detector 3):
      Anthropic:  sk-ant-[a-zA-Z0-9\\-]{20,}  → 0.97
      Stripe:     sk_live_/sk_test_ + 24+      → 0.97
      OpenAI new: sk-proj-[20+]                → 0.97
      OpenAI leg: sk-[48]                      → 0.72 (context boost to ≥ 0.85)
      GitHub:     ghp_/gho_/ghs_[36],
                  github_pat_[82]              → 0.97
      AWS:        AKIA[A-Z0-9]{16}             → 0.97
      Bearer:     Bearer <token>               → 0.92 (Auth header) / 0.68 (other)

    Context rules:
      Boost  +0.15  if surrounding 10 tokens contain: key, token, secret, api,
                    auth, credential, bearer, authorization
      Suppress→0.20 if surrounding 10 tokens contain: example, placeholder,
                    redacted, dummy, fake, test, todo, your_key_here
      Suppress→0.20 if value starts with known test fixture prefix (sk-ant-test, ghp_test)
    """

    def detect(self, text: str) -> list[DetectionResult]:
        # span → (raw_value, confidence) — keeps highest confidence per span
        seen: dict[tuple[int, int], tuple[str, float]] = {}

        # Phase 1: vendor-specific patterns
        for pattern, base_conf in _VENDOR_PATTERNS:
            for m in pattern.finditer(text):
                span = (m.start(), m.end())
                raw = m.group()
                conf = _api_apply_context(base_conf, text, span[0], span[1], raw)
                if span not in seen or conf > seen[span][1]:
                    seen[span] = (raw, conf)

        # Phase 2: Bearer tokens
        # group(1) is the credential only — "Bearer " prefix is excluded from raw_value.
        # JWTs starting with eyJ are skipped (handled by JwtDetector).
        for m in _BEARER_RE.finditer(text):
            raw = m.group(1)
            if raw.startswith("eyJ"):
                continue
            span = (m.start(1), m.end(1))
            if span in seen:
                continue  # already captured by a vendor pattern above

            ctx_tokens = _api_context_tokens(text, span[0], span[1])
            ctx_text = " ".join(t.lower() for t in ctx_tokens)

            # Bearer base confidence is context-determined (not a generic boost)
            base = 0.92 if "authorization" in ctx_text else 0.68

            # Apply suppress only (auth context is already the base — no additional boost)
            raw_lower = raw.lower()
            conf: float
            if any(prefix for prefix in _API_TEST_VALUE_PREFIXES if raw_lower.startswith(prefix)):
                conf = 0.20
            elif any(kw in ctx_text for kw in _API_SUPPRESS_KEYWORDS):
                conf = 0.20
            else:
                conf = base

            seen[span] = (raw, conf)

        return [
            DetectionResult(
                span=span,
                raw_value=raw,
                category="api_key",
                tier=1,
                confidence=conf,
                detector=self.__class__.__name__,
                placeholder=None,
            )
            for span, (raw, conf) in seen.items()
        ]


# ── Shared helpers ────────────────────────────────────────────────────────────


def _is_comment_line(text: str, pos: int) -> bool:
    """Return True if pos falls on a line that starts with a comment marker."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end_raw = text.find("\n", pos)
    line_end = line_end_raw if line_end_raw != -1 else len(text)
    line = text[line_start:line_end]
    return bool(_COMMENT_LINE_RE.match(line))
