"""
IP address detector — IPv4 and IPv6 with context-aware tier assignment.

Tier 2 for real infrastructure IPs; Tier 3 for contextually ambiguous ones
(example markers, loopback, documentation ranges).
"""

from __future__ import annotations

import re
from collections import deque

from darmok.detectors.base import BaseDetector, DetectionResult

# ── IPv4 ──────────────────────────────────────────────────────────────────────

# Strict octet validation (0–255) per detector_spec.md §Detector 6
_IPV4_RE = re.compile(
    r"\b"
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"\b"
)

# ── IPv6 ──────────────────────────────────────────────────────────────────────

# Full form + compressed forms (RFC 5952).  Excludes bare '::' to reduce FPs.
_IPV6_RE = re.compile(r"""(?ix)
    \b
    (?:
        # Full 8-group form
        (?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}
        |
        # Trailing :: (e.g. 2001:db8::)
        (?:[0-9a-f]{1,4}:){1,7}:
        |
        # Leading :: (e.g. ::1)
        :(?::[0-9a-f]{1,4}){1,7}
        |
        # Middle :: variants
        (?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}
        |
        (?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}
        |
        (?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}
        |
        (?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}
        |
        (?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}
        |
        [0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}
    )
    \b
""")

# ── Special-case IP checks ─────────────────────────────────────────────────────

# RFC 5737 TEST-NET documentation ranges — confidence 0.15, Tier 3
_RFC5737_PREFIXES = frozenset({"192.0.2", "198.51.100", "203.0.113"})


def _is_rfc5737(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and ".".join(parts[:3]) in _RFC5737_PREFIXES


# ── Context helpers ────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"\w+")
_CTX_WINDOW = 15  # 15 tokens either side (detector_spec.md §Token Definition)


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


# Context suppression → Tier 3, confidence 0.30 (spec §Detector 6)
_IP_SUPPRESS_KEYWORDS = frozenset({
    "example", "eg", "imagine", "suppose", "sample",
    "placeholder", "dummy", "fake", "test", "illustration",
    "hypothetical", "such", "like",
})

# Server-config / infrastructure context → 0.92, Tier 2
# Tokens that reliably indicate structured config files (Terraform, K8s, .env, nginx)
_IP_CONFIG_KEYWORDS = frozenset({
    "host", "upstream", "backend", "server", "db_host", "dbhost",
    "terraform", "private_ip", "hostip", "binding", "config",
    "manifest", "kubernetes", "k8s",
})

# Error-log / operational-command context → 0.88, Tier 2
# Tokens that reliably indicate a log line or infrastructure command
_IP_LOG_KEYWORDS = frozenset({
    "fatal", "failed", "refused", "rejected", "connect", "connection",
    "connecting", "unreachable", "error", "warn", "nginx", "firewall",
    "ssh", "deploy", "pool", "oomkilled", "timeout",
})


def _port_boost(text: str, ip_end: int) -> float:
    """
    Return +0.10 if the IP match is immediately followed by :PORT (digits).
    Implements spec §Detector 6: 'IP with port in connection string context'.
    """
    if ip_end < len(text) and text[ip_end] == ":":
        i = ip_end + 1
        while i < len(text) and text[i].isdigit():
            i += 1
        if i > ip_end + 1:  # at least one digit
            return 0.10
    return 0.0


def _ip_confidence_and_tier(
    ip: str, text: str, start: int, end: int,
) -> tuple[float, int]:
    """
    Returns (confidence, tier) for an IP match.

    Priority order (highest to lowest precedence):
      1. Loopback (127.0.0.1 / ::1)         → 0.40, Tier 3
      2. All-zeros (0.0.0.0)                 → 0.15, Tier 3
      3. Broadcast (255.255.255.255)         → 0.35, Tier 3
      4. RFC 5737 documentation range        → 0.15, Tier 3
      5. Suppression context keywords        → 0.30 (+port), Tier 3
      6. Config context keywords             → 0.92 (+port), Tier 2
      7. Log/command context keywords        → 0.88 (+port), Tier 2
      8. Default (no signal)                 → 0.75 (+port), Tier 2

    Port boost (+0.10) applies to cases 5–8 only.
    """
    ip_lower = ip.lower()

    # --- Special-value checks (unconditional, not context-dependent) ---
    if ip == "127.0.0.1" or ip_lower == "::1":
        return 0.40, 3
    if ip == "0.0.0.0":
        return 0.15, 3
    if ip == "255.255.255.255":
        return 0.35, 3
    if _is_rfc5737(ip):
        return 0.15, 3

    # --- Context-dependent scoring ---
    ctx = _context_tokens(text, start, end)
    ctx_text = " ".join(t.lower() for t in ctx)
    boost = _port_boost(text, end)

    for kw in _IP_SUPPRESS_KEYWORDS:
        if kw in ctx_text:
            return min(1.0, 0.30 + boost), 3

    for kw in _IP_CONFIG_KEYWORDS:
        if kw in ctx_text:
            return min(1.0, 0.92 + boost), 2

    for kw in _IP_LOG_KEYWORDS:
        if kw in ctx_text:
            return min(1.0, 0.88 + boost), 2

    return min(1.0, 0.75 + boost), 2


class IpAddressDetector(BaseDetector):
    """
    Detects IPv4 and IPv6 addresses with context-aware confidence and tier scoring.

    IPv4: strict octet validation (0–255) via regex
    IPv6: full form and common compressed forms (::1, fe80::1, 2001:db8::, etc.)

    Confidence/tier rules (detector_spec.md §Detector 6):
      Server config, Terraform, K8s, .env   → 0.92, Tier 2
      Error log or stack trace              → 0.88, Tier 2
      Natural language, no example markers  → 0.75, Tier 2
      Natural language WITH example markers → 0.30, Tier 3
      RFC 5737 documentation ranges         → 0.15, Tier 3
      127.0.0.1 / ::1 (loopback)            → 0.40, Tier 3
      0.0.0.0                               → 0.15, Tier 3
      255.255.255.255 (broadcast)           → 0.35, Tier 3
      IP with port in connection string     → +0.10 boost (cases 5–8 only)
    """

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        seen_spans: set[tuple[int, int]] = set()

        for m in _IPV4_RE.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            span = (start, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            assert text[start:end] == raw, "span invariant violated"
            confidence, tier = _ip_confidence_and_tier(raw, text, start, end)
            results.append(DetectionResult(
                span=span,
                raw_value=raw,
                category="ip_address",
                tier=tier,
                confidence=confidence,
                detector=self.__class__.__name__,
                placeholder=None,
            ))

        for m in _IPV6_RE.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            span = (start, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            assert text[start:end] == raw, "span invariant violated"
            confidence, tier = _ip_confidence_and_tier(raw, text, start, end)
            results.append(DetectionResult(
                span=span,
                raw_value=raw,
                category="ip_address",
                tier=tier,
                confidence=confidence,
                detector=self.__class__.__name__,
                placeholder=None,
            ))

        return results
