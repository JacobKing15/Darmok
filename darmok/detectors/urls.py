"""
URL credential detector — detects credentials embedded in connection string URLs.

Pattern: scheme://user:password@host
The full URL including scheme and host is replaced (not just the password) to
avoid leaking the host alongside a redacted credential.
"""

from __future__ import annotations

import re

from darmok.detectors.base import BaseDetector, DetectionResult

# Schemes that indicate a DB/service credential URL → confidence 0.97
_DB_SCHEMES = frozenset({
    "postgres", "postgresql", "mysql", "mongodb", "redis", "amqp", "ftp", "sftp",
})

# HTTP(S) schemes → confidence 0.90
_HTTP_SCHEMES = frozenset({"http", "https"})

# Main credential URL pattern.
# Groups: (1) scheme  (2) user (may be empty)  (3) password (may be empty)
# The host/path segment stops at whitespace and quote characters to avoid
# consuming surrounding delimiters in quoted config values or code strings.
_URL_CRED_RE = re.compile(
    r"(postgres|postgresql|mysql|mongodb|redis|amqp|ftp|sftp|https?)"
    r"://"
    r"([^:@\s]*)"   # user — zero or more non-colon, non-@, non-whitespace chars
    r":"
    r"([^@\s]*)"    # password — zero or more non-@, non-whitespace chars
    r"""@[^\s"']+"""  # @host[/path] — stop at whitespace and quote characters
)

# Passwords that are obviously placeholder/template values (case-insensitive).
# These lower confidence to 0.50 — block for review but not auto-redact.
_PLACEHOLDER_PASSWORDS = frozenset({"password", "pass", "passwd", "secret"})


def _url_confidence(scheme: str, password: str) -> float:
    """
    Confidence rules from detector_spec.md §Detector 4.

    user:@host (empty password)              → 0.40  (probably a template)
    user:password@host (literal "password")  → 0.50  (placeholder template)
    https?:// + user:pass@host               → 0.90
    DB/service scheme + user:pass@host       → 0.97
    """
    if not password:
        return 0.40
    if password.lower() in _PLACEHOLDER_PASSWORDS:
        return 0.50
    if scheme in _DB_SCHEMES:
        return 0.97
    # http / https
    return 0.90


class UrlCredentialDetector(BaseDetector):
    """
    Detects URLs with embedded credentials in the userinfo component.

    Schemes covered: postgres, postgresql, mysql, mongodb, redis, amqp,
                     ftp, sftp, http, https.
    Pattern: scheme://[user]:password@host[/path]

    Confidence rules (detector_spec.md §Detector 4):
      DB/service scheme + user:password@host → 0.97
      http/https + user:password@host        → 0.90
      user:@host (empty password)            → 0.40 — likely a template
      user:password@host (literal "password")→ 0.50 — likely a template

    Raw value: the full URL (scheme through host/path) — replacing the full
    URL avoids leaking the host alongside a redacted credential.
    """

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for m in _URL_CRED_RE.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            assert text[start:end] == raw, "span invariant violated"
            scheme = m.group(1)
            password = m.group(3)
            confidence = _url_confidence(scheme, password)
            results.append(DetectionResult(
                span=(start, end),
                raw_value=raw,
                category="url_credential",
                tier=1,
                confidence=confidence,
                detector=self.__class__.__name__,
                placeholder=None,
            ))
        return results
