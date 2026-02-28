"""
URL credential detector — detects credentials embedded in connection string URLs.

Pattern: scheme://user:password@host
The full URL including scheme and host is replaced (not just the password) to
avoid leaking the host alongside a redacted credential.

Stub — implementation pending (build order step 4).
"""

from __future__ import annotations

from darmok.detectors.base import BaseDetector, DetectionResult


class UrlCredentialDetector(BaseDetector):
    """
    Detects URLs with embedded credentials in the userinfo component.

    Schemes: postgres, postgresql, mysql, mongodb, redis, amqp, ftp, sftp, http, https.
    Pattern: scheme://user:password@host[/path]

    Confidence rules (from detector_spec.md §Detector 4):
      Known DB/service scheme + user:password@host  → 0.97
      http/https with user:password@host            → 0.90
      URL with @ but no :password pattern           → 0.20 (likely email in URL)

    Stub — implementation pending.
    """

    def detect(self, text: str) -> list[DetectionResult]:
        return []
