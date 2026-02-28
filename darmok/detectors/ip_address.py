"""
IP address detector — IPv4 and IPv6 with context-aware tier assignment.

Tier 2 for real infrastructure IPs; Tier 3 for contextually ambiguous ones
(example markers, loopback, documentation ranges).

Stub — implementation pending (build order step 6).
"""

from __future__ import annotations

from darmok.detectors.base import BaseDetector, DetectionResult


class IpAddressDetector(BaseDetector):
    """
    Detects IPv4 and IPv6 addresses with context-aware confidence scoring.

    IPv4 pattern: strict octet validation (0–255)
    IPv6 pattern: full and compressed forms (::1, fe80::1, etc.)

    Confidence/tier rules (from detector_spec.md §Detector 6):
      Server config, Terraform, K8s, .env       → 0.92, Tier 2
      Error log or stack trace                   → 0.88, Tier 2
      Natural language, no example markers       → 0.75, Tier 2
      Natural language WITH example markers      → 0.30, Tier 3
      RFC 5737 documentation ranges              → 0.15, Tier 3
      127.0.0.1 / ::1 (loopback)                → 0.40, Tier 3
      0.0.0.0                                    → 0.15, Tier 3
      IP with port in connection string          → +0.10 boost

    Context suppression tokens (15-token window):
      example, e.g., for example, such as, imagine, suppose, let's say,
      sample, placeholder, dummy, fake, test, illustration, hypothetical

    Stub — implementation pending.
    """

    def detect(self, text: str) -> list[DetectionResult]:
        return []
