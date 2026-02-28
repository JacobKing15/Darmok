"""
Abstract base detector — defines the interface all detectors must implement.
DetectionResult is the sole data contract between detectors, registry,
substitutor, and reconstructor.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    """
    A single detected entity.

    Invariant: original_text[span[0]:span[1]] == raw_value must always hold.
    placeholder is always None when a detector returns results — the registry
    is the only component that sets it.
    """

    span: tuple[int, int]    # (start_inclusive, end_exclusive) in original text
    raw_value: str           # exact matched string from original text
    category: str            # snake_case: "api_key", "jwt", "private_key",
                             #   "url_credential", "email", "ip_address", "credit_card"
    tier: int                # 1, 2, or 3
    confidence: float        # 0.0–1.0, see detector_spec.md §Confidence Composition Rules
    detector: str            # class name, e.g. "PrivateKeyDetector"
    placeholder: str | None = field(default=None)


class BaseDetector(ABC):
    """
    Abstract base for all Phase 1 detectors.

    Contract:
    - detect() returns an empty list (never raises) when nothing is found.
    - All returned DetectionResult objects must have placeholder=None.
    - Invariant: text[r.span[0]:r.span[1]] == r.raw_value for all returned results.
    - Detectors do not check redaction mode — that gate lives in pipeline.py.
    """

    @abstractmethod
    def detect(self, text: str) -> list[DetectionResult]:
        """
        Scan text and return all candidate detections with confidence scores.
        """
        ...
