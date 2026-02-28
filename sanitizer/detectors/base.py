# Abstract base detector class — defines the interface all detectors must implement,
# including the detect() method and 0-to-1 confidence scoring contract.

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Detection:
    value: str       # the exact string detected in the source text
    category: str    # label: EMAIL | IPV4 | IPV6 | API_KEY | JWT | PRIVATE_KEY | URL_CREDENTIAL | CREDIT_CARD
    confidence: float  # 0.0–1.0; auto-redact >= 0.85, flag for review 0.50–0.84
    start: int       # character offset in source text (inclusive)
    end: int         # character offset in source text (exclusive)


class BaseDetector(ABC):
    @abstractmethod
    def detect(self, text: str) -> list[Detection]:
        """
        Scan text and return all candidate detections with confidence scores.
        Must return an empty list (not raise) when nothing is found.
        """
        ...
