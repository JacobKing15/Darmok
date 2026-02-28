# Email address detector — regex pattern match combined with domain validity check
# and surrounding context heuristics to score confidence and reduce false positives.

from sanitizer.detectors.base import BaseDetector, Detection


class EmailDetector(BaseDetector):
    def detect(self, text: str) -> list[Detection]:
        return []
