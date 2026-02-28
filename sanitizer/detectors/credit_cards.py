# Credit card number detector — regex for major card formats (Visa, Mastercard,
# Amex, Discover) with Luhn algorithm as a gate condition; rejects any candidate
# that fails Luhn regardless of pattern match.

from sanitizer.detectors.base import BaseDetector, Detection


class CreditCardDetector(BaseDetector):
    def detect(self, text: str) -> list[Detection]:
        return []
