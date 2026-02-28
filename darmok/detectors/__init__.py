"""
Detector package.

Import individual detectors from their modules:
  from darmok.detectors.api_keys import PrivateKeyDetector, JwtDetector, ApiKeyDetector
  from darmok.detectors.urls import UrlCredentialDetector
  from darmok.detectors.email import EmailDetector
  from darmok.detectors.ip_address import IpAddressDetector
  from darmok.detectors.credit_cards import CreditCardDetector

All detectors inherit from BaseDetector and implement:
  detect(text: str) -> list[DetectionResult]
"""
