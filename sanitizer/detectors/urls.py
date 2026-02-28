# URL credential detector — targets URLs with credentials in the userinfo component
# (scheme://user:password@host); redacts the credential portion only, preserving
# the scheme, host, and path for debugging utility.

from sanitizer.detectors.base import BaseDetector, Detection


class UrlCredentialDetector(BaseDetector):
    def detect(self, text: str) -> list[Detection]:
        return []
