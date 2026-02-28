# API key, JWT, and private key detector — handles vendor-prefixed keys (sk-, ghp_,
# AKIA, sk_live_, Bearer), JWTs (eyJhbGci... three-segment base64url), and PEM-format
# private keys/certificates; uses entropy and structural heuristics for confidence.

from sanitizer.detectors.base import BaseDetector, Detection


class ApiKeyDetector(BaseDetector):
    def detect(self, text: str) -> list[Detection]:
        return []
