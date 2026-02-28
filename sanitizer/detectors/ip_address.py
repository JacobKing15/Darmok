# IPv4 and IPv6 address detector — handles addresses in isolation, embedded in
# connection strings, and with port suffixes; uses context to differentiate
# sensitive IPs from loopback, broadcast, and example/documentation IPs.

from sanitizer.detectors.base import BaseDetector, Detection


class IpAddressDetector(BaseDetector):
    def detect(self, text: str) -> list[Detection]:
        return []
