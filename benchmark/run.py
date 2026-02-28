#!/usr/bin/env python
# Standalone benchmark runner — generates synthetic test data, runs all
# implemented detectors, and prints the tiered dashboard from detector_spec.md.
#
# Usage (from project root):
#   python benchmark/run.py
#
# This script is intentionally independent of pytest so the dashboard can be
# run at any time without the test suite overhead.

from __future__ import annotations

import io
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

# Force UTF-8 output on Windows (box-drawing characters require it)
if isinstance(sys.stdout, io.TextIOWrapper):
    sys.stdout.reconfigure(encoding="utf-8")

from darmok.detectors.api_keys import ApiKeyDetector, JwtDetector, PrivateKeyDetector
from darmok.detectors.credit_cards import CreditCardDetector
from darmok.detectors.email import EmailDetector
from darmok.detectors.ip_address import IpAddressDetector
from darmok.detectors.urls import UrlCredentialDetector
from tests.benchmarks.dashboard import print_dashboard
from tests.harness import AUTO_REDACT_THRESHOLD, evaluate
from tests.synthetic_data.generate import generate_all


def main() -> None:
    n_per_category = 50
    print(f"Generating {n_per_category} test cases per category + 100 negative cases...")
    test_cases = generate_all(n_per_category=n_per_category)
    print(f"Total test cases: {len(test_cases)}\n")

    detectors = [
        PrivateKeyDetector(),
        JwtDetector(),
        ApiKeyDetector(),
        UrlCredentialDetector(),
        EmailDetector(),
        IpAddressDetector(),
        CreditCardDetector(),
    ]

    result = evaluate(test_cases, detectors, confidence_threshold=AUTO_REDACT_THRESHOLD)
    print_dashboard(result)


if __name__ == "__main__":
    main()
