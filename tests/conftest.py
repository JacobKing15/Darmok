# Shared pytest fixtures — session-scoped so the expensive generate_all() call
# and the evaluate() run happen once per test session, not once per test.

import pytest

from darmok.detectors.api_keys import ApiKeyDetector, JwtDetector, PrivateKeyDetector
from darmok.detectors.credit_cards import CreditCardDetector
from darmok.detectors.email import EmailDetector
from darmok.detectors.ip_address import IpAddressDetector
from darmok.detectors.urls import UrlCredentialDetector
from tests.harness import AUTO_REDACT_THRESHOLD, BenchmarkResult, evaluate
from tests.synthetic_data.generate import generate_all


@pytest.fixture(scope="session")
def all_detectors():
    """All Phase 1 detector instances. Shared across the full test session."""
    return [
        PrivateKeyDetector(),
        JwtDetector(),
        ApiKeyDetector(),
        UrlCredentialDetector(),
        EmailDetector(),
        IpAddressDetector(),
        CreditCardDetector(),
    ]


@pytest.fixture(scope="session")
def test_cases():
    """Full synthetic test suite — 50 cases per category plus mixed and negative prompts."""
    return generate_all(n_per_category=50)


@pytest.fixture(scope="session")
def benchmark_result(test_cases, all_detectors) -> BenchmarkResult:
    """
    Single evaluation run cached for the entire session.
    All precision/recall tests read from this result rather than re-running evaluate().
    """
    return evaluate(test_cases, all_detectors, confidence_threshold=AUTO_REDACT_THRESHOLD)
