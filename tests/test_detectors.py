# Main detector test suite — benchmark precision/recall tests plus unit tests
# for specific behaviours documented in detector_spec.md.
#
# Benchmark tests will SKIP (not fail) when a detector returns no detections —
# the expected state while implementations are stubs.  They will FAIL once a
# detector is implemented but does not yet meet its tier target.

import pytest

from tests.harness import (
    ALL_CATEGORIES,
    AUTO_REDACT_THRESHOLD,
    CATEGORY_TIER,
    TIER_PRECISION_TARGET,
    TIER_RECALL_TARGET,
)
from tests.synthetic_data.generate import _fake_jwt, _fake_private_key


# ── Benchmark tests ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_precision_meets_threshold(benchmark_result, category: str) -> None:
    """Precision >= tier target for every implemented category."""
    r = benchmark_result.categories.get(category)
    if r is None or (r.tp + r.fp) == 0:
        pytest.skip(f"{category}: no detections yet — implement detector to enable")
    tier = CATEGORY_TIER.get(category, 3)
    threshold = TIER_PRECISION_TARGET[tier]
    assert r.precision >= threshold, (
        f"{category} precision {r.precision:.3f} < {threshold}  "
        f"(TP={r.tp} FP={r.fp} FN={r.fn})"
    )


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_recall_meets_threshold(benchmark_result, category: str) -> None:
    """Recall >= tier target for every implemented category."""
    r = benchmark_result.categories.get(category)
    if r is None or (r.tp + r.fp) == 0:
        pytest.skip(f"{category}: no detections yet — implement detector to enable")
    tier = CATEGORY_TIER.get(category, 3)
    threshold = TIER_RECALL_TARGET[tier]
    assert r.recall >= threshold, (
        f"{category} recall {r.recall:.3f} < {threshold}  "
        f"(TP={r.tp} FP={r.fp} FN={r.fn})"
    )


def test_print_dashboard(benchmark_result) -> None:
    """Print the full benchmark dashboard. Always passes — for human review."""
    from tests.benchmarks.dashboard import print_dashboard
    print_dashboard(benchmark_result)


# ── Unit tests: EmailDetector ─────────────────────────────────────────────────


class TestEmailDetector:
    def test_detects_basic_email(self, all_detectors):
        hits = _detect(all_detectors, "Contact admin@company.internal for support.", "email")
        assert any(d.raw_value == "admin@company.internal" for d in hits)

    def test_detects_plus_addressing(self, all_detectors):
        hits = _detect(all_detectors, "Routed to user+alerts@monitoring.company.com", "email")
        assert any("user+alerts@monitoring.company.com" in d.raw_value for d in hits)

    def test_detects_email_in_log_line(self, all_detectors):
        text = "[2024-01-15 14:32] Auth failure for jsmith@corp.net from 10.0.0.1"
        hits = _detect(all_detectors, text, "email")
        assert any("jsmith@corp.net" in d.raw_value for d in hits)

    def test_example_domain_not_auto_redacted(self, all_detectors):
        hits = _detect_above(all_detectors, "e.g. user@example.com", "email")
        assert not any("user@example.com" in d.raw_value for d in hits)

    def test_bare_at_sign_not_matched(self, all_detectors):
        hits = _detect_above(all_detectors, "Follow @company on social media.", "email")
        assert not hits

    def test_confidence_is_in_range(self, all_detectors):
        hits = _detect(all_detectors, "Send report to ops@internal.company.com", "email")
        for d in hits:
            assert 0.0 <= d.confidence <= 1.0, f"Confidence {d.confidence} out of range"


# ── Unit tests: IpAddressDetector ────────────────────────────────────────────


class TestIpAddressDetector:
    def test_detects_private_ipv4(self, all_detectors):
        hits = _detect(all_detectors, "Connecting to 192.168.1.100:5432", "ip_address")
        assert any("192.168.1.100" in d.raw_value for d in hits)

    def test_detects_public_ipv4(self, all_detectors):
        hits = _detect(all_detectors, "Inbound connection from 203.0.113.45 blocked.", "ip_address")
        assert any("203.0.113.45" in d.raw_value for d in hits)

    def test_detects_ip_in_connection_string(self, all_detectors):
        hits = _detect(all_detectors, "postgresql://user:pass@10.4.2.100:5432/db", "ip_address")
        assert any("10.4.2.100" in d.raw_value for d in hits)

    def test_loopback_not_auto_redacted(self, all_detectors):
        hits = _detect_above(all_detectors, "Server binding to 127.0.0.1:8080", "ip_address")
        assert not any("127.0.0.1" in d.raw_value for d in hits)

    def test_version_string_not_matched(self, all_detectors):
        hits = _detect_above(all_detectors, "Requires version 1.2.3.4 or higher.", "ip_address")
        assert not any("1.2.3.4" in d.raw_value for d in hits)

    def test_invalid_octets_rejected(self, all_detectors):
        hits = _detect(all_detectors, "Bad address: 999.256.300.1", "ip_address")
        assert not hits

    def test_confidence_is_in_range(self, all_detectors):
        hits = _detect(all_detectors, "Connect to 172.16.8.5:8080", "ip_address")
        for d in hits:
            assert 0.0 <= d.confidence <= 1.0


# ── Unit tests: ApiKeyDetector ────────────────────────────────────────────────


class TestApiKeyDetector:
    def test_detects_openai_key(self, all_detectors):
        key = "sk-" + "a" * 48
        hits = _detect(all_detectors, f"OPENAI_API_KEY={key}", "api_key")
        assert any(key in d.raw_value for d in hits)

    def test_detects_github_pat(self, all_detectors):
        key = "ghp_" + "x" * 36
        hits = _detect(all_detectors, f"token: {key}", "api_key")
        assert any(key in d.raw_value for d in hits)

    def test_detects_aws_key_id(self, all_detectors):
        key = "AKIA" + "A" * 16
        hits = _detect(all_detectors, f"AWS_ACCESS_KEY_ID={key}", "api_key")
        assert any(key in d.raw_value for d in hits)

    def test_placeholder_key_not_auto_redacted(self, all_detectors):
        hits = _detect_above(all_detectors, "Set API_KEY=sk-yourkey in your config.", "api_key")
        assert not hits

    def test_uuid_not_matched(self, all_detectors):
        hits = _detect_above(all_detectors, "Request ID: 550e8400-e29b-41d4-a716-446655440000", "api_key")
        assert not hits

    def test_detects_jwt(self, all_detectors):
        jwt = _fake_jwt()
        hits = _detect(all_detectors, f"Authorization: Bearer {jwt}", "jwt")
        assert any(jwt in d.raw_value for d in hits)

    def test_jwt_high_confidence(self, all_detectors):
        jwt = _fake_jwt()
        hits = _detect_above(all_detectors, f"token = '{jwt}'", "jwt")
        assert hits, "JWT in assignment context should exceed auto-redact threshold"

    def test_detects_pem_private_key(self, all_detectors):
        key = _fake_private_key()
        hits = _detect(all_detectors, key, "private_key")
        assert hits

    def test_private_key_high_confidence(self, all_detectors):
        key = _fake_private_key()
        hits = _detect_above(all_detectors, key, "private_key")
        assert hits, "Bare PEM block should exceed auto-redact threshold"


# ── Unit tests: UrlCredentialDetector ────────────────────────────────────────


class TestUrlCredentialDetector:
    def test_detects_postgres_url(self, all_detectors):
        url = "postgresql://admin:s3cr3t@db.internal:5432/mydb"
        hits = _detect(all_detectors, url, "url_credential")
        assert hits

    def test_detects_redis_password_only(self, all_detectors):
        url = "redis://:authtoken123@cache.internal:6379"
        hits = _detect(all_detectors, url, "url_credential")
        assert hits

    def test_detects_mongodb_url(self, all_detectors):
        url = "mongodb://appuser:password@mongo.internal:27017/collection"
        hits = _detect(all_detectors, url, "url_credential")
        assert hits

    def test_url_without_credentials_not_matched(self, all_detectors):
        hits = _detect_above(all_detectors, "https://api.example.com/v1/users", "url_credential")
        assert not hits

    def test_at_sign_in_path_not_matched(self, all_detectors):
        hits = _detect_above(all_detectors, "https://example.com/users/@john/profile", "url_credential")
        assert not hits

    def test_anonymous_ftp_low_confidence(self, all_detectors):
        hits = _detect_above(all_detectors, "ftp://anonymous@ftp.example.org/pub/", "url_credential")
        assert not hits, "anonymous user with no password should not auto-redact"


# ── Unit tests: CreditCardDetector ───────────────────────────────────────────


class TestCreditCardDetector:
    def test_detects_visa_test_number(self, all_detectors):
        hits = _detect(all_detectors, "Test card: 4111 1111 1111 1111", "credit_card")
        assert hits

    def test_detects_unformatted_visa(self, all_detectors):
        hits = _detect(all_detectors, "Card: 4111111111111111", "credit_card")
        assert hits

    def test_detects_dash_formatted_card(self, all_detectors):
        hits = _detect(all_detectors, "Card 4111-1111-1111-1111 declined.", "credit_card")
        assert hits

    def test_luhn_invalid_not_matched(self, all_detectors):
        # 4111 1111 1111 1112 — changes last digit, fails Luhn
        hits = _detect_above(all_detectors, "Number: 4111 1111 1111 1112", "credit_card")
        assert not hits

    def test_masked_card_not_matched(self, all_detectors):
        hits = _detect_above(all_detectors, "Card ending **** **** **** 4242 charged.", "credit_card")
        assert not hits

    def test_sequential_number_not_matched(self, all_detectors):
        # 1234 5678 9012 3456 — almost certainly fails Luhn
        hits = _detect_above(all_detectors, "Reference: 1234 5678 9012 3456", "credit_card")
        assert not hits


# ── Helpers ───────────────────────────────────────────────────────────────────


def _detect(detectors, text: str, category: str) -> list:
    """Return all detections for a category at any confidence level."""
    results = []
    for det in detectors:
        results.extend(d for d in det.detect(text) if d.category == category)
    return results


def _detect_above(detectors, text: str, category: str) -> list:
    """Return detections for a category above the auto-redact threshold."""
    return [d for d in _detect(detectors, text, category) if d.confidence >= AUTO_REDACT_THRESHOLD]
