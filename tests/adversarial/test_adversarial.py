# Adversarial test suite — two sections:
#
#   1. Out-of-scope (OOS) patterns — must NOT trigger auto-redaction.
#      These pass even with stub detectors; they protect against regressions.
#
#   2. In-scope adversarial patterns — MUST be detected and redacted.
#      From detector_spec.md §Adversarial Coverage Requirements, "In scope" rows.

import base64
import json
import secrets
import string

import pytest

from darmok.pipeline import Pipeline
from tests.adversarial.fixtures import ALL_ADVERSARIAL_CASES, AdversarialCase
from tests.harness import AUTO_REDACT_THRESHOLD


# ── Section 1: Out-of-scope patterns (must NOT auto-redact) ──────────────────


@pytest.mark.parametrize(
    "case",
    ALL_ADVERSARIAL_CASES,
    ids=[c.name for c in ALL_ADVERSARIAL_CASES],
)
def test_no_false_positive_above_threshold(case: AdversarialCase, all_detectors) -> None:
    """
    No detection above AUTO_REDACT_THRESHOLD is permitted for case.category_not_expected.

    Passing with stub detectors (returning []) is expected and correct — this suite
    protects against regressions introduced during implementation.
    """
    above_threshold = []
    for detector in all_detectors:
        above_threshold.extend(
            d
            for d in detector.detect(case.text)
            if d.confidence >= AUTO_REDACT_THRESHOLD
            and d.category == case.category_not_expected
        )

    assert not above_threshold, (
        f"False positive on '{case.name}':\n"
        f"  Category:  {case.category_not_expected}\n"
        f"  Threshold: {AUTO_REDACT_THRESHOLD}\n"
        f"  Input:     {case.text!r}\n"
        f"  Hits:      {[(d.raw_value, round(d.confidence, 3)) for d in above_threshold]}\n"
        f"  Spec note: {case.description}"
    )


# ── Section 2: In-scope adversarial patterns (MUST be detected) ──────────────
#
# From detector_spec.md §Adversarial Coverage Requirements "In scope" rows.
# Each test asserts that a realistic obfuscation context does NOT prevent
# detection — the detector must correctly fire on these inputs.


def test_inscope_git_diff_api_key() -> None:
    """
    Credential in a git diff line (prefixed with +) must be detected and redacted.
    Spec: 'Credential in a git diff (+API_KEY=sk-ant-...) → In scope — detect and redact'
    """
    chars = string.ascii_letters + string.digits
    key = "sk-ant-api03-" + "".join(secrets.choice(chars) for _ in range(40))
    text = f"+ANTHROPIC_API_KEY={key}"

    pipeline = Pipeline()
    resolved = pipeline.detect_resolved(text)
    api_key_hits = [r for r in resolved if r.category == "api_key"]

    assert api_key_hits, (
        f"No api_key detected in git diff line.\n"
        f"  Input: {text!r}\n"
        f"  All resolved: {[(r.category, r.raw_value[:30], r.confidence) for r in resolved]}"
    )
    assert api_key_hits[0].raw_value == key

    sanitized, _ = pipeline.run(text)
    assert key not in sanitized, "API key must be redacted in git diff context"


def test_inscope_credential_in_json_string() -> None:
    """
    Credential embedded as a plain JSON string value must be detected.
    Spec: 'Credential in a JSON string with escape sequences → In scope'
    Phase 1 detects on raw text. Standard JSON string values (no special
    escapes that split the credential) are in scope.
    """
    chars = string.ascii_letters + string.digits
    key = "ghp_" + "".join(secrets.choice(chars) for _ in range(36))
    payload = json.dumps({"GITHUB_TOKEN": key, "env": "production"})
    # e.g. {"GITHUB_TOKEN": "ghp_abc...", "env": "production"}

    pipeline = Pipeline()
    resolved = pipeline.detect_resolved(payload)
    api_key_hits = [r for r in resolved if r.category == "api_key"]

    assert api_key_hits, (
        f"No api_key detected in JSON payload.\n"
        f"  Input: {payload!r}\n"
        f"  All resolved: {[(r.category, r.raw_value[:30]) for r in resolved]}"
    )
    assert api_key_hits[0].raw_value == key

    sanitized, _ = pipeline.run(payload)
    assert key not in sanitized


def test_inscope_ip_in_cidr_notation() -> None:
    """
    IP address in CIDR notation must have the IP portion detected.
    Spec: 'IP in CIDR notation → In scope — detect IP portion only'
    The /prefix suffix must survive unchanged in the sanitized output.

    Uses a server-config context so the IP earns ≥ 0.92 confidence (above
    the 0.85 auto-redact threshold).  Plain prose gives only 0.75 — below
    threshold — which is correct behaviour per the spec's confidence table.
    """
    # "host" is an _IP_CONFIG_KEYWORDS token → confidence 0.92 (Tier 2)
    text = "Firewall rule: host 10.0.1.45/24 allowed in production subnet."

    pipeline = Pipeline()
    resolved = pipeline.detect_resolved(text)
    ip_hits = [r for r in resolved if r.category == "ip_address"]

    assert ip_hits, (
        f"No ip_address detected in CIDR notation (config context).\n"
        f"  Input: {text!r}\n"
        f"  All resolved: {[(r.category, r.raw_value) for r in resolved]}"
    )
    assert ip_hits[0].raw_value == "10.0.1.45", (
        f"raw_value should be '10.0.1.45', got {ip_hits[0].raw_value!r}"
    )

    sanitized, manifest = pipeline.run(text)
    assert "10.0.1.45" not in sanitized, "IP must be redacted"
    assert "/24" in sanitized, "/prefix must be preserved after the IP placeholder"


def test_inscope_jwt_tampered_signature() -> None:
    """
    JWT with a tampered (non-authentic) signature segment must still be detected.
    Spec: 'JWT with tampered signature segment → In scope — detect on header/payload match'
    The eyJ prefix is the reliable discriminator — the signature content is irrelevant.
    """
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(b'{"sub":"user123"}').rstrip(b"=").decode()
    tampered_sig = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    jwt_token = f"{header}.{payload_b64}.{tampered_sig}"
    text = f"Authorization: Bearer {jwt_token}"

    pipeline = Pipeline()
    resolved = pipeline.detect_resolved(text)
    jwt_hits = [r for r in resolved if r.category == "jwt"]

    assert jwt_hits, (
        f"Tampered-signature JWT not detected.\n"
        f"  JWT: {jwt_token!r}\n"
        f"  All resolved: {[(r.category, r.confidence) for r in resolved]}"
    )
    assert jwt_hits[0].raw_value == jwt_token

    sanitized, _ = pipeline.run(text)
    assert jwt_token not in sanitized, "Tampered JWT must be redacted"
