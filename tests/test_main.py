"""
Tests for darmok/main.py — Phase 1 exit gate item 4.

Covers:
  - Auto-redact path: entities >= 0.85 are redacted without any prompt
  - Interactive review flow: Tier 1 entities in [0.50, 0.85) trigger the review box
  - All four actions: [r] Redact, [s] Skip once, [a] Always skip, [x] Abort
  - [p] Page action: loops back to prompt (consumed before final action)
  - Post-run summary: correct format with tier/category breakdown
  - Dry-run mode: original text returned, manifest empty, summary shown
  - Abort: SystemExit(1) raised, nothing written
  - CLI --restore guard: exits non-zero

Inputs that produce Tier 1 block-range confidence (0.50 <= conf < 0.85):
  - Bearer token without "authorization" in surrounding context: base conf 0.68
    (see api_keys.py — bearer tokens do NOT get the generic boost; suppress-only)
  - Input: "Request: Bearer <20+ alphanumeric chars>"

Inputs that produce auto-redact confidence (>= 0.85):
  - GitHub PAT: ghp_[a-zA-Z0-9]{36} — base conf 0.97
"""

from __future__ import annotations

import io
import secrets
import string
import sys

import pytest

from darmok.main import (
    AUTO_REDACT_THRESHOLD,
    TIER1_BLOCK_THRESHOLD,
    _print_summary,
    _run_review,
    _sha256,
    sanitize_interactive,
)
from darmok.pipeline import Pipeline
from tests.synthetic_data.generate import _fake_github_pat


# ── Helpers ───────────────────────────────────────────────────────────────────


def _bearer_token(n: int = 30) -> str:
    """Generate a bearer token value (not a vendor-prefixed key) of length n."""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(n))


def _bearer_text(token: str | None = None) -> tuple[str, str]:
    """
    Return (text, token) where text puts the bearer token in a non-authorization
    context so the ApiKeyDetector assigns base confidence 0.68 (block range).
    """
    tok = token or _bearer_token()
    # "Request:" has no boost keyword → no boost → base conf stays 0.68
    return f"Request: Bearer {tok}", tok


def _github_pat_text() -> tuple[str, str]:
    """Return (text, pat) with a GitHub PAT that auto-redacts at 0.97 confidence."""
    pat = _fake_github_pat()
    return f"GITHUB_TOKEN={pat}", pat


class _MockInput:
    """Simulates terminal input — yields responses in order, raises on exhaustion."""

    def __init__(self, responses: list[str]) -> None:
        self._iter = iter(responses)

    def __call__(self) -> str:
        return next(self._iter)


# ── Auto-redact path (no review prompt) ──────────────────────────────────────


def test_auto_redact_does_not_prompt() -> None:
    """
    Entities with confidence >= AUTO_REDACT_THRESHOLD are redacted without any
    interactive prompt.  The mock input_fn must never be called.
    """
    text, pat = _github_pat_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    called = []

    def _unexpected_input() -> str:
        called.append(True)
        return "r"

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_unexpected_input, stderr=stderr,
    )

    assert not called, "input_fn must not be called for auto-redact entities"
    assert pat not in sanitized, "GitHub PAT must be redacted"
    assert len(manifest) == 1


def test_auto_redact_round_trip() -> None:
    """Auto-redacted text reconstructs back to the original."""
    text, pat = _github_pat_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput([]), stderr=stderr,
    )

    assert pipeline.reconstruct(sanitized, manifest) == text


# ── Interactive review: action [r] Redact ─────────────────────────────────────


def test_review_action_redact() -> None:
    """[r] Redact — entity is replaced with a placeholder in the output."""
    text, token = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput(["r"]), stderr=stderr,
    )

    assert token not in sanitized, "Token must be redacted after action 'r'"
    assert len(manifest) == 1, "Manifest must contain one entry"
    assert pipeline.reconstruct(sanitized, manifest) == text


def test_review_action_redact_summary_shows_tier1() -> None:
    """After [r], the post-run summary must show Tier 1 redacted count."""
    text, _ = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitize_interactive(text, pipeline, input_fn=_MockInput(["r"]), stderr=stderr)

    output = stderr.getvalue()
    assert "Tier 1" in output
    assert "API key" in output or "api key" in output


# ── Interactive review: action [s] Skip once ──────────────────────────────────


def test_review_action_skip_once() -> None:
    """[s] Skip once — entity is NOT redacted; appears as plaintext in output."""
    text, token = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput(["s"]), stderr=stderr,
    )

    assert token in sanitized, "Token must appear as plaintext after action 's'"
    assert manifest == {}, "Manifest must be empty when only item was skipped"


def test_review_action_skip_once_does_not_affect_auto_redact() -> None:
    """
    When the same text has one auto-redact entity and one review-range entity,
    skipping the review entity does not affect the auto-redact entity.
    """
    pat = _fake_github_pat()
    tok = _bearer_token()
    text = f"GITHUB_TOKEN={pat}\nRequest: Bearer {tok}"
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput(["s"]), stderr=stderr,
    )

    assert pat not in sanitized, "GitHub PAT must still be auto-redacted"
    assert tok in sanitized, "Bearer token must remain after skip"
    assert len(manifest) == 1


# ── Interactive review: action [a] Always skip ────────────────────────────────


def test_review_action_always_skip() -> None:
    """[a] Always skip — entity is NOT redacted; its hash is added to allowlist."""
    text, token = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput(["a"]), stderr=stderr,
    )

    assert token in sanitized, "Token must appear as plaintext after action 'a'"
    assert manifest == {}


def test_review_action_always_skip_prevents_reprompt() -> None:
    """
    After [a], a second occurrence of the same value in the same call must NOT
    re-prompt — the allowlist suppresses it immediately.

    Note: overlap resolution de-duplicates spans, so within one prompt the same
    raw_value may appear as the same DetectionResult only once.  We test the
    allowlist effect by mocking _run_review with an instrumented allowlist.
    """
    from darmok.main import _sha256

    token = _bearer_token()
    allowlist: set[str] = set()

    # Simulate "always skip" adding to allowlist
    allowlist.add(_sha256(token))

    # Build a fake DetectionResult pointing at the token
    from darmok.detectors.base import DetectionResult

    result = DetectionResult(
        span=(0, len(token)),
        raw_value=token,
        category="api_key",
        tier=1,
        confidence=0.68,
        detector="ApiKeyDetector",
        placeholder=None,
    )

    input_called = []

    def _unexpected_input() -> str:
        input_called.append(True)
        return "r"

    stderr = io.StringIO()
    action = _run_review(
        result, token, allowlist, input_fn=_unexpected_input, output=stderr
    )

    assert not input_called, "input_fn must not be called when hash is in allowlist"
    assert action == "s", f"Expected 's' (allowlist skip), got {action!r}"


# ── Interactive review: action [x] Abort ─────────────────────────────────────


def test_review_action_abort_raises_systemexit() -> None:
    """[x] Abort — raises SystemExit(1). Nothing is returned or written."""
    text, _ = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    with pytest.raises(SystemExit) as exc_info:
        sanitize_interactive(
            text, pipeline, input_fn=_MockInput(["x"]), stderr=stderr,
        )

    assert exc_info.value.code == 1
    assert "Aborted" in stderr.getvalue()


def test_review_action_abort_on_eof() -> None:
    """EOFError from input_fn is treated as abort (SystemExit(1))."""
    text, _ = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    def _eof() -> str:
        raise EOFError

    with pytest.raises(SystemExit) as exc_info:
        sanitize_interactive(text, pipeline, input_fn=_eof, stderr=stderr)

    assert exc_info.value.code == 1


# ── Interactive review: action [p] Page then action ──────────────────────────


def test_review_action_page_then_redact(monkeypatch) -> None:
    """
    [p] Page — the full-text pager is called, then the prompt is shown again.
    After [p], the user enters [r] — entity is redacted.
    """
    pager_calls: list[str] = []
    monkeypatch.setattr("pydoc.pager", lambda text: pager_calls.append(text))

    text, token = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput(["p", "r"]), stderr=stderr,
    )

    assert pager_calls, "pydoc.pager must have been called for action 'p'"
    assert pager_calls[0] == text, "Pager must receive the full original text"
    assert token not in sanitized, "Token must be redacted after 'p' then 'r'"


def test_review_invalid_action_then_valid(monkeypatch) -> None:
    """
    Invalid action input is ignored and the prompt repeats.
    After invalid input, [s] is accepted.
    """
    monkeypatch.setattr("pydoc.pager", lambda _: None)
    text, token = _bearer_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput(["z", "!", "s"]), stderr=stderr,
    )

    assert token in sanitized, "Token must remain as plaintext after 's'"
    error_output = stderr.getvalue()
    assert "Invalid action" in error_output


# ── Dry-run mode ──────────────────────────────────────────────────────────────


def test_dry_run_returns_original_text() -> None:
    """
    In dry-run mode, sanitize_interactive must return the original unchanged text
    and an empty manifest, regardless of what would be redacted.
    """
    text, pat = _github_pat_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, dry_run=True, input_fn=_MockInput([]), stderr=stderr,
    )

    assert sanitized == text, "Dry-run must not modify the text"
    assert manifest == {}, "Dry-run manifest must be empty"
    assert "[DRY RUN]" in stderr.getvalue()


def test_dry_run_summary_shows_would_be_redacted() -> None:
    """Dry-run summary must list what would have been redacted."""
    text, pat = _github_pat_text()
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitize_interactive(
        text, pipeline, dry_run=True, input_fn=_MockInput([]), stderr=stderr,
    )

    output = stderr.getvalue()
    assert "[DRY RUN]" in output
    assert "✓ Sanitization complete" in output


# ── Post-run summary format ───────────────────────────────────────────────────


def test_summary_format_all_tiers() -> None:
    """_print_summary must emit the exact format from DARMOK_PROJECT_CONTEXT.md."""
    from darmok.detectors.base import DetectionResult

    redacted = [
        DetectionResult(span=(0, 5), raw_value="k1", category="api_key",
                        tier=1, confidence=0.97, detector="ApiKeyDetector",
                        placeholder="[sess_aabbcc:API_KEY_1]"),
        DetectionResult(span=(6, 11), raw_value="k2", category="url_credential",
                        tier=1, confidence=0.97, detector="UrlCredentialDetector",
                        placeholder="[sess_aabbcc:URL_CREDENTIAL_1]"),
        DetectionResult(span=(12, 17), raw_value="e1", category="email",
                        tier=2, confidence=0.92, detector="EmailDetector",
                        placeholder="[sess_aabbcc:EMAIL_1]"),
        DetectionResult(span=(18, 23), raw_value="e2", category="email",
                        tier=2, confidence=0.92, detector="EmailDetector",
                        placeholder="[sess_aabbcc:EMAIL_2]"),
        DetectionResult(span=(24, 29), raw_value="ip1", category="ip_address",
                        tier=2, confidence=0.92, detector="IpAddressDetector",
                        placeholder="[sess_aabbcc:IP_ADDRESS_1]"),
    ]

    buf = io.StringIO()
    _print_summary(redacted, session_id="aabbcc", file=buf)
    output = buf.getvalue()

    assert "✓ Sanitization complete" in output
    assert "Tier 1" in output and "2 redacted" in output
    assert "Tier 2" in output and "3 redacted" in output
    assert "Tier 3" in output and "0 flagged" in output
    assert "Session: aabbcc" in output
    assert "Unstructured content is not in scope." in output


def test_summary_format_zero_redacted() -> None:
    """When nothing is redacted, summary shows zeros for all tiers."""
    buf = io.StringIO()
    _print_summary([], session_id="aabbcc", file=buf)
    output = buf.getvalue()

    assert "Tier 1 — 0 redacted" in output
    assert "Tier 2 — 0 redacted" in output
    assert "Tier 3 — 0 flagged" in output


def test_summary_pluralisation() -> None:
    """Single entity shows singular label; multiple show plural."""
    from darmok.detectors.base import DetectionResult

    one = [
        DetectionResult(span=(0, 5), raw_value="k", category="api_key",
                        tier=1, confidence=0.97, detector="ApiKeyDetector",
                        placeholder="[sess_x:API_KEY_1]"),
    ]
    buf = io.StringIO()
    _print_summary(one, session_id="x", file=buf)
    assert "1 API key" in buf.getvalue()
    assert "API keys" not in buf.getvalue()

    two = one + [
        DetectionResult(span=(6, 11), raw_value="k2", category="api_key",
                        tier=1, confidence=0.97, detector="ApiKeyDetector",
                        placeholder="[sess_x:API_KEY_2]"),
    ]
    buf2 = io.StringIO()
    _print_summary(two, session_id="x", file=buf2)
    assert "2 API keys" in buf2.getvalue()


# ── CLI --restore guard ───────────────────────────────────────────────────────


def test_cli_restore_not_available() -> None:
    """--restore must print an error and exit non-zero in Phase 1."""
    from darmok.main import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--restore"])

    assert exc_info.value.code == 1


# ── No entities — clean pass-through ─────────────────────────────────────────


def test_clean_text_passes_through_unchanged() -> None:
    """Text with no sensitive content must be returned unchanged with empty manifest."""
    text = "The deployment completed successfully. No issues found."
    pipeline = Pipeline()
    stderr = io.StringIO()

    sanitized, manifest = sanitize_interactive(
        text, pipeline, input_fn=_MockInput([]), stderr=stderr,
    )

    assert sanitized == text
    assert manifest == {}
