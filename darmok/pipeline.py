"""
Detection pipeline — orchestrates all Phase 1/2 stages in order.

Stages:
  1. Tokenization  — segments input into logical units
  2. Detection     — detectors run per category (only when mode is on/dry-run)
  3. Scoring       — confidence 0.0–1.0, tier-aware thresholds
  4. Registry      — placeholder assignment (in-memory Phase 1, vault-backed Phase 2)
  5. Substitution  — single pass, longer matches first
  6. Manifest      — exact set of outbound placeholders recorded
  7. Output        — clean text + post-run summary

Library usage (Neech integration):
  from darmok.pipeline import Pipeline

  pipeline = Pipeline()
  pipeline = Pipeline(config_overrides={"redaction_mode": "dry-run"})
  pipeline = Pipeline(config_overrides={"thresholds": {"auto_redact": 0.90}})

  # Phase 2 — with vault:
  from darmok.vault import Vault
  vault = Vault(config)
  vault.open(passphrase)
  pipeline = Pipeline(vault=vault, session_id="a3f9b2")

The CLI (main.py) is a thin consumer of this class — all logic lives here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from darmok.config import DarmokConfig
from darmok.detectors.api_keys import ApiKeyDetector, JwtDetector, PrivateKeyDetector
from darmok.detectors.base import DetectionResult
from darmok.detectors.credit_cards import CreditCardDetector
from darmok.detectors.email import EmailDetector
from darmok.detectors.ip_address import IpAddressDetector
from darmok.detectors.urls import UrlCredentialDetector
from darmok.reconstructor import Reconstructor
from darmok.registry import EntityRegistry
from darmok.substitutor import Substitutor

if TYPE_CHECKING:
    from darmok.vault import Vault


def _resolve_overlaps(results: list[DetectionResult]) -> list[DetectionResult]:
    """
    Greedy overlap resolution — detector_spec.md §Overlap Resolution:

      1. Longer span wins (more characters = higher priority)
      2. Lower tier number breaks equal-length ties (Tier 1 > Tier 2 > Tier 3)
      3. Higher confidence breaks remaining ties

    Returns a non-overlapping list sorted by span start, ready for substitution.
    """
    if not results:
        return []

    sorted_r = sorted(
        results,
        key=lambda r: (-(r.span[1] - r.span[0]), r.tier, -r.confidence),
    )

    selected: list[DetectionResult] = []
    for r in sorted_r:
        s, e = r.span
        overlaps = any(
            not (e <= sel.span[0] or s >= sel.span[1])
            for sel in selected
        )
        if not overlaps:
            selected.append(r)

    return sorted(selected, key=lambda r: r.span[0])


class Pipeline:
    """
    Full sanitization pipeline. Orchestrates detection, overlap resolution,
    registry, substitution, and manifest construction.

    The pipeline reads config from ~/.darmok/config.yaml by default.
    config_overrides takes precedence over the file (used by Neech).

    Redaction mode gate: detectors only run when mode is "on" or "dry-run".
    When mode is "off", the input is passed through unchanged.

    The registry is session-scoped: the same Pipeline instance maintains
    placeholder identity across multiple run() calls.  Create a new Pipeline
    to start a new session with a fresh registry.

    Phase 2: pass vault= and session_id= to enable vault-backed persistence.
    """

    def __init__(
        self,
        config_overrides: dict[str, Any] | None = None,
        vault: "Vault | None" = None,
        session_id: str | None = None,
        expires_at: str | None = None,
        expiry_type: str = "hard",
    ) -> None:
        self._config = DarmokConfig.load(overrides=config_overrides)
        self._detectors = [
            PrivateKeyDetector(),
            JwtDetector(),
            ApiKeyDetector(),
            UrlCredentialDetector(),
            EmailDetector(),
            IpAddressDetector(),
            CreditCardDetector(),
        ]
        self._registry = EntityRegistry(
            session_id=session_id,
            vault=vault,
            expires_at=expires_at,
            expiry_type=expiry_type,
        )
        self._substitutor = Substitutor()
        self._reconstructor = Reconstructor()

    @property
    def _threshold(self) -> float:
        return self._config.auto_redact_threshold

    @property
    def _tier1_block_threshold(self) -> float:
        return self._config.tier1_block_threshold

    @property
    def session_id(self) -> str:
        """The current session ID (first 6 hex chars of the cryptographic session token)."""
        return self._registry.session_id

    def detect_candidates(
        self, text: str, min_confidence: float = 0.0
    ) -> list[DetectionResult]:
        """
        Run detection with a custom minimum confidence floor and overlap resolution.

        Returns non-overlapping DetectionResults above min_confidence with
        placeholder=None.  Used by the interactive review flow in main.py, and
        by any consumer (e.g. Neech) that wants candidates below the auto-redact
        threshold for display or triage.

        Does NOT assign placeholders.
        """
        candidates: list[DetectionResult] = []
        for detector in self._detectors:
            for r in detector.detect(text):
                if r.confidence >= min_confidence:
                    candidates.append(r)
        return _resolve_overlaps(candidates)

    def detect_resolved(self, text: str) -> list[DetectionResult]:
        """
        Run detection and overlap resolution above the auto-redact threshold.

        Returns overlap-resolved DetectionResults with confidence >= auto_redact
        threshold and placeholder=None.  Suitable for dry-run preview, benchmarking,
        or any consumer that wants to inspect what would be auto-redacted.

        Does NOT assign placeholders — call run() for the full pipeline.
        """
        return self.detect_candidates(text, self._threshold)

    def run(self, text: str) -> tuple[str, dict[str, str]]:
        """
        Run the full pipeline on input text.

        Stages: detection → threshold filter → overlap resolution →
                registry → substitution → manifest.

        Returns:
          (sanitized_text, outbound_manifest)
          outbound_manifest maps placeholder → raw_value for the reconstructor.
        """
        resolved = self.detect_resolved(text)

        if not resolved:
            return text, {}

        # Assign placeholders via the session registry (deduplicates same value)
        for r in resolved:
            r.placeholder = self._registry.register(r.raw_value, r.category)

        sanitized, _ = self._substitutor.substitute(text, resolved)

        outbound_manifest = {r.placeholder: r.raw_value for r in resolved}

        return sanitized, outbound_manifest  # type: ignore[return-value]

    def reconstruct(
        self, response_text: str, outbound_manifest: dict[str, str]
    ) -> str:
        """Expand placeholders in an LLM response using the outbound manifest."""
        return self._reconstructor.reconstruct(response_text, outbound_manifest)
