"""
Detection pipeline — orchestrates all Phase 1 stages in order.

Stages:
  1. Tokenization  — segments input into logical units
  2. Detection     — detectors run per category (only when mode is on/dry-run)
  3. Scoring       — confidence 0.0–1.0, tier-aware thresholds
  4. Registry      — in-memory placeholder assignment (Phase 1)
  5. Substitution  — single pass, longer matches first
  6. Manifest      — exact set of outbound placeholders recorded
  7. Output        — clean text + post-run summary

Library usage (Neech integration):
  from darmok.pipeline import Pipeline

  pipeline = Pipeline()
  pipeline = Pipeline(config_overrides={"redaction_mode": "dry-run"})
  pipeline = Pipeline(config_overrides={"thresholds": {"auto_redact": 0.90}})

The CLI (main.py) is a thin consumer of this class — all logic lives here.
"""

from __future__ import annotations

from typing import Any


class Pipeline:
    """
    Full sanitization pipeline. Skeleton — not yet implemented.

    The pipeline reads config from ~/.darmok/config.yaml by default.
    config_overrides takes precedence over the file (used by Neech).

    Redaction mode gate: detectors only run when mode is "on" or "dry-run".
    When mode is "off", the input is passed through unchanged.
    """

    def __init__(self, config_overrides: dict[str, Any] | None = None) -> None:
        self._overrides = config_overrides or {}
        # TODO Phase 1: load and validate ~/.darmok/config.yaml, merge overrides

    def run(self, text: str) -> tuple[str, dict[str, str]]:
        """
        Run the full pipeline on input text.

        Returns:
          (sanitized_text, outbound_manifest)
          outbound_manifest maps placeholder → raw_value for the reconstructor.

        Raises NotImplementedError until implemented.
        """
        raise NotImplementedError("Pipeline.run() not yet implemented — Phase 1 in progress")
