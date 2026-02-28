"""
Substitution engine — replaces detected raw values with registry placeholders.

Rules (from DARMOK_PROJECT_CONTEXT.md §Pipeline Stages):
  - Single pass: longer matches processed before shorter ones.
  - Left-to-right for equal-length non-overlapping matches.
  - Overlapping spans resolved by pipeline before substitution is called
    (overlap resolution lives in the pipeline, not here).

Skeleton — not yet implemented.
"""

from __future__ import annotations

from darmok.detectors.base import DetectionResult


class Substitutor:
    """
    Single-pass text substitutor.

    Requires all DetectionResult objects passed to substitute() to have
    placeholder set (non-None) — the registry populates that field before
    substitution is called.
    """

    def substitute(
        self,
        text: str,
        results: list[DetectionResult],
    ) -> tuple[str, list[DetectionResult]]:
        """
        Replace all detected spans with their assigned placeholders.

        Returns:
          (substituted_text, results_applied_sorted_by_span)

        Raises NotImplementedError until implemented.
        """
        raise NotImplementedError("Substitutor.substitute() not yet implemented")
