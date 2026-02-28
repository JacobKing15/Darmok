"""
Substitution engine — replaces detected raw values with registry placeholders.

Rules (from DARMOK_PROJECT_CONTEXT.md §Pipeline Stages):
  - Single pass: longer matches processed before shorter ones.
  - Left-to-right for equal-length non-overlapping matches.
  - Overlapping spans resolved by pipeline before substitution is called
    (overlap resolution lives in the pipeline, not here).

Preconditions for substitute():
  - results must be non-overlapping (caller's responsibility)
  - every DetectionResult must have placeholder set (registry sets it before
    substitution is called)
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

        Processes results in span-start order (left to right).  Caller must
        ensure results are non-overlapping before calling this method.

        Returns:
          (substituted_text, results_applied_sorted_by_span_start)

        Raises:
          ValueError if any result has placeholder=None.
        """
        sorted_results = sorted(results, key=lambda r: r.span[0])

        parts: list[str] = []
        pos = 0
        applied: list[DetectionResult] = []

        for r in sorted_results:
            start, end = r.span
            if r.placeholder is None:
                raise ValueError(
                    f"DetectionResult.placeholder is None — registry must assign "
                    f"placeholders before substitution is called. Result: {r!r}"
                )
            parts.append(text[pos:start])
            parts.append(r.placeholder)
            pos = end
            applied.append(r)

        parts.append(text[pos:])
        return "".join(parts), applied
