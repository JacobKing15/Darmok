"""
Reconstructor — restores real values from the per-exchange outbound manifest.

Security model (from DARMOK_PROJECT_CONTEXT.md §Reconstructor — Injection Safety):
  - Only placeholders that appear in the outbound manifest can be expanded.
  - Placeholder-shaped strings NOT in the manifest are flagged inline:
      ⚠ [sess_a3f9b2:EMAIL_1] — not in outbound manifest, left unexpanded
  - This closes two attack vectors:
      1. Arbitrary vault expansion (attacker-controlled LLM output → secret exfil)
      2. Fabricated placeholder confusion (LLM-generated look-alikes are flagged)

Skeleton — not yet implemented.
"""

from __future__ import annotations


class Reconstructor:
    """
    Manifest-scoped response reconstructor.

    Phase 1: in-memory. Phase 2: vault-backed with expiry handling.
    """

    def reconstruct(
        self,
        response_text: str,
        outbound_manifest: dict[str, str],
    ) -> str:
        """
        Expand placeholders in response_text using outbound_manifest.

        outbound_manifest maps placeholder → raw_value.

        Placeholder-shaped strings not in outbound_manifest are flagged inline
        rather than expanded or silently passed through.

        Raises NotImplementedError until implemented.
        """
        raise NotImplementedError("Reconstructor.reconstruct() not yet implemented")
