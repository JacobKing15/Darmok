"""
Reconstructor — restores real values from the per-exchange outbound manifest.

Security model (from DARMOK_PROJECT_CONTEXT.md §Reconstructor — Injection Safety):
  - Only placeholders that appear in the outbound manifest can be expanded.
  - Placeholder-shaped strings NOT in the manifest are flagged inline:
      ⚠ [sess_a3f9b2:EMAIL_1] — not in outbound manifest, left unexpanded
  - This closes two attack vectors:
      1. Arbitrary vault expansion (attacker-controlled LLM output → secret exfil)
      2. Fabricated placeholder confusion (LLM-generated look-alikes are flagged)
"""

from __future__ import annotations

import re

# Matches placeholders of the form [sess_a3f9b2:CATEGORY_NAME_1]
# Session ID: 6 lowercase hex chars
# Category:   UPPER_SNAKE_CASE, starting with an uppercase letter
# Index:      one or more digits
_PLACEHOLDER_RE = re.compile(r"\[sess_[0-9a-f]{6}:[A-Z][A-Z0-9_]*_\d+\]")


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
        """

        def expand(m: re.Match) -> str:  # type: ignore[type-arg]
            placeholder = m.group(0)
            if placeholder in outbound_manifest:
                return outbound_manifest[placeholder]
            return f"⚠ {placeholder} — not in outbound manifest, left unexpanded"

        return _PLACEHOLDER_RE.sub(expand, response_text)
