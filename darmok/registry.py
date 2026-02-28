"""
Entity registry — maps detected raw values to session-scoped placeholders.

Phase 1: in-memory only.
Phase 2: backed by encrypted vault (see docs/vault_failure_modes.md).

Placeholder format:  [sess_{session_id}:{CATEGORY}_{index}]
  e.g.               [sess_a3f9b2:API_KEY_1]

Identity rules (from DARMOK_PROJECT_CONTEXT.md §Entity Registry):
  - Same raw value → same placeholder (global dedup within session).
  - Two different values can never share a placeholder.
  - Once assigned, a placeholder is the permanent identity of a value in
    this session (collision is structurally impossible by construction).
"""

from __future__ import annotations

import secrets


class EntityRegistry:
    """
    In-memory entity registry for Phase 1.

    Thread safety: not thread-safe (single-session CLI use in Phase 1).
    Phase 2 adds vault-backed persistence and cross-session deduplication.
    """

    def __init__(self, session_id: str | None = None) -> None:
        # session_id is the first 6 hex chars of the cryptographic session ID
        self._session_id = session_id or secrets.token_hex(3)
        self._value_to_placeholder: dict[str, str] = {}
        self._category_counters: dict[str, int] = {}

    @property
    def session_id(self) -> str:
        return self._session_id

    def register(self, raw_value: str, category: str) -> str:
        """
        Return the placeholder for raw_value, creating one if first seen.

        category is snake_case (e.g. "api_key"); converted to UPPER for display.
        Placeholder format: [sess_{session_id}:{CATEGORY}_{index}]
        """
        if raw_value in self._value_to_placeholder:
            return self._value_to_placeholder[raw_value]

        upper_cat = category.upper()
        idx = self._category_counters.get(upper_cat, 0) + 1
        self._category_counters[upper_cat] = idx
        placeholder = f"[sess_{self._session_id}:{upper_cat}_{idx}]"
        self._value_to_placeholder[raw_value] = placeholder
        return placeholder

    def get(self, raw_value: str) -> str | None:
        """Return the placeholder for raw_value, or None if not registered."""
        return self._value_to_placeholder.get(raw_value)

    def reverse_map(self) -> dict[str, str]:
        """Return a {placeholder: raw_value} map for use by the reconstructor."""
        return {v: k for k, v in self._value_to_placeholder.items()}

    def __len__(self) -> int:
        return len(self._value_to_placeholder)
