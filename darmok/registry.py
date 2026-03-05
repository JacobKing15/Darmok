"""
Entity registry — maps detected raw values to session-scoped placeholders.

Phase 1: in-memory only.
Phase 2: vault-backed persistence with cross-session deduplication.

Placeholder format:  [sess_{session_id}:{CATEGORY}_{index}]
  e.g.               [sess_a3f9b2:API_KEY_1]

Identity rules (from DARMOK_PROJECT_CONTEXT.md §Entity Registry):
  - Same raw value → same placeholder (global dedup across all sessions via vault).
  - Two different values can never share a placeholder.
  - Once assigned, a placeholder is the permanent identity of a value in
    the vault (collision is structurally impossible by construction).

Phase 2 deduplication:
  When a vault is provided, register() first checks vault.lookup_by_value()
  before assigning a new placeholder. This gives cross-session identity —
  the same secret seen in any session always gets the same placeholder.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from darmok.vault import Vault


class EntityRegistry:
    """
    Entity registry with optional vault-backed persistence.

    Thread safety: not thread-safe (single-session CLI use).

    Parameters:
        session_id   — 6-char hex session ID (default: random)
        vault        — open Vault instance for cross-session dedup (Phase 2)
        expires_at   — ISO-8601 expiry for vault-stored entries
        expiry_type  — "hard" or "soft"
    """

    def __init__(
        self,
        session_id: str | None = None,
        vault: "Vault | None" = None,
        expires_at: str | None = None,
        expiry_type: str = "hard",
    ) -> None:
        self._session_id = session_id or secrets.token_hex(3)
        self._vault = vault
        self._expires_at = expires_at
        self._expiry_type = expiry_type
        self._value_to_placeholder: dict[str, str] = {}
        self._category_counters: dict[str, int] = {}

    @property
    def session_id(self) -> str:
        return self._session_id

    def register(self, raw_value: str, category: str) -> str:
        """
        Return the placeholder for raw_value, creating one if first seen.

        Phase 2: if a vault is attached, check for cross-session dedup first.
        Phase 1: pure in-memory — same value → same placeholder within session.

        category is snake_case (e.g. "api_key"); converted to UPPER for display.
        Placeholder format: [sess_{session_id}:{CATEGORY}_{index}]
        """
        # In-memory cache (within-session dedup, avoids redundant vault hits)
        if raw_value in self._value_to_placeholder:
            return self._value_to_placeholder[raw_value]

        # Phase 2: vault-backed cross-session dedup
        if self._vault is not None:
            existing = self._vault.lookup_by_value(raw_value)
            if existing is not None:
                self._value_to_placeholder[raw_value] = existing
                return existing

            # Not in vault — register and persist
            expires_at = self._expires_at or _default_expiry()
            placeholder = self._vault.register_entity(
                raw_value,
                category,
                self._session_id,
                expires_at,
                self._expiry_type,
            )
            self._value_to_placeholder[raw_value] = placeholder
            return placeholder

        # Phase 1: in-memory only
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


def _default_expiry() -> str:
    """Return ISO-8601 UTC expiry 4 hours from now (config default)."""
    from datetime import datetime, timedelta, timezone
    dt = datetime.now(timezone.utc) + timedelta(hours=4)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
