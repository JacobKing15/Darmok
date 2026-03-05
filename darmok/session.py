"""
Darmok session manager — Phase 2.

Sessions are named groups of detection + redaction exchanges.
Metadata lives in ~/.darmok/sessions.json (not the vault).
Entity mappings live in the vault only.

Failure modes handled here:
  F-03  — session resumption fails (wrong passphrase or hard expiry)
  F-11  — sessions.json missing / corrupt JSON / wrong permissions
  F-13  — context doc missing at session start

Session ID format: first 6 hex chars of a secrets.token_hex(16) value.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import secrets
import shutil
import stat
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from darmok.config import DarmokConfig, _check_permissions

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.2"


# ── SessionMeta ───────────────────────────────────────────────────────────────

@dataclass
class SessionMeta:
    session_id: str          # First 6 hex chars of the cryptographic session token
    name: str
    created_at: str          # ISO-8601 UTC
    expires_at: str          # ISO-8601 UTC
    expiry_type: str         # "hard" or "soft"
    tags: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    ended: bool = False
    context_docs: list[str] = field(default_factory=list)

    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = _parse_utc(self.expires_at)
        return now >= exp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SessionMeta":
        # Forward-compatible: ignore unknown keys
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


# ── SessionManager ────────────────────────────────────────────────────────────

class SessionManager:
    """
    Manages session lifecycle and the sessions.json metadata index.

    The vault (for entity storage) is a separate concern — SessionManager
    only tracks session metadata.
    """

    def __init__(self, config: DarmokConfig) -> None:
        self._config = config

    @property
    def _sessions_path(self) -> Path:
        return self._config.sessions_json_path

    # ── Public API ────────────────────────────────────────────────────────────

    def start(
        self,
        name: str,
        expiry_hours: int | None = None,
        expiry_type: str | None = None,
        tags: list[str] | None = None,
        context_docs: list[str] | None = None,
    ) -> SessionMeta:
        """
        Create a new session. Writes to sessions.json.

        F-13: if any context_docs paths are missing, warn and skip.
        """
        hours = expiry_hours if expiry_hours is not None else self._config.default_expiry_hours
        etype = expiry_type if expiry_type is not None else self._config.default_expiry_type

        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=hours)
        session_id = secrets.token_hex(16)[:6]

        # F-13: check context docs
        valid_docs: list[str] = []
        for doc_path in (context_docs or []):
            if not Path(doc_path).exists():
                print(
                    f"\n⚠ Context doc not found: {doc_path}\n"
                    f"\nThis document was expected but is missing. It will be skipped for this session."
                    f"\nOther context docs in the hierarchy are unaffected."
                    f"\n\nTo create it: touch {doc_path}"
                    f"\n\nTo suppress: remove the project from the folder hierarchy or recreate the file.\n",
                    file=sys.stderr,
                )
                logger.warning(
                    "context_doc path=%s status=missing session_id=%s",
                    doc_path, session_id,
                )
            else:
                valid_docs.append(doc_path)

        meta = SessionMeta(
            session_id=session_id,
            name=name,
            created_at=_format_iso(now),
            expires_at=_format_iso(expires),
            expiry_type=etype,
            tags=tags or [],
            open_questions=[],
            schema_version=SCHEMA_VERSION,
            context_docs=valid_docs,
        )

        sessions = self._load_sessions()
        sessions.append(meta.to_dict())
        self._save_sessions(sessions)
        return meta

    def resume(self, session_id: str) -> SessionMeta:
        """
        Resume an existing session.

        F-03: hard fail if session is hard-expired or not found.
        """
        sessions = self._load_sessions()
        for s in sessions:
            meta = SessionMeta.from_dict(s)
            if meta.session_id == session_id:
                if meta.ended:
                    raise SessionError(
                        f"✗ Session {session_id} has been ended and cannot be resumed.\n"
                        f"\nTo start a new session: darmok --session-start \"project-name\""
                    )
                if meta.is_expired() and meta.expiry_type == "hard":
                    expires_str = _format_display(meta.expires_at)
                    raise SessionExpiredError(
                        f"✗ Session {session_id} has expired and cannot be resumed.\n"
                        f"\nSession expired: {expires_str} ({meta.expiry_type.replace('hard', f'{self._config.default_expiry_hours} hours')} after creation)"
                        f"\nExpiry type: hard — entries have been overwritten.\n"
                        f"\nThe session metadata is still readable via: darmok --audit {session_id}"
                        f"\nTo start a new session: darmok --session-start \"project-name\""
                    )
                return meta
        raise SessionNotFoundError(
            f"✗ Session {session_id} not found.\n"
            f"\nTo list sessions: darmok --sessions"
        )

    def end(self, session_id: str) -> None:
        """Mark a session as ended in sessions.json."""
        sessions = self._load_sessions()
        for s in sessions:
            if s.get("session_id") == session_id:
                s["ended"] = True
                break
        self._save_sessions(sessions)

    def list_sessions(self) -> list[SessionMeta]:
        """Return all sessions (active, expired, ended)."""
        sessions = self._load_sessions()
        return [SessionMeta.from_dict(s) for s in sessions]

    def get(self, session_id: str) -> SessionMeta | None:
        """Return SessionMeta for session_id, or None if not found."""
        sessions = self._load_sessions()
        for s in sessions:
            if s.get("session_id") == session_id:
                return SessionMeta.from_dict(s)
        return None

    def update(self, meta: SessionMeta) -> None:
        """Write updated session metadata back to sessions.json."""
        sessions = self._load_sessions()
        for i, s in enumerate(sessions):
            if s.get("session_id") == meta.session_id:
                sessions[i] = meta.to_dict()
                break
        self._save_sessions(sessions)

    # ── I/O ───────────────────────────────────────────────────────────────────

    def _load_sessions(self) -> list[dict[str, Any]]:
        """
        Load sessions.json, handling F-11 (missing, corrupt, wrong permissions).

        Returns a list of raw session dicts.
        """
        path = self._sessions_path

        # F-11: permissions check (Unix/Mac only)
        if self._config.permission_check and path.exists():
            _check_permissions(path, "sessions.json")

        if not path.exists():
            # F-11: missing — recreate empty
            print(
                "\n⚠ sessions.json not found — recreating empty index.\n"
                "\nSession metadata (project names, tags, open questions) from prior sessions is not available."
                "\nVault entries are unaffected. To suppress: this warning is shown once per recreation.\n",
                file=sys.stderr,
            )
            logger.warning("sessions.json not found — recreated empty index")
            return []

        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError("Expected JSON array")
            return data
        except (json.JSONDecodeError, ValueError) as exc:
            # F-11: corrupt JSON — backup and recreate
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            backup = path.with_suffix(f".json.bak.{date_str}")
            shutil.copy2(str(path), str(backup))
            print(
                f"\n⚠ sessions.json is corrupted (invalid JSON) — recreating empty index.\n"
                f"\nA backup of the corrupted file has been saved: {backup}"
                f"\nSession metadata from prior sessions is not available. Vault entries are unaffected.\n",
                file=sys.stderr,
            )
            logger.warning("sessions.json corrupted — backed up to %s, recreated empty", backup)
            return []

    def _save_sessions(self, sessions: list[dict[str, Any]]) -> None:
        """Write sessions list to sessions.json with permissions 600."""
        path = self._sessions_path
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(sessions, indent=2, ensure_ascii=False)
        path.write_text(text, encoding="utf-8")
        if platform.system() != "Windows":
            path.chmod(0o600)


# ── Session errors ────────────────────────────────────────────────────────────

class SessionError(Exception):
    """Base class for session failures."""


class SessionExpiredError(SessionError):
    """F-03: session is hard-expired."""


class SessionNotFoundError(SessionError):
    """Session ID not found in sessions.json."""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_display(iso_str: str) -> str:
    try:
        dt = _parse_utc(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso_str


def _parse_utc(s: str) -> datetime:
    s = s.rstrip("Z")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
