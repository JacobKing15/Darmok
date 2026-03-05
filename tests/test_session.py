"""
Tests for darmok/session.py — SessionManager and SessionMeta.

Covers:
  - Session lifecycle (start, resume, end, list)
  - F-03: session resumption fails (hard expiry)
  - F-11: sessions.json missing / corrupt JSON / wrong permissions
  - F-13: context doc missing at session start
"""

from __future__ import annotations

import json
import platform
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from darmok.config import DarmokConfig
from darmok.session import (
    SessionExpiredError,
    SessionManager,
    SessionMeta,
    SessionNotFoundError,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _cfg(tmp_path: Path) -> DarmokConfig:
    return DarmokConfig.load(
        path=tmp_path / "config.yaml",
        overrides={
            "session": {
                "schema_version": "1.2",
                "sessions_json_path": str(tmp_path / "sessions.json"),
            },
            "vault": {
                "default_expiry_hours": 4,
                "default_expiry_type": "hard",
                "soft_expiry_max_recoveries": 3,
                "argon2": {"time_cost": 1, "memory_cost": 16384, "parallelism": 1},
            },
        },
    )


def _past_iso(hours: int = 5) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _future_iso(hours: int = 4) -> str:
    dt = datetime.now(timezone.utc) + timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── SessionMeta ───────────────────────────────────────────────────────────────


def test_session_meta_is_expired_past():
    """SessionMeta.is_expired() returns True when expires_at is in the past."""
    meta = SessionMeta(
        session_id="abc123",
        name="test",
        created_at="2026-01-01T00:00:00Z",
        expires_at=_past_iso(2),
        expiry_type="hard",
    )
    assert meta.is_expired() is True


def test_session_meta_is_expired_future():
    """SessionMeta.is_expired() returns False when expires_at is in the future."""
    meta = SessionMeta(
        session_id="abc123",
        name="test",
        created_at="2026-01-01T00:00:00Z",
        expires_at=_future_iso(4),
        expiry_type="hard",
    )
    assert meta.is_expired() is False


def test_session_meta_round_trip_dict():
    """SessionMeta serializes to dict and back without loss."""
    meta = SessionMeta(
        session_id="ab1234",
        name="my project",
        created_at="2026-02-28T10:00:00Z",
        expires_at="2026-02-28T14:00:00Z",
        expiry_type="soft",
        tags=["infra", "prod"],
        open_questions=["what about rate limits?"],
    )
    d = meta.to_dict()
    restored = SessionMeta.from_dict(d)
    assert restored.session_id == meta.session_id
    assert restored.name == meta.name
    assert restored.tags == meta.tags
    assert restored.open_questions == meta.open_questions
    assert restored.expiry_type == meta.expiry_type


def test_session_meta_from_dict_ignores_unknown_keys():
    """from_dict() silently ignores unknown keys (forward compatibility)."""
    d = {
        "session_id": "ab1234",
        "name": "test",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T04:00:00Z",
        "expiry_type": "hard",
        "future_field": "some_value",  # unknown
    }
    meta = SessionMeta.from_dict(d)
    assert meta.session_id == "ab1234"


# ── Session lifecycle ─────────────────────────────────────────────────────────


def test_start_session_creates_metadata(tmp_path):
    """start() creates a session and writes to sessions.json."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("my-project")

    assert len(meta.session_id) == 6
    assert meta.name == "my-project"
    assert meta.expiry_type == "hard"
    assert not meta.is_expired()

    sessions_path = tmp_path / "sessions.json"
    assert sessions_path.exists()
    data = json.loads(sessions_path.read_text())
    assert len(data) == 1
    assert data[0]["session_id"] == meta.session_id


def test_start_session_custom_expiry(tmp_path):
    """start() respects custom expiry hours and type."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("proj", expiry_hours=2, expiry_type="soft")

    assert meta.expiry_type == "soft"
    # expires_at should be ~2h in the future
    expires = datetime.fromisoformat(meta.expires_at.rstrip("Z")).replace(tzinfo=timezone.utc)
    diff = expires - datetime.now(timezone.utc)
    assert 1.5 * 3600 < diff.total_seconds() < 2.5 * 3600


def test_start_session_with_tags(tmp_path):
    """start() stores tags correctly."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("proj", tags=["infra", "staging"])
    assert meta.tags == ["infra", "staging"]


def test_list_sessions_returns_all(tmp_path):
    """list_sessions() returns all created sessions."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    sm.start("project-a")
    sm.start("project-b")
    sessions = sm.list_sessions()
    assert len(sessions) == 2
    names = {s.name for s in sessions}
    assert names == {"project-a", "project-b"}


def test_get_session_by_id(tmp_path):
    """get() returns the matching SessionMeta."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("find-me")
    found = sm.get(meta.session_id)
    assert found is not None
    assert found.name == "find-me"


def test_get_nonexistent_returns_none(tmp_path):
    """get() returns None for unknown session ID."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    assert sm.get("zzzzzz") is None


def test_resume_active_session(tmp_path):
    """resume() returns meta for a non-expired session."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("active-project")
    resumed = sm.resume(meta.session_id)
    assert resumed.session_id == meta.session_id
    assert resumed.name == "active-project"


def test_end_session_marks_ended(tmp_path):
    """end() marks session as ended in sessions.json."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("to-end")
    sm.end(meta.session_id)
    found = sm.get(meta.session_id)
    assert found is not None
    assert found.ended is True


def test_update_session_persists_changes(tmp_path):
    """update() writes modified SessionMeta back to sessions.json."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("to-update")
    meta.open_questions = ["Q1", "Q2"]
    sm.update(meta)

    reloaded = sm.get(meta.session_id)
    assert reloaded is not None
    assert reloaded.open_questions == ["Q1", "Q2"]


# ── F-03: Session resumption fails ───────────────────────────────────────────


def test_f03_hard_expired_session_raises(tmp_path):
    """F-03: resuming a hard-expired session → SessionExpiredError with message."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("expired-project")
    # Force expiry by backdating expires_at
    meta.expires_at = _past_iso(2)
    meta.expiry_type = "hard"
    sm.update(meta)

    with pytest.raises(SessionExpiredError) as exc_info:
        sm.resume(meta.session_id)

    msg = str(exc_info.value)
    assert meta.session_id in msg
    assert "expired" in msg.lower()
    assert "hard" in msg.lower()
    assert "darmok --audit" in msg


def test_f03_hard_expiry_message_format(tmp_path):
    """F-03 message includes session ID, expiry info, and recovery suggestion."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("proj-x")
    meta.expires_at = _past_iso(1)
    meta.expiry_type = "hard"
    sm.update(meta)

    with pytest.raises(SessionExpiredError) as exc_info:
        sm.resume(meta.session_id)

    msg = str(exc_info.value)
    assert "darmok --session-start" in msg


def test_f03_ended_session_raises(tmp_path):
    """Resuming an ended session raises SessionError."""
    from darmok.session import SessionError
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("ended-project")
    sm.end(meta.session_id)

    with pytest.raises(SessionError):
        sm.resume(meta.session_id)


def test_f03_nonexistent_session_raises(tmp_path):
    """Resuming unknown session ID → SessionNotFoundError."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    with pytest.raises(SessionNotFoundError):
        sm.resume("zzzzzz")


# ── F-11: sessions.json missing / corrupt / permissions ──────────────────────


def test_f11_missing_sessions_json_warns_and_recreates(tmp_path, capsys):
    """F-11: missing sessions.json → warn + recreate empty + return []."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    sessions_path = tmp_path / "sessions.json"

    # File doesn't exist yet — first list_sessions triggers F-11
    sessions = sm.list_sessions()
    assert sessions == []

    captured = capsys.readouterr()
    assert "sessions.json" in captured.err.lower()
    assert "recreating" in captured.err.lower() or "not found" in captured.err.lower()


def test_f11_missing_sessions_json_then_start_works(tmp_path, capsys):
    """After F-11 warn, start() still works correctly."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    # Trigger missing-file path
    sm.list_sessions()
    capsys.readouterr()  # clear

    # start() should work fine afterward
    meta = sm.start("after-missing")
    assert meta.session_id is not None

    sessions = sm.list_sessions()
    assert len(sessions) == 1


def test_f11_corrupt_json_warns_and_recreates(tmp_path, capsys):
    """F-11: corrupt sessions.json → warn + backup + recreate empty."""
    cfg = _cfg(tmp_path)
    sessions_path = tmp_path / "sessions.json"
    sessions_path.write_text("this is not valid json {{{", encoding="utf-8")

    sm = SessionManager(cfg)
    sessions = sm.list_sessions()
    assert sessions == []

    captured = capsys.readouterr()
    assert "corrupt" in captured.err.lower() or "invalid json" in captured.err.lower()
    assert "backup" in captured.err.lower() or "bak" in captured.err.lower()

    # Backup should exist
    backups = list(tmp_path.glob("sessions.json.bak.*"))
    assert len(backups) >= 1


def test_f11_corrupt_json_backup_contains_original(tmp_path):
    """F-11: corrupted sessions.json is backed up before being discarded."""
    cfg = _cfg(tmp_path)
    sessions_path = tmp_path / "sessions.json"
    original_content = "CORRUPT CONTENT {{{"
    sessions_path.write_text(original_content, encoding="utf-8")

    sm = SessionManager(cfg)
    sm.list_sessions()  # triggers F-11

    backups = list(tmp_path.glob("sessions.json.bak.*"))
    assert len(backups) >= 1
    assert backups[0].read_text(encoding="utf-8") == original_content


@pytest.mark.skipif(platform.system() == "Windows", reason="chmod not meaningful on Windows")
def test_f11_wrong_permissions_warns(tmp_path, capsys):
    """F-11: sessions.json with permissions 644 → permission warning shown."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    sm.start("a-project")  # creates sessions.json at 600

    sessions_path = tmp_path / "sessions.json"
    sessions_path.chmod(0o644)

    sm2 = SessionManager(cfg)
    sm2.list_sessions()  # triggers permissions check

    captured = capsys.readouterr()
    assert "644" in captured.err
    assert "600" in captured.err


# ── F-13: Context doc missing at session start ────────────────────────────────


def test_f13_missing_context_doc_warns_and_skips(tmp_path, capsys):
    """F-13: missing context doc → warn + skip + session starts."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    missing_doc = str(tmp_path / "missing_context.md")

    meta = sm.start("proj", context_docs=[missing_doc])

    # Session was created despite missing doc
    assert meta.session_id is not None

    captured = capsys.readouterr()
    assert "context doc" in captured.err.lower() or "missing" in captured.err.lower()
    assert "missing_context.md" in captured.err

    # Missing doc not in valid_docs
    assert missing_doc not in meta.context_docs


def test_f13_existing_context_doc_not_warned(tmp_path, capsys):
    """F-13: existing context doc → no warning, included in session."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)

    existing_doc = tmp_path / "context.md"
    existing_doc.write_text("# Context", encoding="utf-8")

    meta = sm.start("proj", context_docs=[str(existing_doc)])

    captured = capsys.readouterr()
    # No F-13 warning for the existing doc
    assert "context doc not found" not in captured.err.lower()

    # Doc IS in the session
    assert str(existing_doc) in meta.context_docs


def test_f13_mixed_docs_skips_only_missing(tmp_path, capsys):
    """F-13: mix of existing and missing docs → warn only for missing."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)

    existing = tmp_path / "real.md"
    existing.write_text("content", encoding="utf-8")
    missing = str(tmp_path / "ghost.md")

    meta = sm.start("proj", context_docs=[str(existing), missing])

    assert str(existing) in meta.context_docs
    assert missing not in meta.context_docs

    captured = capsys.readouterr()
    assert "ghost.md" in captured.err
    assert "real.md" not in captured.err


# ── Session ID generation ─────────────────────────────────────────────────────


def test_session_ids_are_unique(tmp_path):
    """Each session gets a unique session ID."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    ids = {sm.start(f"proj-{i}").session_id for i in range(10)}
    assert len(ids) == 10, "Session IDs must be unique"


def test_session_id_is_6_hex_chars(tmp_path):
    """Session ID is exactly 6 lowercase hex characters."""
    cfg = _cfg(tmp_path)
    sm = SessionManager(cfg)
    meta = sm.start("test")
    sid = meta.session_id
    assert len(sid) == 6
    assert all(c in "0123456789abcdef" for c in sid)


# ── Registry integration (Phase 2 dedup) ─────────────────────────────────────


def test_registry_vault_cross_session_dedup(tmp_path):
    """
    Phase 2 registry with vault: same raw value across two sessions
    returns the same placeholder (cross-session deduplication).
    """
    from darmok.vault import Vault
    from darmok.registry import EntityRegistry

    cfg = DarmokConfig.load(
        path=tmp_path / "config.yaml",
        overrides={
            "vault": {
                "path": str(tmp_path / "vault.db"),
                "salt_path": str(tmp_path / "vault.salt"),
                "argon2": {"time_cost": 1, "memory_cost": 16384, "parallelism": 1},
            },
        },
    )
    passphrase = "test-dedup-passphrase"
    future = _future_iso(4)

    # Session 1
    vault1 = Vault(cfg)
    vault1.open(passphrase)
    reg1 = EntityRegistry(session_id="aa1111", vault=vault1, expires_at=future)
    ph1 = reg1.register("shared-api-key", "api_key")
    vault1.close()

    # Session 2 — different session_id, same raw value
    vault2 = Vault(cfg)
    vault2.open(passphrase)
    reg2 = EntityRegistry(session_id="bb2222", vault=vault2, expires_at=future)
    ph2 = reg2.register("shared-api-key", "api_key")
    vault2.close()

    assert ph1 == ph2, "Same raw value must produce same placeholder across sessions"


def test_registry_without_vault_is_in_memory(tmp_path):
    """Phase 1 registry (no vault) works in-memory as before."""
    from darmok.registry import EntityRegistry
    reg = EntityRegistry(session_id="cc3333")
    ph1 = reg.register("value-a", "api_key")
    ph2 = reg.register("value-a", "api_key")  # same value → same placeholder
    ph3 = reg.register("value-b", "api_key")  # different → different
    assert ph1 == ph2
    assert ph1 != ph3
    assert ph1.startswith("[sess_cc3333:API_KEY_")
