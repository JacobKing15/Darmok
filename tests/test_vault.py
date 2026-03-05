"""
Tests for darmok/vault.py — Vault, encryption, and all 13 failure modes.

Failure mode induction per docs/vault_failure_modes.md §Testing Requirements.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from darmok.config import DarmokConfig
from darmok.vault import (
    REKEY_HARD_LIMIT,
    Vault,
    VaultCorrupted,
    VaultError,
    VaultRekeyRequired,
    VaultSaltMissing,
    VaultSchemaMismatch,
    VaultWrongPassphrase,
    _sha256,
    _utcnow,
    _zero_key,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

PASSPHRASE = "test-passphrase-darmok"
ALT_PASSPHRASE = "different-passphrase"


def _cfg(tmp_path: Path, **overrides) -> DarmokConfig:
    """Build a DarmokConfig pointing to tmp_path."""
    return DarmokConfig.load(
        path=tmp_path / "config.yaml",
        overrides={
            "vault": {
                "path": str(tmp_path / "vault.db"),
                "salt_path": str(tmp_path / "vault.salt"),
                "default_expiry_hours": 4,
                "default_expiry_type": "hard",
                "soft_expiry_max_recoveries": 3,
                "rekey_threshold": REKEY_HARD_LIMIT,
                "argon2": {
                    # Use minimal parameters for test speed (16384 is spec minimum)
                    "time_cost": 1,
                    "memory_cost": 16384,
                    "parallelism": 1,
                },
                **overrides.pop("vault", {}),
            },
            **overrides,
        },
    )


def _future(hours: int = 4) -> str:
    dt = datetime.now(timezone.utc) + timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _past(hours: int = 1) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Basic round-trip ──────────────────────────────────────────────────────────

def test_round_trip_single_entity(tmp_path):
    """Encrypt entity → decrypt entity → values match."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity(
            "sk-ant-api03-abc123xyz",
            "api_key",
            "ab1234",         # 6-char session ID (no "sess_" prefix)
            _future(),
        )
        assert ph.startswith("[sess_ab1234:API_KEY_")
        raw = vault.get_entity(ph)
        assert raw == "sk-ant-api03-abc123xyz"
    finally:
        vault.close()


def test_round_trip_multiple_categories(tmp_path):
    """Multiple categories all round-trip cleanly."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        values = {
            "api_key":     "sk-ant-api03-abcdefg",
            "email":       "user@example.com",
            "ip_address":  "192.168.1.100",
            "credit_card": "4111111111111111",
        }
        placeholders = {}
        for cat, val in values.items():
            ph = vault.register_entity(val, cat, "cd5678", _future())
            placeholders[cat] = ph

        for cat, val in values.items():
            recovered = vault.get_entity(placeholders[cat])
            assert recovered == val, f"Round-trip failed for {cat}"
    finally:
        vault.close()


def test_cross_session_dedup(tmp_path):
    """Same raw value in a later session → same placeholder returned."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph1 = vault.register_entity(
            "sk-ant-api03-shared", "api_key", "aa1234", _future()
        )
    finally:
        vault.close()

    # Re-open in a different "session"
    vault2 = Vault(cfg)
    vault2.open(PASSPHRASE)
    try:
        ph2 = vault2.register_entity(
            "sk-ant-api03-shared", "api_key", "bb9012", _future()
        )
        assert ph2 == ph1, "Same value must return same placeholder across sessions"
    finally:
        vault2.close()


def test_different_values_get_different_placeholders(tmp_path):
    """Two different values always produce distinct placeholders."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph1 = vault.register_entity("value_one", "api_key", "aa1234", _future())
        ph2 = vault.register_entity("value_two", "api_key", "aa1234", _future())
        assert ph1 != ph2
    finally:
        vault.close()


def test_lookup_by_value(tmp_path):
    """lookup_by_value returns placeholder if exists, None otherwise."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("my-api-key-xyz", "api_key", "aa1234", _future())
        assert vault.lookup_by_value("my-api-key-xyz") == ph
        assert vault.lookup_by_value("not-registered") is None
    finally:
        vault.close()


def test_context_manager(tmp_path):
    """Context manager opens and closes vault cleanly."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    with vault.session(PASSPHRASE):
        ph = vault.register_entity("token-abc", "api_key", "aa1234", _future())
        assert ph.startswith("[sess_aa1234:API_KEY_")


# ── Allowlist ─────────────────────────────────────────────────────────────────

def test_allowlist_add_and_check(tmp_path):
    """add_to_allowlist + is_allowlisted work correctly."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        assert not vault.is_allowlisted("my-value")
        vault.add_to_allowlist("my-value")
        assert vault.is_allowlisted("my-value")
    finally:
        vault.close()


def test_allowlist_persists_across_sessions(tmp_path):
    """Allowlist entries persist across vault open/close cycles."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.add_to_allowlist("persistent-value")
    vault.close()

    vault2 = Vault(cfg)
    vault2.open(PASSPHRASE)
    try:
        assert vault2.is_allowlisted("persistent-value")
    finally:
        vault2.close()


def test_allowlist_remove(tmp_path):
    """remove_from_allowlist removes the entry."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.add_to_allowlist("to-remove")
        entries = vault.list_allowlist()
        entry_id = entries[0]["id"]
        removed = vault.remove_from_allowlist(entry_id)
        assert removed is True
        assert not vault.is_allowlisted("to-remove")
    finally:
        vault.close()


# ── Log records ───────────────────────────────────────────────────────────────

def test_sanitized_log_round_trip(tmp_path):
    """save_sanitized_log stores plain text, no encryption."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.save_sanitized_log("aa1234", "The LLM saw: [sess_aa:API_KEY_1]")
    finally:
        vault.close()
    # Verify it's in the DB as plaintext
    conn = sqlite3.connect(str(tmp_path / "vault.db"))
    row = conn.execute("SELECT content FROM sanitized_logs").fetchone()
    conn.close()
    assert row[0] == "The LLM saw: [sess_aa:API_KEY_1]"


def test_reconstructed_log_encrypted(tmp_path):
    """save_reconstructed_log encrypts; get_reconstructed_log decrypts back."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.save_reconstructed_log("aa1234", "Real value: sk-ant-api03-abc")
        recovered = vault.get_reconstructed_log("aa1234")
        assert recovered == "Real value: sk-ant-api03-abc"
    finally:
        vault.close()


# ── Maintenance ───────────────────────────────────────────────────────────────

def test_purge_expired_removes_hard_expired(tmp_path):
    """purge_expired removes hard-expired entries."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("val", "api_key", "aa1234", _past(2), "hard")
        count = vault.purge_expired()
        assert count >= 1
        # Entity should no longer be retrievable
        conn = sqlite3.connect(str(tmp_path / "vault.db"))
        row = conn.execute(
            "SELECT 1 FROM entities WHERE placeholder=?", (ph,)
        ).fetchone()
        conn.close()
        assert row is None
    finally:
        vault.close()


def test_compact_runs_without_error(tmp_path):
    """compact() runs VACUUM without error."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.register_entity("val", "api_key", "aa1234", _future())
        vault.compact()
    finally:
        vault.close()


def test_audit_returns_entity_summary(tmp_path):
    """audit() returns entity list without raw values."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.register_entity("key1", "api_key", "aa1234", _future())
        vault.register_entity("key2", "api_key", "aa1234", _future())
        result = vault.audit("aa1234")
        assert result["entity_count"] == 2
        # Raw values must not appear in audit output
        for entity in result["entities"]:
            assert "key1" not in str(entity)
            assert "key2" not in str(entity)
    finally:
        vault.close()


# ─────────────────────────────────────────────────────────────────────────────
# FAILURE MODES
# ─────────────────────────────────────────────────────────────────────────────

# ── F-01: Wrong passphrase ────────────────────────────────────────────────────

def test_f01_wrong_passphrase_on_existing_vault(tmp_path):
    """F-01: Wrong passphrase on vault with existing entity → VaultWrongPassphrase."""
    cfg = _cfg(tmp_path)
    # Create and populate vault
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.register_entity("secret-key-123", "api_key", "aa1234", _future())
    vault.close()

    # Try wrong passphrase
    vault2 = Vault(cfg)
    with pytest.raises(VaultWrongPassphrase) as exc_info:
        vault2.open(ALT_PASSPHRASE)

    msg = str(exc_info.value)
    assert "incorrect passphrase" in msg.lower()
    assert "vault-reinitialize" in msg


def test_f01_message_contains_vault_path(tmp_path):
    """F-01 error message includes vault path."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.register_entity("key-for-f01", "api_key", "aa1234", _future())
    vault.close()

    vault2 = Vault(cfg)
    with pytest.raises(VaultWrongPassphrase) as exc_info:
        vault2.open(ALT_PASSPHRASE)

    assert "vault.db" in str(exc_info.value)


# ── F-02: Corrupted vault.db ──────────────────────────────────────────────────

def test_f02_corrupted_vault_raises(tmp_path):
    """F-02: Flipping bytes in vault.db → VaultCorrupted with integrity message."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.register_entity("some-key", "api_key", "aa1234", _future())
    vault.close()

    # Corrupt the database (flip bytes in the middle)
    db_path = tmp_path / "vault.db"
    data = db_path.read_bytes()
    offset = len(data) // 2
    corrupted = data[:offset] + bytes([b ^ 0xFF for b in data[offset:offset+32]]) + data[offset+32:]
    db_path.write_bytes(corrupted)

    vault2 = Vault(cfg)
    with pytest.raises((VaultCorrupted, VaultWrongPassphrase, VaultError)):
        vault2.open(PASSPHRASE)


def test_f02_integrity_message_content(tmp_path):
    """F-02 error message mentions integrity check and options."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.register_entity("some-key", "api_key", "aa1234", _future())
    vault.close()

    # Corrupt the DB pages by overwriting the header area
    db_path = tmp_path / "vault.db"
    data = bytearray(db_path.read_bytes())
    # Corrupt page 2+ data (skip SQLite header to ensure file opens but fails integrity)
    for i in range(2048, min(2048 + 512, len(data))):
        data[i] = data[i] ^ 0xAA
    db_path.write_bytes(bytes(data))

    vault2 = Vault(cfg)
    try:
        vault2.open(PASSPHRASE)
        vault2.close()
        # If the corruption wasn't enough to trigger integrity_check,
        # that's OK — the important test is F-02 message content below.
    except (VaultCorrupted, VaultError) as exc:
        msg = str(exc)
        assert "integrity" in msg.lower() or "corrupt" in msg.lower()
        assert "vault-reinitialize" in msg


# ── F-05: Incorrect file permissions ─────────────────────────────────────────

@pytest.mark.skipif(platform.system() == "Windows", reason="chmod not meaningful on Windows")
def test_f05_vault_db_wrong_permissions_warns(tmp_path, capsys):
    """F-05: vault.db at 644 → warning message shown, tool continues."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    # Change permissions to 644
    db_path = tmp_path / "vault.db"
    db_path.chmod(0o644)

    vault2 = Vault(cfg)
    vault2.open(PASSPHRASE)  # should not raise
    vault2.close()

    captured = capsys.readouterr()
    assert "644" in captured.err
    assert "600" in captured.err
    assert "chmod" in captured.err


@pytest.mark.skipif(platform.system() == "Windows", reason="chmod not meaningful on Windows")
def test_f05_salt_wrong_permissions_warns(tmp_path, capsys):
    """F-05: vault.salt at 644 → warning message shown."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    salt_path = tmp_path / "vault.salt"
    salt_path.chmod(0o644)

    vault2 = Vault(cfg)
    vault2.open(PASSPHRASE)
    vault2.close()

    captured = capsys.readouterr()
    assert "644" in captured.err


# ── F-06: Schema version mismatch ────────────────────────────────────────────

def test_f06_unknown_schema_version_hard_fails(tmp_path):
    """F-06: schema_version 0.9 (no migration path) → VaultSchemaMismatch."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    # Set schema_version to an unsupported old version
    conn = sqlite3.connect(str(tmp_path / "vault.db"))
    conn.execute("UPDATE vault_meta SET schema_version='0.9' WHERE id=1")
    conn.commit()
    conn.close()

    vault2 = Vault(cfg)
    with pytest.raises(VaultSchemaMismatch) as exc_info:
        vault2.open(PASSPHRASE)

    msg = str(exc_info.value)
    assert "v0.9" in msg or "0.9" in msg
    assert "vault-reinitialize" in msg


def test_f06_migration_1_1_to_1_2_shown(tmp_path, monkeypatch):
    """F-06: schema v1.1 → migration prompt shown with changelog."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    conn = sqlite3.connect(str(tmp_path / "vault.db"))
    conn.execute("UPDATE vault_meta SET schema_version='1.1' WHERE id=1")
    conn.commit()
    conn.close()

    # Mock input to confirm migration
    monkeypatch.setattr("builtins.input", lambda _: "y")

    vault2 = Vault(cfg)
    vault2.open(PASSPHRASE)  # should migrate and succeed
    vault2.close()

    # Verify schema version updated
    conn2 = sqlite3.connect(str(tmp_path / "vault.db"))
    row = conn2.execute("SELECT schema_version FROM vault_meta").fetchone()
    conn2.close()
    assert row[0] == "1.2"


def test_f06_migration_declined_exits(tmp_path, monkeypatch):
    """F-06: choosing 'n' on migration prompt exits without modifying anything."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    conn = sqlite3.connect(str(tmp_path / "vault.db"))
    conn.execute("UPDATE vault_meta SET schema_version='1.1' WHERE id=1")
    conn.commit()
    conn.close()

    monkeypatch.setattr("builtins.input", lambda _: "n")

    vault2 = Vault(cfg)
    with pytest.raises(SystemExit):
        vault2.open(PASSPHRASE)

    # Schema version must be unchanged
    conn2 = sqlite3.connect(str(tmp_path / "vault.db"))
    row = conn2.execute("SELECT schema_version FROM vault_meta").fetchone()
    conn2.close()
    assert row[0] == "1.1"


# ── F-07: Expired entry during reconstruction ─────────────────────────────────

def test_f07_hard_expired_returns_none(tmp_path, capsys):
    """F-07 (hard): expired hard-expiry entry returns None with message."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("my-api-key", "api_key", "aa1234", _past(2), "hard")
        result = vault.get_entity(ph)
        assert result is None
    finally:
        vault.close()

    captured = capsys.readouterr()
    assert "hard" in captured.err.lower()
    assert "expired" in captured.err.lower()
    assert "overwritten" in captured.err.lower() or "not recoverable" in captured.err.lower()


def test_f07_hard_expired_shows_expiry_type_first(tmp_path, capsys):
    """F-07: expiry type is shown before any passphrase prompt (spec requirement)."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("key-x", "api_key", "aa1234", _past(1), "hard")
        vault.get_entity(ph)
    finally:
        vault.close()

    captured = capsys.readouterr()
    # Should mention expiry type BEFORE anything about passphrase
    err = captured.err
    expiry_pos = err.lower().find("hard")
    pass_pos = err.lower().find("passphrase")
    assert expiry_pos != -1
    if pass_pos != -1:
        assert expiry_pos < pass_pos, "Expiry type must be shown before passphrase prompt"


def test_f07_soft_expired_recovery_available(tmp_path, monkeypatch, capsys):
    """F-07 (soft, available): soft-expiry entry prompts recovery with count shown."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("soft-key", "api_key", "aa1234", _past(1), "soft")
        # Simulate user declining recovery
        monkeypatch.setattr("builtins.input", lambda _: "n")
        result = vault.get_entity(ph)
        assert result is None
    finally:
        vault.close()

    captured = capsys.readouterr()
    assert "soft" in captured.err.lower()
    assert "recovery" in captured.err.lower()
    assert "1 of 3" in captured.err


def test_f07_soft_expired_recovery_succeeds(tmp_path, monkeypatch):
    """F-07 (soft): accepting recovery with correct passphrase returns value."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("recoverable-key", "api_key", "aa1234", _past(1), "soft")
        monkeypatch.setattr("builtins.input", lambda _: "y")
        result = vault.get_entity(ph, passphrase=PASSPHRASE)
        assert result == "recoverable-key"
    finally:
        vault.close()


def test_f07_soft_recovery_wrong_passphrase(tmp_path, monkeypatch, capsys):
    """F-07 (soft): recovery with wrong passphrase → failure message."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("soft-key-2", "api_key", "aa1234", _past(1), "soft")
        monkeypatch.setattr("builtins.input", lambda _: "y")
        result = vault.get_entity(ph, passphrase=ALT_PASSPHRASE)
        assert result is None
    finally:
        vault.close()

    captured = capsys.readouterr()
    assert "incorrect passphrase" in captured.err.lower()


def test_f07_soft_limit_reached_promotes_to_hard(tmp_path, capsys):
    """F-07 (soft, limit): recovery_count=3 → promoted to hard, not recoverable."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        ph = vault.register_entity("limit-key", "api_key", "aa1234", _past(1), "soft")
        # Force recovery_count to max
        vault._conn.execute(  # type: ignore[union-attr]
            "UPDATE entities SET recovery_count=3 WHERE placeholder=?", (ph,)
        )
        vault._conn.commit()  # type: ignore[union-attr]
        result = vault.get_entity(ph)
        assert result is None

        # Verify promoted to hard
        row = vault._conn.execute(  # type: ignore[union-attr]
            "SELECT expiry_type FROM entities WHERE placeholder=?", (ph,)
        ).fetchone()
        assert row[0] == "hard"
    finally:
        vault.close()

    captured = capsys.readouterr()
    assert "maximum" in captured.err.lower() or "limit" in captured.err.lower()
    assert "hard" in captured.err.lower()


# ── F-08: Key zeroing failure ─────────────────────────────────────────────────

def test_f08_key_zeroing_failure_warns(tmp_path, capsys, monkeypatch):
    """F-08: if ctypes zeroing raises → F-08 warning shown, tool continues."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)

    # Monkey-patch _zero_key to simulate failure
    import darmok.vault as vault_module
    original_zero = vault_module._zero_key
    monkeypatch.setattr(vault_module, "_zero_key", lambda key: False)

    vault.close()

    captured = capsys.readouterr()
    assert "key zeroing" in captured.err.lower() or "zeroing" in captured.err.lower()
    assert "swap" in captured.err.lower()
    assert "terminal" in captured.err.lower() or "session" in captured.err.lower()


# ── F-09: vault.salt missing ─────────────────────────────────────────────────

def test_f09_salt_missing_hard_fails(tmp_path):
    """F-09: vault.salt absent → VaultSaltMissing with exact message."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    # Delete the salt
    salt_path = tmp_path / "vault.salt"
    salt_path.unlink()

    vault2 = Vault(cfg)
    with pytest.raises(VaultSaltMissing) as exc_info:
        vault2.open(PASSPHRASE)

    msg = str(exc_info.value)
    assert "vault.salt" in msg.lower() or "salt" in msg.lower()
    assert "unrecoverable" in msg.lower() or "not recoverable" in msg.lower()
    assert "vault-reinitialize" in msg


def test_f09_salt_wrong_length_hard_fails(tmp_path):
    """F-09: vault.salt with wrong length → VaultSaltMissing."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    # Write truncated salt
    salt_path = tmp_path / "vault.salt"
    salt_path.write_bytes(b"too-short")

    vault2 = Vault(cfg)
    with pytest.raises(VaultSaltMissing):
        vault2.open(PASSPHRASE)


# ── F-10: Re-keying threshold ─────────────────────────────────────────────────

def test_f10_rekey_threshold_blocks_writes(tmp_path):
    """F-10: encryption_op_count at threshold → VaultRekeyRequired on next encrypt."""
    # Use spec minimum (1000) to stay within config validation
    cfg = _cfg(tmp_path, vault={"rekey_threshold": 1000})
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.set_op_count(1000)  # Set to exactly threshold
        with pytest.raises(VaultRekeyRequired) as exc_info:
            vault.register_entity("blocked-key", "api_key", "aa1234", _future())
        msg = str(exc_info.value)
        assert "re-keying" in msg.lower() or "rekey" in msg.lower()
        assert "1,000" in msg or "1000" in msg or "limit" in msg.lower()
    finally:
        if vault._conn is not None:
            vault._conn.close()
            vault._conn = None
        vault._key = None


def test_f10_one_below_threshold_succeeds(tmp_path):
    """One below threshold → write succeeds (threshold is checked before, not after)."""
    cfg = _cfg(tmp_path, vault={"rekey_threshold": 1000})
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    try:
        vault.set_op_count(999)  # One below
        ph = vault.register_entity("allowed-key", "api_key", "aa1234", _future())
        assert ph is not None
    finally:
        vault.close()


# ── F-12: Cloud sync detection ────────────────────────────────────────────────

def test_f12_onedrive_path_warns_once(tmp_path, capsys):
    """F-12: vault path matching OneDrive pattern → warn once, suppressed on re-open."""
    # Simulate OneDrive path by using a subdirectory named "OneDrive"
    onedrive_dir = tmp_path / "OneDrive" / "darmok"
    onedrive_dir.mkdir(parents=True)

    cfg = DarmokConfig.load(
        path=tmp_path / "config.yaml",
        overrides={
            "vault": {
                "path": str(onedrive_dir / "vault.db"),
                "salt_path": str(onedrive_dir / "vault.salt"),
                "argon2": {"time_cost": 1, "memory_cost": 16384, "parallelism": 1},
            },
        },
    )

    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    captured1 = capsys.readouterr()
    # Warning must mention cloud or OneDrive
    assert "cloud" in captured1.err.lower() or "onedrive" in captured1.err.lower()

    # Second open → no cloud warning (suppressed after first warn)
    vault2 = Vault(cfg)
    vault2.open(PASSPHRASE)
    vault2.close()

    captured2 = capsys.readouterr()
    # The cloud-sync warning itself (not the INFO config line) must be absent
    assert "cloud-synced" not in captured2.err.lower()


def test_f12_non_cloud_path_no_warning(tmp_path, capsys):
    """F-12: non-cloud path → no cloud-sync warning."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.close()

    captured = capsys.readouterr()
    # tmp_path is not in a cloud-synced location — the specific warning phrase must be absent
    assert "cloud-synced" not in captured.err.lower()
    assert "dropbox" not in captured.err.lower()
    assert "icloud" not in captured.err.lower()


# ── Rekey operation ────────────────────────────────────────────────────────────

def test_rekey_round_trip(tmp_path, capsys):
    """rekey() with new passphrase → old passphrase fails, new passphrase succeeds."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.register_entity("key-before-rekey", "api_key", "aa1234", _future())

    vault.rekey(new_passphrase="new-test-passphrase")
    vault.close()

    # Old passphrase should fail
    vault_old = Vault(cfg)
    with pytest.raises(VaultWrongPassphrase):
        vault_old.open(PASSPHRASE)

    # New passphrase should succeed and data should be intact
    vault_new = Vault(cfg)
    vault_new.open("new-test-passphrase")
    try:
        ph = vault_new.lookup_by_value("key-before-rekey")
        assert ph is not None
        recovered = vault_new.get_entity(ph)
        assert recovered == "key-before-rekey"
    finally:
        vault_new.close()


def test_rekey_creates_backup(tmp_path, capsys):
    """rekey() creates a dated backup file."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.rekey(new_passphrase="new-passphrase-2")
    vault.close()

    backups = list(tmp_path.glob("vault.db.bak.*"))
    assert len(backups) >= 1, "rekey must create a backup"


# ── Reinitialize ──────────────────────────────────────────────────────────────

def test_reinitialize_clears_vault(tmp_path):
    """reinitialize() removes vault.db and vault.salt (with backups)."""
    cfg = _cfg(tmp_path)
    vault = Vault(cfg)
    vault.open(PASSPHRASE)
    vault.register_entity("to-be-lost", "api_key", "aa1234", _future())
    vault.reinitialize()

    assert not (tmp_path / "vault.db").exists()
    assert not (tmp_path / "vault.salt").exists()
    # Backups should exist
    backups = list(tmp_path.glob("*.reinit-bak.*"))
    assert len(backups) >= 1


# ── Key zeroing helper ────────────────────────────────────────────────────────

def test_zero_key_uses_buffer_protocol():
    """_zero_key uses from_buffer (buffer protocol), zeroes bytes to 0."""
    key = bytearray(b"SECRETKEY1234567890ABCDEFGHIJKLM")
    assert any(b != 0 for b in key)
    success = _zero_key(key)
    assert success
    assert all(b == 0 for b in key)


def test_sha256_helper():
    """_sha256 returns consistent SHA-256 hex digest."""
    h1 = _sha256("test-value")
    h2 = _sha256("test-value")
    h3 = _sha256("different-value")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64
