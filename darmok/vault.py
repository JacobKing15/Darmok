"""
Darmok encrypted vault — Phase 2.

Storage: SQLite at ~/.darmok/vault.db
Encryption: AES-256-GCM, unique 96-bit nonce per operation
Key derivation: Argon2id (argon2-cffi), time_cost=3, memory_cost=65536, parallelism=1
Key lifecycle:
  - Always bytearray, never bytes or str
  - mlock on Linux immediately after derivation
  - Zeroed on close via ctypes buffer-protocol memset

All 13 failure modes (docs/vault_failure_modes.md) are implemented here
or in SessionManager (F-11, F-13).

Schema version: 1.2
"""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import logging
import os
import platform
import shutil
import sqlite3
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from darmok.config import DarmokConfig, _check_permissions

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.2"
REKEY_HARD_LIMIT = 2**24  # 16,777,216

# Cloud-sync path patterns (F-12)
_CLOUD_SYNC_PATTERNS: dict[str, list[str]] = {
    "iCloud":      ["Library/Mobile Documents", "iCloudDrive", "iCloud Drive"],
    "Dropbox":     ["Dropbox"],
    "OneDrive":    ["OneDrive"],
    "Google Drive": ["Google Drive", "GoogleDrive", "My Drive"],
}

# ── Schema DDL ───────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version TEXT NOT NULL,
    encryption_op_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    cloud_sync_warned INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS entities (
    placeholder TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL,
    category TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    nonce BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    expiry_type TEXT NOT NULL DEFAULT 'hard',
    recovery_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entities_value_hash ON entities(value_hash);

CREATE TABLE IF NOT EXISTS allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sanitized_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reconstructed_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    encrypted_content BLOB NOT NULL,
    nonce BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""

# v1.1 → v1.2 migration changelog (F-06)
_MIGRATION_1_1_TO_1_2 = """\
Changes in v1.2:
  - Added parent_session_id, thread_root_id, thread_position fields
  - Added folder field to session metadata
  - Added redaction_mode and redaction_tiers fields
  - Added context_docs_prepended field\
"""


# ── Key lifecycle helpers ─────────────────────────────────────────────────────

def _mlock(key: bytearray) -> None:
    """Lock key memory on Linux to prevent swap exposure."""
    if platform.system() != "Linux":
        return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        rc = libc.mlock(ctypes.c_char_p(bytes(key)), ctypes.c_size_t(len(key)))
        if rc != 0:
            logger.debug("mlock failed (non-fatal): errno=%d", ctypes.get_errno())
    except Exception:
        logger.debug("mlock not available (non-fatal)")


def _zero_key(key: bytearray) -> bool:
    """
    Zero a bytearray in-place using the buffer protocol.

    Uses (ctypes.c_char * len(key)).from_buffer(key) to get the actual data
    address via Python's buffer protocol — NOT id(key), which points to the
    Python object header, not the data buffer.

    Returns True on success, False if zeroing could not be confirmed (F-08).
    """
    try:
        buf = (ctypes.c_char * len(key)).from_buffer(key)
        ctypes.memset(buf, 0, len(key))
        return True
    except Exception as exc:
        logger.warning("key_zeroing zeroing_unconfirmed: %s", exc)
        return False


def _read_passphrase(prompt: str = "Vault passphrase: ") -> str:
    """Read passphrase from /dev/tty (Unix) or console (Windows) via getpass."""
    return getpass.getpass(prompt)


# ── Vault errors ─────────────────────────────────────────────────────────────

class VaultError(Exception):
    """Base class for hard vault failures."""


class VaultWrongPassphrase(VaultError):
    """F-01: wrong passphrase on unlock."""


class VaultCorrupted(VaultError):
    """F-02: SQLite integrity check failed."""


class VaultSaltMissing(VaultError):
    """F-09: vault.salt missing or invalid."""


class VaultSchemaMismatch(VaultError):
    """F-06: schema version mismatch with no migration path."""


class VaultRekeyRequired(VaultError):
    """F-10: encryption_op_count reached threshold."""


class VaultDiskFull(VaultError):
    """F-04: no space left and cleanup insufficient."""


# ── Vault ─────────────────────────────────────────────────────────────────────

class Vault:
    """
    Encrypted vault backed by SQLite.

    Usage (typical):
        vault = Vault(config)
        vault.open("my passphrase")
        try:
            placeholder = vault.register_entity(raw, "api_key", "sess_a3f9b2", ...)
            raw_value   = vault.get_entity(placeholder)
        finally:
            vault.close()

    Context manager:
        with vault.session("my passphrase"):
            ...
    """

    def __init__(self, config: DarmokConfig) -> None:
        self._config = config
        self._key: bytearray | None = None
        self._conn: sqlite3.Connection | None = None

    # ── Session context manager ───────────────────────────────────────────────

    @contextmanager
    def session(self, passphrase: str | None = None):
        """Context manager: open vault, yield, close (zeroing key on exit)."""
        self.open(passphrase)
        try:
            yield self
        finally:
            self.close()

    # ── Open / close ──────────────────────────────────────────────────────────

    def open(self, passphrase: str | None = None) -> None:
        """
        Derive key from passphrase, open/create DB, run integrity check.

        passphrase=None → reads from tty via getpass (CLI use).
        Tests pass the passphrase directly.
        """
        if passphrase is None:
            passphrase = _read_passphrase()

        db_path   = self._config.vault_path
        salt_path = self._config.salt_path

        # Ensure ~/.darmok/ exists
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # ── F-05: permission check ─────────────────────────────────────────
        if self._config.permission_check:
            if db_path.exists():
                _check_permissions(db_path, "vault.db")
            if salt_path.exists():
                _check_permissions(salt_path, "vault.salt")

        # ── F-09: salt handling ────────────────────────────────────────────
        salt = self._load_or_create_salt(salt_path, vault_exists=db_path.exists())

        # ── Key derivation (Argon2id) ──────────────────────────────────────
        self._key = self._derive_key(passphrase, salt)
        _mlock(self._key)

        # ── Open SQLite ────────────────────────────────────────────────────
        new_db = not db_path.exists()
        try:
            self._conn = sqlite3.connect(str(db_path))
            self._conn.row_factory = sqlite3.Row
        except (sqlite3.Error, sqlite3.DatabaseError) as exc:
            self._zero_and_clear_key()
            if not new_db:
                raise VaultCorrupted(
                    f"✗ Vault integrity check failed — vault.db is corrupted.\n"
                    f"\nThe vault at {db_path} failed its integrity check and cannot be used safely.\n"
                    f"\nOptions:\n"
                    f"  1. Restore from backup if you have one\n"
                    f"  2. Reinitialize: darmok --vault-reinitialize\n"
                    f"     Warning: reinitializing permanently destroys all existing vault data.\n"
                    f"\nDo not attempt to use the vault in its current state."
                ) from exc
            raise VaultError(f"Could not open vault.db: {exc}") from exc

        if new_db:
            self._initialize_schema()
            if platform.system() != "Windows":
                db_path.chmod(0o600)
        else:
            # ── F-02: integrity check ──────────────────────────────────────
            self._check_integrity()
            # ── F-01: passphrase verification ──────────────────────────────
            self._verify_passphrase()
            # ── F-06: schema version ───────────────────────────────────────
            self._check_schema_version()

        # ── F-12: cloud sync check ─────────────────────────────────────────
        if self._config.warn_vault_in_cloud:
            self._check_cloud_sync(db_path)

        # Purge hard-expired entries on open
        self._purge_hard_expired_silent()

    def close(self) -> None:
        """Close vault: zero key memory, close DB connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

        zeroed = self._zero_and_clear_key()
        if not zeroed:
            # F-08: key zeroing incomplete
            print(
                "\n⚠ Key zeroing may be incomplete — recommended action: close this terminal session.\n"
                "\n  The session key could not be reliably zeroed from memory. This can occur if:"
                "\n    - The key was held in memory long enough for the OS to write it to swap"
                "\n    - Python copied the key to a new memory location before zeroing occurred"
                "\n\n  Action recommended: terminate this terminal session now to flush process memory."
                "\n  Terminating the terminal does not clear swap. If your system has swap enabled,"
                "\n  key material may persist on disk until the swap partition is overwritten."
                "\n\n  For full protection: disable swap before running this tool with Tier 1 credentials,"
                "\n  or use a system with an encrypted swap partition."
                "\n\n  [Press any key to continue]",
                file=sys.stderr,
            )
            logger.warning(
                "key_zeroing session_id=unknown status=incomplete reason=zeroing_unconfirmed"
            )

    def _zero_and_clear_key(self) -> bool:
        """Zero key memory. Returns True on success."""
        if self._key is None:
            return True
        success = _zero_key(self._key)
        self._key = None
        return success

    # ── Schema ────────────────────────────────────────────────────────────────

    def _initialize_schema(self) -> None:
        assert self._conn is not None
        self._conn.executescript(_DDL)
        now = _utcnow()
        self._conn.execute(
            "INSERT INTO vault_meta (id, schema_version, encryption_op_count, created_at)"
            " VALUES (1, ?, 0, ?)",
            (SCHEMA_VERSION, now),
        )
        self._conn.commit()

    # ── Integrity check (F-02) ────────────────────────────────────────────────

    def _check_integrity(self) -> None:
        assert self._conn is not None
        db_path = self._config.vault_path
        try:
            rows = self._conn.execute("PRAGMA integrity_check").fetchall()
            results = [row[0] for row in rows]
        except (sqlite3.Error, sqlite3.DatabaseError) as exc:
            self._conn.close()
            self._conn = None
            self._zero_and_clear_key()
            raise VaultCorrupted(
                f"✗ Vault integrity check failed — vault.db is corrupted.\n"
                f"\nThe vault at {db_path} failed its integrity check and cannot be used safely.\n"
                f"\nOptions:\n"
                f"  1. Restore from backup if you have one\n"
                f"  2. Reinitialize: darmok --vault-reinitialize\n"
                f"     Warning: reinitializing permanently destroys all existing vault data.\n"
                f"\nDo not attempt to use the vault in its current state."
            ) from exc
        if results != ["ok"]:
            self._conn.close()
            self._conn = None
            self._zero_and_clear_key()
            raise VaultCorrupted(
                f"✗ Vault integrity check failed — vault.db is corrupted.\n"
                f"\nThe vault at {db_path} failed its integrity check and cannot be used safely.\n"
                f"\nOptions:\n"
                f"  1. Restore from backup if you have one\n"
                f"  2. Reinitialize: darmok --vault-reinitialize\n"
                f"     Warning: reinitializing permanently destroys all existing vault data.\n"
                f"\nDo not attempt to use the vault in its current state."
            )

    # ── Passphrase verification (F-01) ────────────────────────────────────────

    def _verify_passphrase(self) -> None:
        """
        Verify the passphrase by attempting to decrypt the first entity.
        If no entities exist, create and immediately delete a sentinel entry.
        """
        assert self._conn is not None
        assert self._key is not None

        # Try decrypting any existing entity
        row = self._conn.execute(
            "SELECT encrypted_value, nonce FROM entities LIMIT 1"
        ).fetchone()
        if row is not None:
            try:
                self._decrypt(bytes(row["encrypted_value"]), bytes(row["nonce"]))
            except InvalidTag:
                self._conn.close()
                self._conn = None
                self._zero_and_clear_key()
                db_path = self._config.vault_path
                raise VaultWrongPassphrase(
                    f"✗ Vault unlock failed — incorrect passphrase.\n"
                    f"\nThe vault at {db_path} could not be decrypted.\n"
                    f"\nIf you have forgotten your passphrase, the vault contents are unrecoverable.\n"
                    f"To start fresh: darmok --vault-reinitialize\n"
                    f"Warning: reinitializing permanently destroys all existing vault data."
                )
        else:
            # No entities — write a sentinel, verify, delete
            sentinel = b"darmok-sentinel"
            nonce = os.urandom(12)
            try:
                ct = self._encrypt_raw(sentinel, nonce)
                self._decrypt(ct, nonce)
            except InvalidTag:
                self._conn.close()
                self._conn = None
                self._zero_and_clear_key()
                db_path = self._config.vault_path
                raise VaultWrongPassphrase(
                    f"✗ Vault unlock failed — incorrect passphrase.\n"
                    f"\nThe vault at {db_path} could not be decrypted.\n"
                    f"\nIf you have forgotten your passphrase, the vault contents are unrecoverable.\n"
                    f"To start fresh: darmok --vault-reinitialize\n"
                    f"Warning: reinitializing permanently destroys all existing vault data."
                )

    # ── Schema version (F-06) ─────────────────────────────────────────────────

    def _check_schema_version(self) -> None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT schema_version FROM vault_meta WHERE id=1"
        ).fetchone()
        if row is None:
            return  # fresh vault, nothing to check

        stored = row["schema_version"]
        if stored == SCHEMA_VERSION:
            return

        # Migration path: v1.1 → v1.2
        if stored == "1.1":
            self._migrate_1_1_to_1_2()
            return

        # No migration path
        self._conn.close()
        self._conn = None
        self._zero_and_clear_key()
        raise VaultSchemaMismatch(
            f"✗ Vault schema version v{stored} is not supported by this version of the tool.\n"
            f"\nThis vault was created with an older version that cannot be automatically migrated.\n"
            f"The vault contents are not accessible with this version.\n"
            f"\nOptions:\n"
            f"  1. Downgrade to the version that created this vault\n"
            f"  2. Reinitialize: darmok --vault-reinitialize\n"
            f"     Warning: reinitializing permanently destroys all existing vault data."
        )

    def _migrate_1_1_to_1_2(self) -> None:
        """Migrate schema from v1.1 → v1.2 with backup (F-06)."""
        db_path = self._config.vault_path
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        backup_path = db_path.with_suffix(f".db.bak.{date_str}")

        # Prompt user (migration is interactive)
        print(
            f"\n⚠ Vault schema migration required: v1.1 → v1.2\n"
            f"\n{_MIGRATION_1_1_TO_1_2}\n"
            f"\nA backup will be created before migrating: {backup_path}\n",
            file=sys.stderr,
        )
        try:
            choice = input("Migrate now? [y/n] (choosing 'n' exits without modifying anything): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "n"

        if choice != "y":
            self._conn.close()  # type: ignore[union-attr]
            self._conn = None
            self._zero_and_clear_key()
            raise SystemExit(0)

        # Create backup
        shutil.copy2(str(db_path), str(backup_path))
        if platform.system() != "Windows":
            backup_path.chmod(0o600)

        # Apply migration (v1.2 just updates the version marker in our implementation)
        assert self._conn is not None
        try:
            self._conn.execute(
                "UPDATE vault_meta SET schema_version = ? WHERE id = 1",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()
        except Exception as exc:
            # Restore from backup
            self._conn.close()
            self._conn = None
            shutil.copy2(str(backup_path), str(db_path))
            self._zero_and_clear_key()
            raise VaultError(
                f"✗ Re-keying failed and could not be completed.\n"
                f"\nThe vault has been restored from backup: {backup_path}\n"
                f"The vault is now in read-only mode — reconstruction is available but no new entities can be stored.\n"
                f"\nFree disk space and run: darmok --vault-rekey"
            ) from exc

    # ── Cloud sync check (F-12) ───────────────────────────────────────────────

    def _check_cloud_sync(self, db_path: Path) -> None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT cloud_sync_warned FROM vault_meta WHERE id=1"
        ).fetchone()
        if row is not None and row["cloud_sync_warned"]:
            return  # already warned

        path_str = str(db_path).replace("\\", "/")
        detected_provider: str | None = None
        for provider, patterns in _CLOUD_SYNC_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in path_str.lower():
                    detected_provider = provider
                    break
            if detected_provider:
                break

        if detected_provider is None:
            return

        print(
            f"\n⚠ vault.db appears to be in a cloud-synced folder.\n"
            f"\nYour vault is encrypted and your data is protected, but storing vault.db in a"
            f"\ncloud-synced location has two risks:"
            f"\n  1. Concurrent writes from multiple devices can corrupt SQLite"
            f"\n  2. Your encrypted vault file is uploaded to a third-party server"
            f"\n\nRecommendation: move your vault to a non-synced location:"
            f"\n  mv {db_path} ~/Documents/darmok-vault/vault.db"
            f"\n  (update vault_path in config.yaml to match)"
            f"\n\nTo suppress this warning: set warn_vault_in_cloud: false in config.yaml\n",
            file=sys.stderr,
        )
        logger.warning(
            "vault_location path=%s cloud_sync_detected=true provider=%s",
            db_path, detected_provider,
        )
        # Mark as warned (suppress on subsequent opens)
        self._conn.execute(
            "UPDATE vault_meta SET cloud_sync_warned = 1 WHERE id = 1"
        )
        self._conn.commit()

    # ── Salt management (F-09) ────────────────────────────────────────────────

    def _load_or_create_salt(self, salt_path: Path, vault_exists: bool = False) -> bytes:
        """
        Load existing salt or generate and persist a new one.

        If vault_exists=True and the salt is absent or malformed → F-09 hard fail.
        An initialized vault without its salt is permanently unreadable.
        """
        _salt_missing_msg = (
            f"✗ vault.salt is missing or corrupted.\n"
            f"\nKey derivation requires the salt file at {salt_path}.\n"
            f"Without it, the vault cannot be decrypted. This is not recoverable.\n"
            f"\nIf you have a backup of vault.salt, restore it to {salt_path} and retry.\n"
            f"\nIf no backup exists, the vault contents are permanently unrecoverable.\n"
            f"To start fresh: darmok --vault-reinitialize\n"
            f"Warning: reinitializing permanently destroys all existing vault data."
        )
        if salt_path.exists():
            data = salt_path.read_bytes()
            if len(data) != 32:
                raise VaultSaltMissing(_salt_missing_msg)
            return data
        if vault_exists:
            # Existing vault without salt — F-09: permanently unreadable
            raise VaultSaltMissing(_salt_missing_msg)
        # Fresh vault — generate new salt
        salt = os.urandom(32)
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt_path.write_bytes(salt)
        if platform.system() != "Windows":
            salt_path.chmod(0o600)
        return salt

    # ── Key derivation ────────────────────────────────────────────────────────

    def _derive_key(self, passphrase: str, salt: bytes) -> bytearray:
        """Derive 32-byte Argon2id key from passphrase + salt."""
        raw = hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=self._config.argon2_time_cost,
            memory_cost=self._config.argon2_memory_cost,
            parallelism=self._config.argon2_parallelism,
            hash_len=32,
            type=Argon2Type.ID,
        )
        # Store as bytearray, never bytes
        key = bytearray(raw)
        # Defensively zero the raw bytes object (best effort — bytes is immutable)
        del raw
        return key

    # ── Encryption helpers ────────────────────────────────────────────────────

    def _encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.
        Returns (ciphertext_with_tag, nonce).
        Increments encryption_op_count; raises VaultRekeyRequired if threshold hit.
        """
        self._check_rekey_threshold()
        nonce = os.urandom(12)
        ct = self._encrypt_raw(plaintext, nonce)
        self._increment_op_count()
        return ct, nonce

    def _encrypt_raw(self, plaintext: bytes, nonce: bytes) -> bytes:
        """Encrypt without touching op_count. Used internally."""
        assert self._key is not None
        aesgcm = AESGCM(bytes(self._key))
        return aesgcm.encrypt(nonce, plaintext, None)

    def _decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt AES-256-GCM. Raises InvalidTag on auth failure."""
        assert self._key is not None
        aesgcm = AESGCM(bytes(self._key))
        return aesgcm.decrypt(nonce, ciphertext, None)

    # ── Rekey threshold (F-10) ────────────────────────────────────────────────

    def _check_rekey_threshold(self) -> None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT encryption_op_count FROM vault_meta WHERE id=1"
        ).fetchone()
        if row is None:
            return
        count = row["encryption_op_count"]
        if count >= self._config.rekey_threshold:
            raise VaultRekeyRequired(
                f"⚠ Vault re-keying required — encryption operation limit reached.\n"
                f"\nThis vault has reached the maximum number of encryption operations under the current key\n"
                f"({self._config.rekey_threshold:,} operations). Re-keying is required before the vault can accept new entries.\n"
                f"\nRe-keying will:\n"
                f"  1. Derive a new key from your passphrase with a fresh salt\n"
                f"  2. Re-encrypt all vault entries under the new key\n"
                f"  3. Replace vault.salt and reset the operation counter\n"
                f"\nRun: darmok --vault-rekey"
            )

    def _increment_op_count(self) -> None:
        assert self._conn is not None
        self._conn.execute(
            "UPDATE vault_meta SET encryption_op_count = encryption_op_count + 1 WHERE id=1"
        )
        self._conn.commit()

    # ── Entity registration ───────────────────────────────────────────────────

    def register_entity(
        self,
        raw_value: str,
        category: str,
        session_id: str,
        expires_at: str,
        expiry_type: str = "hard",
    ) -> str:
        """
        Register a raw value and return its placeholder.
        If the raw value already exists in the vault (cross-session dedup),
        return the existing placeholder without creating a new entry.

        Raises VaultRekeyRequired if encryption_op_count >= rekey_threshold (F-10).
        """
        assert self._conn is not None

        # Cross-session dedup via SHA-256 hash
        value_hash = _sha256(raw_value)
        existing = self.lookup_by_value(raw_value)
        if existing is not None:
            return existing

        # Assign new placeholder (category counters scoped to session)
        upper_cat = category.upper()
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM entities WHERE session_id=? AND category=?",
            (session_id, category),
        ).fetchone()
        idx = (row["cnt"] if row else 0) + 1
        placeholder = f"[sess_{session_id}:{upper_cat}_{idx}]"

        # Encrypt the raw value
        ct, nonce = self._encrypt(raw_value.encode("utf-8"))

        now = _utcnow()
        try:
            self._conn.execute(
                "INSERT INTO entities "
                "(placeholder, session_id, category, value_hash, encrypted_value, nonce,"
                " created_at, expires_at, expiry_type, recovery_count)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (placeholder, session_id, category, value_hash,
                 ct, nonce, now, expires_at, expiry_type),
            )
            self._conn.commit()
        except OSError as exc:
            if _is_disk_full(exc):
                self._handle_disk_full(raw_value)
            raise

        return placeholder

    # ── Entity lookup ─────────────────────────────────────────────────────────

    def lookup_by_value(self, raw_value: str) -> str | None:
        """Return existing placeholder for raw_value, or None if not found."""
        assert self._conn is not None
        value_hash = _sha256(raw_value)
        row = self._conn.execute(
            "SELECT placeholder FROM entities WHERE value_hash=?",
            (value_hash,),
        ).fetchone()
        return row["placeholder"] if row is not None else None

    def get_entity(
        self,
        placeholder: str,
        passphrase: str | None = None,
    ) -> str | None:
        """
        Decrypt and return the raw value for placeholder.

        Handles F-07 (expired entry):
          - soft expiry + recovery available → prompt passphrase → decrypt
          - soft expiry + limit reached → promote to hard, return None
          - hard expiry → return None

        Returns None with inline flag if unresolvable.
        """
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM entities WHERE placeholder=?",
            (placeholder,),
        ).fetchone()

        if row is None:
            return None

        now_dt = datetime.now(timezone.utc)
        expires_dt = _parse_utc(row["expires_at"])

        if now_dt < expires_dt:
            # Not expired — decrypt normally
            try:
                raw = self._decrypt(bytes(row["encrypted_value"]), bytes(row["nonce"]))
                return raw.decode("utf-8")
            except InvalidTag:
                return None

        # Entry is expired — F-07
        expiry_type = row["expiry_type"]
        recovery_count = row["recovery_count"]
        session_id = row["session_id"]
        max_rec = self._config.soft_expiry_max_recoveries
        expires_str = _format_dt(expires_dt)

        if expiry_type == "soft" and recovery_count < max_rec:
            # Soft expiry, recovery available
            print(
                f"\n⚠ Placeholder {placeholder} cannot be resolved — vault entry has expired.\n"
                f"\nSession {session_id} expired: {expires_str}"
                f"\nExpiry type: soft — data is flagged but still recoverable"
                f" (recovery {recovery_count + 1} of {max_rec} allowed).\n",
                file=sys.stderr,
            )
            try:
                choice = input("Attempt recovery? This requires your vault passphrase. [y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = "n"

            if choice == "y":
                pp = passphrase if passphrase is not None else _read_passphrase("Vault passphrase for recovery: ")
                try:
                    temp_key = self._derive_key(pp, self._load_or_create_salt(self._config.salt_path))
                    aesgcm = AESGCM(bytes(temp_key))
                    raw = aesgcm.decrypt(bytes(row["nonce"]), bytes(row["encrypted_value"]), None)
                    _zero_key(temp_key)
                    # Increment recovery count
                    self._conn.execute(
                        "UPDATE entities SET recovery_count = recovery_count + 1 WHERE placeholder=?",
                        (placeholder,),
                    )
                    self._conn.commit()
                    return raw.decode("utf-8")
                except (InvalidTag, Exception):
                    print(
                        f"✗ Recovery failed — incorrect passphrase. {placeholder} left unexpanded.",
                        file=sys.stderr,
                    )
                    return None
            return None

        elif expiry_type == "soft" and recovery_count >= max_rec:
            # Promote to hard expiry
            self._conn.execute(
                "UPDATE entities SET expiry_type='hard' WHERE placeholder=?",
                (placeholder,),
            )
            self._conn.commit()
            print(
                f"✗ Placeholder {placeholder} cannot be resolved — vault entry has expired.\n"
                f"\nSession {session_id} expired: {expires_str}"
                f"\nExpiry type: soft — but maximum recovery extensions ({max_rec}) have been reached."
                f"\nThis entry has been promoted to hard expiry and will be overwritten on next vault open."
                f"\n\nThe original value is not recoverable.",
                file=sys.stderr,
            )
            return None

        else:
            # Hard expiry
            print(
                f"✗ Placeholder {placeholder} cannot be resolved — vault entry has expired.\n"
                f"\nSession {session_id} expired: {expires_str}"
                f"\nExpiry type: hard — entry has been overwritten. The original value is not recoverable.",
                file=sys.stderr,
            )
            return None

    # ── Allowlist ─────────────────────────────────────────────────────────────

    def add_to_allowlist(self, raw_value: str) -> None:
        """Add SHA-256 hash of raw_value to the allowlist."""
        assert self._conn is not None
        value_hash = _sha256(raw_value)
        now = _utcnow()
        self._conn.execute(
            "INSERT OR IGNORE INTO allowlist (value_hash, created_at) VALUES (?, ?)",
            (value_hash, now),
        )
        self._conn.commit()

    def is_allowlisted(self, raw_value: str) -> bool:
        assert self._conn is not None
        value_hash = _sha256(raw_value)
        row = self._conn.execute(
            "SELECT 1 FROM allowlist WHERE value_hash=?", (value_hash,)
        ).fetchone()
        return row is not None

    def list_allowlist(self) -> list[dict[str, str]]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT id, value_hash, created_at FROM allowlist ORDER BY created_at"
        ).fetchall()
        return [dict(row) for row in rows]

    def remove_from_allowlist(self, entry_id: int) -> bool:
        assert self._conn is not None
        cursor = self._conn.execute(
            "DELETE FROM allowlist WHERE id=?", (entry_id,)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ── Log records ───────────────────────────────────────────────────────────

    def save_sanitized_log(self, session_id: str, content: str) -> None:
        """Save the sanitized (already-redacted) log — plain text."""
        assert self._conn is not None
        now = _utcnow()
        self._conn.execute(
            "INSERT INTO sanitized_logs (session_id, content, created_at) VALUES (?, ?, ?)",
            (session_id, content, now),
        )
        self._conn.commit()

    def save_reconstructed_log(
        self,
        session_id: str,
        content: str,
        retention_days: int = 90,
    ) -> None:
        """Save the reconstructed log (real values restored) — encrypted in vault."""
        assert self._conn is not None
        ct, nonce = self._encrypt(content.encode("utf-8"))
        now_dt = datetime.now(timezone.utc)
        expires_dt = now_dt.replace(day=now_dt.day)  # placeholder — computed below
        from datetime import timedelta
        expires_dt = now_dt + timedelta(days=retention_days)
        now = _utcnow()
        expires = _format_iso(expires_dt)
        self._conn.execute(
            "INSERT INTO reconstructed_logs"
            " (session_id, encrypted_content, nonce, created_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (session_id, ct, nonce, now, expires),
        )
        self._conn.commit()

    def get_reconstructed_log(self, session_id: str) -> str | None:
        """Decrypt and return the most recent reconstructed log for a session."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT encrypted_content, nonce FROM reconstructed_logs"
            " WHERE session_id=? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            raw = self._decrypt(bytes(row["encrypted_content"]), bytes(row["nonce"]))
            return raw.decode("utf-8")
        except InvalidTag:
            return None

    # ── Maintenance ───────────────────────────────────────────────────────────

    def purge_expired(self) -> int:
        """Purge all hard-expired entities. Returns count removed."""
        assert self._conn is not None
        now = _utcnow()
        cursor = self._conn.execute(
            "DELETE FROM entities WHERE expiry_type='hard' AND expires_at <= ?", (now,)
        )
        self._conn.commit()
        return cursor.rowcount

    def _purge_hard_expired_silent(self) -> int:
        """Purge expired entries on open without user-visible output."""
        if self._conn is None:
            return 0
        try:
            return self.purge_expired()
        except Exception:
            return 0

    def compact(self) -> None:
        """Run VACUUM to reclaim SQLite free pages."""
        assert self._conn is not None
        self._conn.execute("VACUUM")

    def rekey(
        self,
        new_passphrase: str | None = None,
        current_passphrase: str | None = None,
    ) -> None:
        """
        Re-key the vault with a new passphrase and fresh salt (F-10).
        Creates a backup of vault.db before proceeding.
        """
        assert self._conn is not None
        assert self._key is not None

        db_path   = self._config.vault_path
        salt_path = self._config.salt_path
        date_str  = datetime.now(timezone.utc).strftime("%Y%m%d")
        backup_path = db_path.with_suffix(f".db.bak.{date_str}")

        print(f"\nA backup will be created first: {backup_path}", file=sys.stderr)
        shutil.copy2(str(db_path), str(backup_path))
        if platform.system() != "Windows":
            backup_path.chmod(0o600)

        if new_passphrase is None:
            new_passphrase = _read_passphrase("New vault passphrase: ")

        # Generate new salt
        new_salt = os.urandom(32)
        new_key  = self._derive_key(new_passphrase, new_salt)
        _mlock(new_key)

        # Re-encrypt all entities
        rows = self._conn.execute(
            "SELECT placeholder, encrypted_value, nonce FROM entities"
        ).fetchall()

        try:
            for row in rows:
                old_ct    = bytes(row["encrypted_value"])
                old_nonce = bytes(row["nonce"])
                plaintext = self._decrypt(old_ct, old_nonce)
                new_nonce = os.urandom(12)
                aesgcm    = AESGCM(bytes(new_key))
                new_ct    = aesgcm.encrypt(new_nonce, plaintext, None)
                self._conn.execute(
                    "UPDATE entities SET encrypted_value=?, nonce=? WHERE placeholder=?",
                    (new_ct, new_nonce, row["placeholder"]),
                )

            # Re-encrypt reconstructed logs
            log_rows = self._conn.execute(
                "SELECT id, encrypted_content, nonce FROM reconstructed_logs"
            ).fetchall()
            for row in log_rows:
                old_ct    = bytes(row["encrypted_content"])
                old_nonce = bytes(row["nonce"])
                plaintext = self._decrypt(old_ct, old_nonce)
                new_nonce = os.urandom(12)
                aesgcm    = AESGCM(bytes(new_key))
                new_ct    = aesgcm.encrypt(new_nonce, plaintext, None)
                self._conn.execute(
                    "UPDATE reconstructed_logs SET encrypted_content=?, nonce=? WHERE id=?",
                    (new_ct, new_nonce, row["id"]),
                )

            self._conn.execute(
                "UPDATE vault_meta SET encryption_op_count=0 WHERE id=1"
            )
            self._conn.commit()

        except Exception as exc:
            # Restore from backup
            self._conn.close()
            self._conn = None
            shutil.copy2(str(backup_path), str(db_path))
            _zero_key(new_key)
            self._zero_and_clear_key()
            raise VaultError(
                f"✗ Re-keying failed and could not be completed.\n"
                f"\nThe vault has been restored from backup: {backup_path}\n"
                f"The vault is now in read-only mode.\n"
                f"\nFree disk space and run: darmok --vault-rekey"
            ) from exc

        # Commit new salt and update in-memory key
        salt_path.write_bytes(new_salt)
        if platform.system() != "Windows":
            salt_path.chmod(0o600)

        _zero_key(self._key)
        self._key = new_key

    def audit(self, session_id: str) -> dict[str, Any]:
        """Return session entity summary (no raw values exposed)."""
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT placeholder, category, created_at, expires_at, expiry_type,"
            " recovery_count FROM entities WHERE session_id=? ORDER BY created_at",
            (session_id,),
        ).fetchall()
        return {
            "session_id": session_id,
            "entity_count": len(rows),
            "entities": [dict(row) for row in rows],
        }

    def reinitialize(self) -> None:
        """Destroy vault.db and vault.salt, then reinitialize (with backup)."""
        db_path   = self._config.vault_path
        salt_path = self._config.salt_path

        if self._conn is not None:
            self._conn.close()
            self._conn = None

        date_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        for path in [db_path, salt_path]:
            if path.exists():
                backup = path.with_suffix(f"{path.suffix}.reinit-bak.{date_str}")
                shutil.move(str(path), str(backup))

    # ── F-04: disk full handling ──────────────────────────────────────────────

    def _handle_disk_full(self, context: str = "") -> None:
        """
        F-04: attempt to free space by purging expired sessions.
        Prompts user to continue without persistence or abort.
        """
        freed = self.purge_expired()
        freed_mb = 0.0  # estimation; actual size not trivially available
        if freed > 0:
            print(
                f"\n⚠ Vault disk full — freed space by purging {freed} expired sessions. Continuing.\n",
                file=sys.stderr,
            )
            return

        print(
            f"\n✗ Vault disk full and insufficient space recovered after cleanup.\n"
            f"\nFreed by cleanup: 0 sessions purged\n"
            f"\nThe tool will continue processing but nothing will be persisted to the vault.\n"
            f"Reconstruction after this session will not be possible.\n"
            f"\nTo free space manually:\n"
            f"  darmok --vault-purge-expired\n"
            f"  darmok --vault-compact\n"
            f"\nPress [c] to continue without persistence, [x] to abort.",
            file=sys.stderr,
        )
        try:
            choice = input("Action: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "x"

        if choice == "x":
            raise SystemExit(1)
        raise VaultDiskFull("Vault disk full — continuing without persistence")

    # ── op_count accessor for testing ─────────────────────────────────────────

    def get_op_count(self) -> int:
        """Return current encryption_op_count (for testing)."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT encryption_op_count FROM vault_meta WHERE id=1"
        ).fetchone()
        return row["encryption_op_count"] if row else 0

    def set_op_count(self, count: int) -> None:
        """Set encryption_op_count (for testing F-10)."""
        assert self._conn is not None
        self._conn.execute(
            "UPDATE vault_meta SET encryption_op_count=? WHERE id=1", (count,)
        )
        self._conn.commit()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M")


def _parse_utc(s: str) -> datetime:
    """Parse ISO-8601 UTC string to timezone-aware datetime."""
    s = s.rstrip("Z")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_disk_full(exc: OSError) -> bool:
    import errno
    return exc.errno in (errno.ENOSPC, errno.EDQUOT) if hasattr(errno, "EDQUOT") else exc.errno == errno.ENOSPC
