# Vault Failure Modes Specification
**Version:** 1.2
**Last Updated:** 2026-02-28
**Scope:** Phase 2 — Encrypted Vault and Session Management

> **Status (2026-02-28): Phase 1 and Phase 2 are both complete.** All 7 detectors pass (recall=1.000, precision=1.000). The encrypted vault (`darmok/vault.py`), session manager (`darmok/session.py`), and config loader (`darmok/config.py`) are implemented. All 13 failure mode tests pass in `tests/test_vault.py` and `tests/test_session.py`. See `DARMOK_PROJECT_CONTEXT.md` for the full project status.

**Changelog v1.2:** Updated all file paths from `~/.sanitizer/` to `~/.darmok/` to reflect product rename. Updated CLI command prefix from `python sanitize.py` to `darmok`. Updated schema version references to 1.2. Added F-12 (vault detected in cloud-synced folder). Added F-13 (context doc missing at session start). Added GUI behavior notes to all failure modes — failure messages must surface appropriately in both CLI and desktop GUI contexts. Updated failure mode matrix and testing requirements for F-12 and F-13.

**Changelog v1.1:** Revised F-06 migration prompt to clarify 'n' exits without modifying. Revised F-07 to surface expiry type before asking for passphrase, added hard/soft/limit-reached message variants. Revised F-08 to address swap exposure and lead with recommended action. Added F-10 (re-keying threshold). Added F-11 (sessions.json missing/corrupt/permissions). Added `--dry-run` column to failure mode matrix. Updated testing requirements for all new cases.

---

## Design Principle

The vault never silently degrades into an unprotected state. Every failure either hard fails with a clear, actionable error message, or warns explicitly and gives the user a decision. Silent failures are never acceptable — the tool's entire value is trust, and trust requires transparency about what is and isn't working.

**For the desktop GUI:** All failure messages that appear in the CLI also surface in the GUI — either as modal dialogs (hard failures) or as dismissable notification banners (warnings). CLI message text is the source of truth for message content; the GUI wraps it in appropriate UI chrome. Error log entries always go to `~/.darmok/error.log` regardless of surface.

---

## Failure Reference

### F-01 — Wrong Passphrase on Vault Unlock
**Trigger:** Argon2id key derivation produces a key that fails AES-256-GCM authentication on the first vault read.
**Behavior:** Hard fail.
**User message:**
```
✗ Vault unlock failed — incorrect passphrase.

The vault at ~/.darmok/vault.db could not be decrypted.

If you have forgotten your passphrase, the vault contents are unrecoverable.
To start fresh: darmok --vault-reinitialize
Warning: reinitializing permanently destroys all existing vault data.
```
**GUI behavior:** Modal dialog with single action: Try again (re-prompts passphrase) or Reinitialize (with confirmation step).
**Recovery path:** `--vault-reinitialize` after explicit user confirmation.
**Do not:** Retry automatically. Do not offer hints. Do not fall back to sessionless mode.

---

### F-02 — Corrupted vault.db
**Trigger:** SQLite integrity check fails on vault open (`PRAGMA integrity_check` returns errors).
**Behavior:** Hard fail.
**User message:**
```
✗ Vault integrity check failed — vault.db is corrupted.

The vault at ~/.darmok/vault.db failed its integrity check and cannot be used safely.

Options:
  1. Restore from backup if you have one
  2. Reinitialize: darmok --vault-reinitialize
     Warning: reinitializing permanently destroys all existing vault data.

Do not attempt to use the vault in its current state.
```
**GUI behavior:** Modal dialog with two buttons: Open Backup Location and Reinitialize Vault (with confirmation).
**Do not:** Attempt auto-repair. Do not start sessionless mode. Corrupted vault may indicate tampering.

---

### F-03 — Session Resumption Fails (Wrong Passphrase or Expired)
**Trigger:** User provides session ID for resumption but key derivation fails, or session has passed hard expiry.
**Behavior:** Hard fail.
**User message (wrong passphrase):**
```
✗ Session resumption failed — incorrect passphrase for session sess_a3f9b2.

This session cannot be resumed without the correct passphrase.
The session metadata (project name, tags, open questions) is still readable.
The entity mappings (real values behind placeholders) are not recoverable.

To start a new session: darmok --session-start "project-name"
```
**User message (hard expiry):**
```
✗ Session sess_a3f9b2 has expired and cannot be resumed.

Session expired: 2026-02-24 18:32 (4 hours after creation)
Expiry type: hard — entries have been overwritten.

The session metadata is still readable via: darmok --audit sess_a3f9b2
To start a new session: darmok --session-start "project-name"
```
**GUI behavior:** Modal dialog. For wrong passphrase: Try again button. For hard expiry: shows session metadata (project, tags, open questions) from sessions.json since those remain readable, with a Start New Session button.
**Do not:** Silently start a new session. Do not treat as a new session without explicit user action.

---

### F-04 — Vault Disk Full
**Trigger:** Write to vault.db fails with no space left on device.
**Behavior:** Attempt cleanup first, then warn and continue if cleanup frees enough space, hard fail if not.
**Cleanup step:** Attempt to purge all hard-expired sessions before surfacing the error. Log how much space was recovered.
**If cleanup succeeds:**
```
⚠ Vault disk full — freed 2.3MB by purging 4 expired sessions. Continuing.
```
**If cleanup fails to free enough space:**
```
✗ Vault disk full and insufficient space recovered after cleanup.

Freed by cleanup: 0.4MB (4 expired sessions purged)
Still required: ~1.2MB

The tool will continue processing but nothing will be persisted to the vault.
Reconstruction after this session will not be possible.

To free space manually:
  darmok --vault-purge-expired    # remove all expired sessions
  darmok --vault-compact          # reclaim SQLite free pages

Press [c] to continue without persistence, [x] to abort.
```
**GUI behavior:** Warning banner for cleanup success. Modal dialog for hard fail with Continue Without Saving and Abort buttons and a link to vault management settings.
**Do not:** Silently drop writes. Every unpersisted entity must be flagged.

---

### F-05 — Vault File Incorrect Permissions
**Trigger:** `vault.db` or `vault.salt` found with permissions other than 600 on Unix/Mac systems.
**Behavior:** Warn and continue. Log the issue.
**User message:**
```
⚠ Security warning: vault.db has permissions 644 (expected 600).

Other users on this system may be able to read your vault file.
The vault is still encrypted, but this is not the recommended configuration.

To fix: chmod 600 ~/.darmok/vault.db

Continuing. To suppress this warning: set permission_check: false in config.yaml
```
**GUI behavior:** Dismissable warning banner with a Fix Automatically button (runs `chmod 600` and confirms). Suppress option available in settings.
**Log entry:** `WARN permission_check vault.db mode=644 expected=600`
**Do not:** Auto-fix permissions without telling the user. Do not block — the vault is still encrypted.

---

### F-06 — Vault Schema Version Mismatch
**Trigger:** `schema_version` in vault.db does not match the current tool version's expected schema.
**Behavior:** Attempt migration if a migration path exists. Hard fail if no migration path exists.
**If migration path exists:**
```
⚠ Vault schema migration required: v1.1 → v1.2

Changes in v1.2:
  - Added parent_session_id, thread_root_id, thread_position fields
  - Added folder field to session metadata
  - Added redaction_mode and redaction_tiers fields
  - Added context_docs_prepended field

A backup will be created before migrating: ~/.darmok/vault.db.bak.20260227

Migrate now? [y/n] (choosing 'n' exits without modifying anything):
```
**GUI behavior:** Modal dialog with changelog shown in a scrollable area. Migrate Now and Cancel buttons. Always shows backup location before proceeding.
Migration is non-destructive — backup always created first. If migration fails, restore from backup and hard fail.
**If no migration path exists:**
```
✗ Vault schema version v0.9 is not supported by this version of the tool.

This vault was created with an older version that cannot be automatically migrated.
The vault contents are not accessible with this version.

Options:
  1. Downgrade to the version that created this vault
  2. Reinitialize: darmok --vault-reinitialize
     Warning: reinitializing permanently destroys all existing vault data.
```
**Do not:** Proceed with a mismatched schema. Silent schema mismatch can corrupt data.

---

### F-07 — Expired Vault Entry During Reconstruction
**Trigger:** Reconstructor attempts to expand a placeholder but the corresponding vault entry has passed its expiry time.
**Behavior:** Surface expiry type first, then prompt based on what is possible. Do not ask for a decision before the user knows whether recovery is possible.

**If expiry type is `soft` and recovery count < 3:**
```
⚠ Placeholder [sess_a3f9b2:API_KEY_1] cannot be resolved — vault entry has expired.

Session sess_a3f9b2 expired: 2026-02-24 18:32
Expiry type: soft — data is flagged but still recoverable (recovery 1 of 3 allowed).

Attempt recovery? This requires your vault passphrase. [y/n]:
```
**If recovery succeeds:** Reconstruct normally, increment `recovery_count`, log the recovery event.
**If recovery fails (wrong passphrase):**
```
✗ Recovery failed — incorrect passphrase. [sess_a3f9b2:API_KEY_1] left unexpanded.
```

**If expiry type is `soft` and recovery count = 3 (limit reached):**
```
✗ Placeholder [sess_a3f9b2:API_KEY_1] cannot be resolved — vault entry has expired.

Session sess_a3f9b2 expired: 2026-02-24 18:32
Expiry type: soft — but maximum recovery extensions (3) have been reached.
This entry has been promoted to hard expiry and will be overwritten on next vault open.

The original value is not recoverable.
```

**If expiry type is `hard`:**
```
✗ Placeholder [sess_a3f9b2:API_KEY_1] cannot be resolved — vault entry has expired.

Session sess_a3f9b2 expired: 2026-02-24 18:32
Expiry type: hard — entry has been overwritten. The original value is not recoverable.
```

**In all unresolved cases,** flag inline in reconstructed output:
```
⚠ [sess_a3f9b2:API_KEY_1] — vault entry expired, could not recover. Original value lost.
```
**GUI behavior:** For soft expiry with recovery available — modal dialog showing expiry info, passphrase prompt, then result. For hard expiry or limit reached — inline warning banner in the reconstructed output view with an explanation. The session's entity panel shows expired entries in red with a lock-broken icon.
**Do not:** Silently leave the placeholder without flagging it. Do not substitute an empty string. Do not ask for the passphrase before telling the user whether recovery is even possible.

---

### F-08 — Key Zeroing Failure at Session End
**Trigger:** Session end or timeout triggered, but the `bytearray` zeroing operation via `ctypes` cannot be confirmed, or the key was inadvertently copied to an immutable Python object.
**Behavior:** Warn and continue. Surface to user with the recommended action first.
**User message:**
```
⚠ Key zeroing may be incomplete — recommended action: close this terminal session.

The session key could not be reliably zeroed from memory. This can occur if:
  - The key was held in memory long enough for the OS to write it to swap
  - Python copied the key to a new memory location before zeroing occurred

Action recommended: terminate this terminal session now to flush process memory.
Terminating the terminal does not clear swap. If your system has swap enabled,
key material may persist on disk until the swap partition is overwritten.

For full protection: disable swap before running this tool with Tier 1 credentials,
or use a system with an encrypted swap partition.

[Press any key to continue]
```
**GUI behavior:** Modal dialog with a single Understood button. The recommended action (close the app) is stated clearly. In the desktop app context, the equivalent of "close this terminal session" is "quit the application entirely."
**Log entry:** `WARN key_zeroing session_id=sess_a3f9b2 status=incomplete reason=zeroing_unconfirmed`
**Do not:** Silently continue. Do not hard fail — the session completed successfully. Key zeroing is a best-effort security property, not a correctness property. Implementation must use `bytearray` for key storage and `ctypes` for zeroing. `mlock` must be used on Linux before this failure mode is triggered.

---

### F-09 — vault.salt Missing or Corrupted
**Trigger:** `vault.salt` file is absent or fails a checksum/length validation.
**Behavior:** Hard fail. Salt is required for key derivation — without it the vault is permanently unreadable.
**User message:**
```
✗ vault.salt is missing or corrupted.

Key derivation requires the salt file at ~/.darmok/vault.salt.
Without it, the vault cannot be decrypted. This is not recoverable.

If you have a backup of vault.salt, restore it to ~/.darmok/vault.salt and retry.

If no backup exists, the vault contents are permanently unrecoverable.
To start fresh: darmok --vault-reinitialize
Warning: reinitializing permanently destroys all existing vault data.
```
**GUI behavior:** Modal dialog. If a backup vault export exists, offer to restore from it (vault export includes both vault.db and vault.salt as a single encrypted bundle). Otherwise: Open Backup Location and Reinitialize buttons.
**Do not:** Attempt key derivation without the correct salt. Do not generate a new salt and try.

---

### F-10 — Re-keying Threshold Reached
**Trigger:** `encryption_op_count` in the vault metadata row reaches 2^24 (16,777,216). Checked before every encryption operation.
**Behavior:** Hard block on further writes until re-keying completes.
**User message:**
```
⚠ Vault re-keying required — encryption operation limit reached.

This vault has reached the maximum number of encryption operations under the current key
(16,777,216 operations). Re-keying is required before the vault can accept new entries.

Re-keying will:
  1. Derive a new key from your passphrase with a fresh salt
  2. Re-encrypt all vault entries under the new key
  3. Replace vault.salt and reset the operation counter

A backup will be created first: ~/.darmok/vault.db.bak.20260227

Re-key now? [y/n] (choosing 'n' puts the vault in read-only mode until re-keying completes):
```
**If re-keying succeeds:** Resume normally.
**If re-keying fails mid-way:**
```
✗ Re-keying failed and could not be completed.

The vault has been restored from backup: ~/.darmok/vault.db.bak.20260227
The vault is now in read-only mode — reconstruction is available but no new entities can be stored.

Free disk space and run: darmok --vault-rekey
```
**GUI behavior:** Modal dialog with Re-key Now (passphrase prompt follows) and Later (read-only mode warning shown in status bar) buttons. Progress indicator shown during re-keying. On failure: modal with backup restoration confirmation and link to vault management.
**Do not:** Allow further encryption operations without re-keying. Do not silently increment past the threshold.

---

### F-11 — sessions.json Missing or Unreadable
**Trigger:** `sessions.json` is absent, not valid JSON, or has permissions other than 600.
**Behavior (missing or invalid JSON):** Warn, recreate empty, continue. Vault entries are unaffected.
**User message (missing):**
```
⚠ sessions.json not found — recreating empty index.

Session metadata (project names, tags, open questions) from prior sessions is not available.
Vault entries are unaffected. To suppress: this warning is shown once per recreation.
```
**User message (invalid JSON):**
```
⚠ sessions.json is corrupted (invalid JSON) — recreating empty index.

A backup of the corrupted file has been saved: ~/.darmok/sessions.json.bak.20260227
Session metadata from prior sessions is not available. Vault entries are unaffected.
```
**Behavior (wrong permissions):** Warn and continue, same pattern as F-05.
**User message (wrong permissions):**
```
⚠ Security warning: sessions.json has permissions 644 (expected 600).

Project names, tags, and open questions stored in this file may be readable by
other users on this system. The file does not contain raw secret values.

To fix: chmod 600 ~/.darmok/sessions.json

Continuing. To suppress this warning: set permission_check: false in config.yaml
```
**GUI behavior:** Dismissable warning banner for all three cases. For missing/corrupt: the sessions sidebar will show empty state with a "Sessions index was rebuilt" notice. For permissions: same Fix Automatically button pattern as F-05.
**Log entry:** `WARN permission_check sessions.json mode=644 expected=600`
**Do not:** Hard fail on missing sessions.json. Do not expose session metadata contents in the error message.

---

### F-12 — Vault Detected in Cloud-Synced Folder
**Trigger:** On vault open, the tool detects that `~/.darmok/vault.db` or `~/.darmok/vault.salt` is located inside a known cloud-synced directory (iCloud Drive, Dropbox, OneDrive, Google Drive — detected by path pattern and/or extended attribute checks on macOS/Windows).
**Behavior:** Warn once, continue. Do not block — the vault is encrypted and the user may have intentionally done this.
**User message:**
```
⚠ vault.db appears to be in a cloud-synced folder.

Your vault is encrypted and your data is protected, but storing vault.db in a
cloud-synced location has two risks:
  1. Concurrent writes from multiple devices can corrupt SQLite
  2. Your encrypted vault file is uploaded to a third-party server

Recommendation: move your vault to a non-synced location:
  mv ~/.darmok/vault.db ~/Documents/darmok-vault/vault.db
  (update vault_path in config.yaml to match)

To suppress this warning: set warn_vault_in_cloud: false in config.yaml
```
**GUI behavior:** Dismissable warning banner shown once per vault location. Settings → Storage shows the current vault path with a cloud-sync indicator if detected, and a Move Vault button.
**Log entry:** `WARN vault_location path=~/.darmok/vault.db cloud_sync_detected=true provider=iCloud`
**Do not:** Auto-move the vault. Do not hard fail — the user may have made an informed choice. Do not warn on every open — only warn once and then suppress unless the location changes.

---

### F-13 — Context Doc Missing at Session Start
**Trigger:** A context doc referenced in the project/folder hierarchy is not found at its expected path when a session is being started.
**Behavior:** Warn, skip the missing doc, continue with remaining context docs. Do not block session start.
**User message:**
```
⚠ Context doc not found: auth-service/context.md

This document was expected but is missing. It will be skipped for this session.
Other context docs in the hierarchy are unaffected.

To create it: open the project in Darmok and add a context document, or:
  touch ~/.darmok/projects/auth-service/context.md

To suppress: remove the project from the folder hierarchy or recreate the file.
```
**GUI behavior:** Dismissable warning banner in the session view. The context doc banner at the top of the chat shows the missing doc with a strikethrough and a `⚠ missing` badge. Clicking it opens a dialog to create the doc.
**Log entry:** `WARN context_doc path=auth-service/context.md status=missing session_id=sess_a3f9b2`
**Do not:** Hard fail — a missing context doc is an organizational problem, not a security problem. Do not silently skip without telling the user. Do not block session start.

---

## Message Conventions

All failure messages follow these conventions:

- `✗` prefix for hard failures — unrecoverable without user action
- `⚠` prefix for warnings — tool continues with a degraded or modified behavior
- Every hard failure includes at least one concrete recovery path with the exact command
- Every warning includes a way to suppress it (`config.yaml` setting or `--no-warn-X` flag)
- No stack traces surfaced to the user — log to `~/.darmok/error.log` instead
- Error messages never include raw sensitive values, partial key material, or vault contents
- GUI equivalents: hard failures → modal dialogs. Warnings → dismissable banners. Both use the same message text as the CLI.

---

## Failure Mode Matrix

| Code | Scenario | Behavior | Recoverable? | `--dry-run` behavior | GUI surface |
|---|---|---|---|---|---|
| F-01 | Wrong passphrase | Hard fail | Only via reinitialize | Same — hard fail | Modal dialog |
| F-02 | Corrupted vault.db | Hard fail | Only via backup or reinitialize | Same — hard fail | Modal dialog |
| F-03 | Session resumption fails | Hard fail | No — data unrecoverable | Same — hard fail | Modal dialog |
| F-04 | Disk full | Cleanup + warn/fail | Yes — free disk space | Warn only — dry-run makes no writes | Banner (warn) / Modal (fail) |
| F-05 | Incorrect file permissions | Warn, continue | Yes — chmod 600 or auto-fix | Same — warn, continue | Dismissable banner |
| F-06 | Schema version mismatch | Migrate or hard fail | Yes if migration path exists | Same — hard fail (dry-run does not trigger migration) | Modal dialog with changelog |
| F-07 | Expired entry on reconstruct | Prompt recovery (if soft) / hard fail (if hard) | Maybe — depends on expiry type | Same — dry-run still reads vault | Modal (soft) / inline flag (hard) |
| F-08 | Key zeroing incomplete | Warn, continue | N/A — best-effort property | N/A — dry-run does not open a keyed session | Modal dialog |
| F-09 | vault.salt missing | Hard fail | Only via backup or reinitialize | Same — hard fail | Modal dialog |
| F-10 | Re-keying threshold reached | Block writes, prompt re-key | Yes — re-key with passphrase | Warn only — dry-run makes no writes | Modal dialog with progress |
| F-11 | sessions.json missing/corrupt/wrong permissions | Warn, recreate or continue | Yes — recreated automatically | Same | Dismissable banner |
| F-12 | Vault in cloud-synced folder | Warn once, continue | N/A — user decision | Same — warn once | Dismissable banner |
| F-13 | Context doc missing at session start | Warn, skip doc, continue | Yes — create the file | Same — warn, continue | Dismissable banner |

---

## Testing Requirements

Each failure mode must have a deliberate failure test in the Phase 2 test suite:

| Test | How to induce |
|---|---|
| F-01 | Provide wrong passphrase to `darmok --session-resume` |
| F-02 | Corrupt vault.db by flipping bytes, attempt open |
| F-03 | Resume expired session, provide wrong passphrase |
| F-04 | Fill disk with a temp file, attempt vault write |
| F-05 | `chmod 644 vault.db`, run tool |
| F-06 | Manually set `schema_version` to old value, run current tool — verify v1.1→v1.2 migration changelog shown |
| F-07 (soft) | Create soft-expiry session, force-expire entry, attempt reconstruction — verify expiry type shown before passphrase prompt |
| F-07 (hard) | Create hard-expiry session, force-expire entry, attempt reconstruction — verify immediate unrecoverable message |
| F-07 (limit) | Create soft-expiry entry, set `recovery_count=3`, attempt reconstruction — verify auto-promotion to hard |
| F-08 | Mock the `ctypes` zeroing call to return failure, end session — verify swap warning present in output |
| F-09 | Delete `vault.salt`, attempt vault open |
| F-10 | Set `encryption_op_count` to 2^24 - 1, perform one more encryption — verify re-key prompt |
| F-11 (missing) | Delete `sessions.json`, run tool — verify warn + recreate |
| F-11 (corrupt) | Write invalid JSON to `sessions.json`, run tool — verify warn + backup + recreate |
| F-11 (permissions) | `chmod 644 sessions.json`, run tool — verify permission warning |
| F-12 | Symlink vault.db into a path matching iCloud Drive pattern, run tool — verify single warn on first open, suppressed on subsequent opens |
| F-13 | Create project with context.md reference, delete the file, start session — verify warn + skip + session proceeds |

**Status (2026-02-28): ✓ All 13 failure mode tests pass.** Phase 2 is complete.
