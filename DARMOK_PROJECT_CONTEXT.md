# Darmok — Project Knowledge Base
**Product:** Darmok (CLI Privacy Firewall)
**Version:** 2.0
**Last Updated:** 2026-02-28

---

## ⚠ Instructions for Claude Code — Read Before Writing Any Code

1. **Do not start Phase 2 until Phase 1 benchmark targets are fully met.** All three tiers must pass independently: Tier 1 recall ≥ 0.99, Tier 2 recall ≥ 0.95, Tier 3 recall ≥ 0.90. Passing an overall average is not sufficient. Do not begin vault or session work until the benchmark dashboard shows all tiers green.

2. **Do not implement compression.** Compression has been removed entirely. There is no `compressor.py`. Do not create one. If a task seems to imply compression, stop and flag it.

3. **Read the spec before writing the code.** Before implementing any detector, read `docs/detector_spec.md` in full. Before implementing any vault or session logic, read `docs/vault_failure_modes.md` in full. The spec is the source of truth — do not infer behavior from code structure.

4. **Implement detectors one at a time in this order:** PrivateKey → JWT → ApiKey → UrlCredential → Email → IpAddress → CreditCard. Run the benchmark suite after each. Do not proceed to the next detector until the current one passes its tier target.

5. **Do not add features not in this document.** If something seems useful but isn't specified here, stop and ask. Do not build ahead.

6. **This is a library as well as a CLI.** Darmok's detection engine and vault are consumed by Neech (a separate desktop product). Write the detection pipeline and vault as importable Python modules, not just CLI-bound logic. The CLI is a consumer of the library, not the only consumer.

---

**Status:** Phase 1 in progress.

*Test infrastructure* — Updated from `sanitizer.*` to `darmok.*`. Category names are snake_case throughout (`private_key`, `jwt`, `api_key`, `url_credential`, `email`, `ip_address`, `credit_card`). Harness uses `d.raw_value`, tier-aware `TierResult`/`CATEGORY_TIER`, per-tier recall/precision targets. Synthetic suite: 50 cases per category + 100 negative cases = 460 total. Standalone benchmark runner at `benchmark/run.py`.

*Benchmark (2026-02-28)* — pytest: 39 pass, 12 skip (stub detectors), 17 fail (unit tests for unimplemented detectors — expected). 19 adversarial tests all passing.

| Detector      | Recall | Precision | Target  | Status     |
|---|---|---|---|---|
| PrivateKey    | 1.000  | 1.000     | ≥ 0.99  | ✓ PASS     |
| JWT           | 1.000  | 1.000     | ≥ 0.99  | ✓ PASS     |
| ApiKey        | 1.000  | 1.000     | ≥ 0.99  | ✓ PASS     |
| UrlCredential | 1.000  | 1.000     | ≥ 0.99  | ✓ PASS     |
| Email         | —      | —         | ≥ 0.95  | not started |
| IpAddress     | —      | —         | ≥ 0.95  | not started |
| CreditCard    | —      | —         | ≥ 0.95  | not started |

**Last Updated:** 2026-02-28
**Next Action:** Implement `EmailDetector` in `darmok/detectors/email.py`. Run `python benchmark/run.py`. Verify recall ≥ 0.95 passes. Then move to `IpAddressDetector`. Do not skip ahead.

## Companion Documents
- `docs/detector_spec.md` — canonical detector specification. All implementations build against this.
- `docs/vault_failure_modes.md` — all 13 vault failure scenarios with exact behavior, user messages, and test requirements.

---

## What Darmok Is

A CLI privacy firewall for developers, DevOps engineers, and technical users who work with LLMs on real infrastructure data. Sits between the user and any LLM. Intercepts input, detects and redacts recognized structured secrets, sends the clean version to the LLM, reconstructs the response with real values restored. Nothing sensitive leaves the machine in plaintext.

Darmok is also the engine that powers Neech, a separate desktop AI workspace product. The detection pipeline and vault built here are consumed by Neech as a library. This shapes two things: the code must be importable as a module, and the API surface of the library matters as much as the CLI UX.

**The privacy guarantee covers recognized structured secrets:** API keys, private keys, JWTs, URL-embedded credentials, email addresses, IP addresses, credit card numbers. It does not extend to unstructured sensitive content such as proprietary business logic or natural-language descriptions of sensitive matters. This boundary is communicated clearly at every run.

---

## The Full Pipeline

```
Raw Input → Detector → Redactor → Safe Prompt → LLM
                                                  ↓
Real Output ← Reconstructor ← Per-Exchange Manifest ← LLM Response
```

Compression is not part of this pipeline. It is not deferred — it is removed.

---

## Why We Are Building It This Way

### Detection — Hybrid Pipeline
- **Pure Regex** — rejected. Brittle, cannot handle ambiguity.
- **Pure ML/NER** — rejected for Phase 1. Heavy, slow, overkill for structured secrets.
- **Pure LLM Detection** — rejected entirely. Circular: sending sensitive data to detect sensitive data.
- **Local LLM for detection** — rejected for Phases 1 and 2. Structured pattern matching does not require language understanding. Local LLM belongs in Neech Phase 5.
- **Hybrid Pipeline (chosen)** — regex for structured patterns, confidence scoring for ambiguity, context disambiguation. Modular — each detector is independently swappable.

### No Compression
Compression is removed entirely. Privacy is the core value proposition. Compression adds a failure surface without strengthening that promise. Token costs are falling fast. It is not coming back.

### Build and Test Philosophy
Each phase is validated completely before the next begins. Detector accuracy gaps discovered after the vault is built are exponentially more expensive to fix. Phase 1 is not done until all tier targets are met independently on synthetic data including adversarial cases.

---

## Tiered Recall Targets

| Tier | Categories | Recall Target | Precision Target | Below auto-redact threshold |
|---|---|---|---|---|
| **1** | API keys, private keys, JWTs, URL credentials | ≥ 0.99 | ≥ 0.90 | Block — require user decision |
| **2** | Email addresses, IP addresses, credit card numbers | ≥ 0.95 | ≥ 0.95 | Flag for review |
| **3** | Contextual / ambiguous | ≥ 0.90 | ≥ 0.95 | Log, leave alone |

All tiers must pass independently. Passing an average is not sufficient.

---

## Entity Registry

The entity registry is a first-class system component. Its identity semantics and collision behavior are invariants, not conventions.

**Placeholder format:** `[sess_a3f9b2:EMAIL_1]` — full session-scoped IDs everywhere. Short or unprefixed placeholders are never used.

**Identity rules:**
- Global value-to-placeholder map across all sessions.
- When a raw value is first seen, it is assigned a session-scoped ID that becomes its permanent identity in the vault.
- Same raw value in a later session → same original placeholder returned. Deduplication is a vault lookup.
- Two different raw values can never share a placeholder. Collision is structurally impossible by construction.

---

## Config File — `~/.darmok/config.yaml`

All runtime-configurable values live here. Detectors, the pipeline, the vault, and the CLI all read from this file. Neech reads it via the Darmok library — it does not maintain a separate copy.

If the file is missing, Darmok creates it with defaults on first run. If the file is present but a key is missing, the default is used. If the file contains an unknown key, warn and ignore (do not hard fail — forward compatibility).

Permissions: 600 on Unix/Mac. Checked on load, same pattern as F-05.

### Schema

```yaml
# ─── Detection Thresholds ───────────────────────────────────────────
thresholds:
  auto_redact: 0.85          # Confidence >= this → auto-redact (all tiers). Inclusive.
  tier1_block: 0.50          # Confidence >= this and < auto_redact → block for review (Tier 1 only)
  log_floor: 0.0             # Confidence > this → logged. 0.0 means everything above zero is logged.
  suppression_floor: 0.20    # Fixed floor for suppressed matches. Not configurable per-detector.

# ─── Detector-Specific Overrides ────────────────────────────────────
# Per-detector threshold overrides. If absent, the global thresholds above apply.
# Only override if benchmarking shows a specific detector needs different tuning.
detectors:
  api_key:
    enabled: true
    # auto_redact: 0.85      # Uncomment to override global
  jwt:
    enabled: true
  private_key:
    enabled: true
  url_credential:
    enabled: true
  email:
    enabled: true
  ip_address:
    enabled: true
  credit_card:
    enabled: true

# ─── Context Windows ────────────────────────────────────────────────
# Tokens (word characters per \w+ regex) to examine on each side of a match.
# These are intentionally different per detector — do not standardize without benchmarking.
context_windows:
  api_key: 10
  jwt: 10
  private_key: 5             # PEM markers are unambiguous, minimal context needed
  url_credential: 5          # URL structure is self-contained
  email: 10
  ip_address: 15             # IPs appear in more varied prose contexts
  credit_card: 10

# ─── Entity Registry ────────────────────────────────────────────────
registry:
  placeholder_format: "sess_{session_id}:{CATEGORY}_{index}"
  # session_id is the first 6 hex chars of the cryptographic session ID

# ─── Vault ──────────────────────────────────────────────────────────
vault:
  path: "~/.darmok/vault.db"
  salt_path: "~/.darmok/vault.salt"
  default_expiry_hours: 4
  default_expiry_type: "hard"          # "hard" or "soft"
  soft_expiry_max_recoveries: 3
  rekey_threshold: 16777216            # 2^24 — encryption ops before mandatory re-key
  argon2:
    time_cost: 3
    memory_cost: 65536                 # KiB
    parallelism: 1

# ─── Session ────────────────────────────────────────────────────────
session:
  schema_version: "1.2"
  sessions_json_path: "~/.darmok/sessions.json"

# ─── Thread Context (consumed by Neech, defined here for single source of truth) ─
thread_context:
  budget_pct: 0.20                     # Max fraction of model context window for prepend
  decay_window_sessions: 3             # Context entries decay after this many sessions
  compaction_interval: 5               # Compaction runs every N sessions in a thread

# ─── Warnings and Checks ───────────────────────────────────────────
warnings:
  permission_check: true               # Check file permissions on vault.db, vault.salt, sessions.json
  warn_vault_in_cloud: true            # Warn if vault is in a cloud-synced folder (F-12)

# ─── Output ─────────────────────────────────────────────────────────
output:
  show_post_run_summary: true
  show_tier_breakdown: true
  log_path: "~/.darmok/error.log"

# ─── Redaction Mode ────────────────────────────────────────────────
# Default mode for new sessions. Can be overridden per-session or per-message in Neech.
# Values: "off", "dry-run", "on"
redaction_mode: "off"
```

### Loading Rules

1. **File location:** `~/.darmok/config.yaml`. Overridable via `DARMOK_CONFIG` environment variable or `--config` CLI flag.
2. **Missing file:** Create with all defaults. Log: `INFO config created at ~/.darmok/config.yaml with defaults`.
3. **Missing key:** Use the default value from the schema above. Do not error.
4. **Unknown key:** Warn and ignore. Log: `WARN config unknown key: <key>`. Do not error.
5. **Invalid value type:** Hard fail with message: `✗ config.yaml: <key> expected <type>, got <actual>`. Example: `✗ config.yaml: thresholds.auto_redact expected float, got string "high"`.
6. **Invalid value range:** Hard fail with message. Example: `✗ config.yaml: thresholds.auto_redact must be between 0.0 and 1.0, got 1.5`.
7. **Permissions check:** Same pattern as F-05 — warn if not 600 on Unix/Mac.

### Validation Constraints

| Key | Type | Range | Default |
|---|---|---|---|
| `thresholds.auto_redact` | float | 0.0–1.0 | 0.85 |
| `thresholds.tier1_block` | float | 0.0–1.0, must be < auto_redact | 0.50 |
| `thresholds.suppression_floor` | float | 0.0–1.0, must be < tier1_block | 0.20 |
| `vault.default_expiry_hours` | int | 1–720 (30 days max) | 4 |
| `vault.default_expiry_type` | string | "hard" \| "soft" | "hard" |
| `vault.soft_expiry_max_recoveries` | int | 1–10 | 3 |
| `vault.rekey_threshold` | int | ≥ 1000 | 16777216 |
| `vault.argon2.time_cost` | int | 1–10 | 3 |
| `vault.argon2.memory_cost` | int | 16384–1048576 | 65536 |
| `vault.argon2.parallelism` | int | 1–8 | 1 |
| `thread_context.budget_pct` | float | 0.05–0.50 | 0.20 |
| `thread_context.decay_window_sessions` | int | 1–20 | 3 |
| `thread_context.compaction_interval` | int | 3–20 | 5 |
| `redaction_mode` | string | "off" \| "dry-run" \| "on" | "off" |
| `context_windows.*` | int | 1–50 | (per-detector defaults above) |
| `detectors.*.enabled` | bool | — | true |

### Relationship Constraints

- `thresholds.tier1_block` must be strictly less than `thresholds.auto_redact`
- `thresholds.suppression_floor` must be strictly less than `thresholds.tier1_block`
- If `redaction_mode` is `"on"` and vault is not initialized, hard fail: `✗ Redaction mode is "on" but no vault found. Run: darmok --vault-init`

### Precedence for Neech

When Neech imports Darmok as a library, it passes a config dict to the pipeline constructor. This dict follows the same schema. If Neech passes overrides, they take precedence over the config file. If Neech passes nothing, the file defaults apply.

```python
from darmok.pipeline import Pipeline

# Use file defaults
pipeline = Pipeline()

# Override specific values
pipeline = Pipeline(config_overrides={
    "redaction_mode": "dry-run",
    "thresholds": {"auto_redact": 0.90}
})
```

The library never reads `config.yaml` directly when instantiated with overrides — it uses the override dict merged over defaults. This allows Neech to manage its own config UI without filesystem coupling.

---

## Reconstructor — Injection Safety

The reconstructor uses the **per-exchange outbound manifest** as its sole source of truth. Only placeholders that appear in the sanitized prompt going out can be expanded in the response coming back.

Any placeholder-shaped string in the LLM response that was not in the outbound manifest is flagged inline:
```
⚠ [sess_a3f9b2:EMAIL_1] — not in outbound manifest, left unexpanded
```

This closes two attack vectors:
- **Arbitrary vault expansion:** an attacker influencing LLM output cannot cause the reconstructor to emit secrets by referencing arbitrary placeholders.
- **Fabricated placeholder confusion:** placeholder-shaped strings generated by the LLM are immediately flagged as such, not silently passed through.

---

## Phase 1 — CLI Tool: Detection and Redaction

### CLI Interface
```bash
cat prompt.txt | darmok
darmok --input prompt.txt --output clean.txt
darmok --interactive
darmok --dry-run --input prompt.txt
```

Note: `--restore` is Phase 2 only. If invoked in Phase 1, print a clear error and exit non-zero. Do not appear in Phase 1 `--help`.

### Pipeline Stages
1. **Tokenization** — segments input into logical units (sentences, lines, code blocks, key-value pairs).
2. **Pattern Detection** — detectors run per category with regex + heuristics + confidence scoring.
3. **Confidence Scoring** — 0.0–1.0 scale with tier-aware thresholds. See `docs/detector_spec.md` §Confidence Composition Rules.
4. **Entity Registry** — in-memory map for Phase 1. Deduplication within session only. Format: `[sess_a3f9b2:EMAIL_1]`.
5. **Substitution** — single pass, longer matches before shorter. Left-to-right for equal-length non-overlapping matches.
6. **Per-Exchange Manifest** — exact set of outbound placeholders recorded, passed to reconstructor.
7. **Output** — clean text plus post-run summary.

### File Structure
```
darmok/
├── main.py              # CLI entry point
├── pipeline.py          # Orchestrates stages
├── detectors/
│   ├── base.py          # Abstract detector — DetectionResult dataclass lives here
│   ├── api_keys.py      # PrivateKey, JWT, ApiKey detectors
│   ├── urls.py          # UrlCredential detector
│   ├── email.py         # Email detector
│   ├── ip_address.py    # IpAddress detector
│   └── credit_cards.py  # CreditCard detector
├── registry.py          # Entity tracking, placeholder assignment
├── substitutor.py       # Text replacement
├── reconstructor.py     # Manifest-scoped reconstruction
└── config.yaml          # Thresholds, categories, output format
```

`compressor.py` does not exist. Do not create it.

### Interactive Review Flow
Triggered when Tier 1 confidence is 0.50–0.85. Tool stops before sending.

```
┌─ TIER 1 BLOCK ──────────────────────────────────────────────────────┐
│ Detector  : ApiKeyDetector                                          │
│ Match     : sk-ant-api03-abc...                                     │
│ Confidence: 0.71                                                    │
│ Placeholder: [sess_a3f9b2:API_KEY_1]                               │
└─────────────────────────────────────────────────────────────────────┘
  [r] Redact — replace with placeholder
  [s] Skip once — send in plaintext this prompt only
  [a] Always skip — add to allowlist, never flag again
  [p] Page full prompt — view in pager, then return here
  [x] Abort — cancel prompt, send nothing

Action:
```

Always-skip uses SHA-256 hash of raw value stored in vault — never the raw value itself.

### Post-Run Summary
```
✓ Sanitization complete
  Tier 1 — 2 redacted (1 API key, 1 URL credential)
  Tier 2 — 3 redacted (2 emails, 1 IP address)
  Tier 3 — 0 flagged
  Session: sess_a3f9b2

  Note: redaction covers recognized structured secrets only.
  Unstructured content is not in scope.
```

### Phase 1 Complete When
All of the following are independently true:
1. Per-detector benchmarks pass their tier targets in isolation.
2. Full-pipeline benchmark passes with overlap resolution active — this is the exit gate, not per-detector results.
3. Red-team exercise complete against `.env`, Terraform, K8s manifest, CI/CD YAML with Faker-generated values.
4. Interactive review flow functional end-to-end including all four actions and post-run summary.
5. All documented adversarial out-of-scope patterns produce zero false positives.
6. Benchmark suite established as the baseline for all future changes.
7. No compressor.

---

## Phase 2 — Encrypted Vault and Session Management

### Encryption Architecture
- **Key Derivation:** Argon2id via `argon2-cffi`. Parameters: `time_cost=3`, `memory_cost=65536`, `parallelism=1`. Fixed at vault creation — changing requires migration (triggers F-06).
- **Encryption:** AES-256-GCM. Unique random 96-bit nonce per operation.
- **Re-keying threshold:** `encryption_op_count` reaches 2^24 → hard block on writes, prompt re-key (F-10).
- **Key lifecycle:** `bytearray` from derivation. Never `bytes` or `str`. `mlock` on Linux immediately after derivation. Zero with `ctypes` at session end. See F-08 for failure mode.
- **Salt:** stored in `vault.salt` (permissions 600). Required for key derivation — losing it makes the vault permanently unreadable (F-09).

### Session Design
- Cryptographically random session IDs.
- **Expiry types:** `hard` (default) — entries overwritten on expiry, unrecoverable. `soft` (opt-in) — entries flagged but recoverable up to 3 times with passphrase.
- Default expiry: 4 hours, configurable.
- Expiry clock pauses during interactive review.

### Vault File Layout
```
~/.darmok/
├── vault.db          # Encrypted SQLite (permissions 600)
├── vault.salt        # Key derivation salt (permissions 600)
├── sessions.json     # Session metadata index (permissions 600)
└── config.yaml
```

### CLI Commands Added in Phase 2
```bash
darmok --session-start "project-name" --input prompt.txt
darmok --session-resume sess_a3f9b2
darmok --sessions
darmok --restore --session sess_a3f9b2 --input response.txt
darmok --session-end sess_a3f9b2
darmok --audit sess_a3f9b2
darmok --vault-purge-expired
darmok --vault-compact
darmok --vault-rekey
darmok --allowlist
darmok --allowlist-remove <id>
```

### Passphrase Input
Always read interactively from `/dev/tty`. Never from stdin or positional argument. `--passphrase-env VAR_NAME` available as explicit opt-in for CI/CD with a security warning printed at runtime.

### Vault Failure Modes
All 13 failure scenarios specified in `docs/vault_failure_modes.md`. Design principle: the vault never silently degrades into an unprotected state.

### Three Parallel Log Records
1. **Sanitized log** — exactly what the LLM saw. For debugging and audit.
2. **Reconstructed log** — full conversation with real values restored. Encrypted in vault. 90-day default retention.
3. **Annotated log** — generated on demand. Shows both placeholder and real value inline. Not persisted.

### Phase 2 Complete When
Session close and reopen results in perfect reconstruction. Encryption round-trips cleanly. All 13 vault failure mode tests pass. Session expiry and key zeroing behave correctly under deliberate failure conditions. Schema versioning present and enforced.

---

## Library API (for Neech Integration)

Darmok exposes its core functionality as importable Python modules. The CLI is a thin wrapper over this library. Neech imports the library directly — it does not shell out to the CLI.

Key importable surfaces:
- `darmok.pipeline.Pipeline` — full detection + substitution pipeline
- `darmok.registry.EntityRegistry` — entity tracking and placeholder assignment
- `darmok.reconstructor.Reconstructor` — manifest-scoped reconstruction
- `darmok.vault.Vault` — encrypted vault open/read/write/close
- `darmok.detectors.*` — individual detectors, each implementing `detect(text: str) -> list[DetectionResult]`

The library API must be stable before Neech Phase 1 begins. Breaking changes to the library API require coordination with Neech development.

---

## Key Decisions

- Hybrid detection pipeline — not pure regex, not pure ML, not LLM-based
- Local LLM inappropriate for detection — belongs in Neech Phase 5
- Argon2id over PBKDF2
- AES-256-GCM — authenticated encryption
- Tiered recall targets, all must pass independently
- No compression — removed, not deferred
- Reconstructor uses per-exchange outbound manifest only
- Entity registry: global value-to-placeholder map, session-scoped format, same value always same placeholder
- Entity placeholders not stored in `sessions.json` — vault only
- Passphrase from `/dev/tty`, never stdin
- Three parallel log records for human readability
- SQLite for vault storage
- Schema versioning from Phase 2, enforced on session resumption
- Detection event logs sanitize context windows to the same standard as outbound prompts
- Darmok is both a CLI and a library — Neech consumes the library directly
- Presidio (Microsoft) and LLM Guard (Protect AI) evaluated as alternative detection engines — building custom detectors for Phase 1 to maintain full control over tiered confidence model and DevOps-specific patterns. May revisit for Tier 2/3 categories (email, IP, credit card) if custom benchmarks stall.

---

## Open Questions

- Detector update distribution: how do users get new detection patterns without a full binary upgrade?
- Allowlist portability: does the allowlist travel with vault export/import?
