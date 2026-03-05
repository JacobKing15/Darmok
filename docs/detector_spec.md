# Detector Specification
**Version:** 2.4
**Last Updated:** 2026-02-28
**Status:** Canonical. All detector implementations build against this document.

**Changelog v2.4:** Phase 1 complete. All 7 detectors implemented and benchmarked: PrivateKey, JWT, ApiKey, UrlCredential, Email, IpAddress, CreditCard — all reach recall=1.000, precision=1.000. Full-pipeline benchmark with overlap resolution passes (Phase 1 exit gate). Red-team suite (.env, Terraform, K8s, GitHub Actions, mixed incident) passes. Interactive review flow (all 5 actions, post-run summary) verified end-to-end. Phase 2 also complete: `darmok/config.py`, `darmok/vault.py`, `darmok/session.py` implemented; all 13 vault failure mode tests pass; registry and pipeline wired to vault and config loader; all Phase 2 CLI commands added. Full suite: 255 pass, 3 skip (Windows chmod), 0 fail.

**Changelog v2.3:** Corrected detector package path in Overview from `sanitizer/detectors/` to `darmok/detectors/` (the `sanitizer/` package is superseded). Test infrastructure now uses snake_case category names throughout (`private_key`, `jwt`, `api_key`, `url_credential`, `email`, `ip_address`, `credit_card`), `d.raw_value` (not `d.value`), tier-aware benchmark harness with `TierResult`/`CATEGORY_TIER`, and 100 negative test cases in the synthetic suite. Standalone benchmark runner: `python benchmark/run.py`. No changes to detection logic, confidence rules, tier targets, or test fixtures.

**Changelog v2.2:** Updated all file paths from `~/.sanitizer/` to `~/.darmok/`. Updated CLI command prefix from `python sanitize.py` to `darmok`. Added redaction mode gate note — detectors only run when session redaction mode is `on` or `dry-run`, not `off`. Added GUI surface notes for interactive review flow. No changes to detection logic, confidence rules, tier targets, or test fixtures.

**Changelog v2.1:** Added DetectionResult data contract, Confidence Composition Rules, Token Definition sections. Renumbered detector headings to match build order (PrivateKey=1, JWT=2, ApiKey=3). Standardized suppression target to 0.20 across all detectors. Resolved `above 0.85` vs `≥ 0.85` threshold contradiction in favor of ≥ 0.85 (inclusive). Added config.yaml reference note to threshold section.

---

## Overview

This document specifies every detector in the Phase 1 pipeline: what it targets, its tier assignment, confidence scoring rules, context disambiguation logic, synthetic test fixtures, edge cases, and explicit out-of-scope declarations.

Detectors are implemented in `darmok/detectors/`. Each inherits from `base.py` and must implement `detect(text: str) -> list[DetectionResult]`.

**Redaction mode gate:** Detectors only run when the session redaction mode is `on` or `dry-run`. When mode is `off`, the pipeline skips detection entirely and passes the prompt through unchanged. This check happens in `pipeline.py` before any detector is invoked — individual detectors do not need to check the mode themselves.

All detectors are tested against the benchmark suite before any Phase 1 code is considered shippable. Tier targets must be met independently — passing an average is not sufficient.

---

## Tier Reference

| Tier | Recall Target | Precision Target | Below auto-redact threshold behavior |
|---|---|---|---|
| 1 | ≥ 0.99 | ≥ 0.90 | Block — require user decision |
| 2 | ≥ 0.95 | ≥ 0.95 | Flag for review |
| 3 | ≥ 0.90 | ≥ 0.95 | Log, leave alone |

Auto-redact threshold: confidence **≥ 0.85** across all tiers (inclusive — a score of exactly 0.85 auto-redacts).
Tier 1 block threshold: confidence ≥ 0.50 and < 0.85.
Below 0.50: log only, no action.

All thresholds are configurable via `config.yaml`. See PROJECT_CONTEXT.md §Config File for the full schema. Detectors must read thresholds from config at runtime — do not hardcode 0.85, 0.50, or any other threshold value.

---

## DetectionResult — Data Contract

Every detector returns `list[DetectionResult]`. This is the sole data contract between detectors, the registry, the substitutor, and the reconstructor. All fields are required at detection time except `placeholder`, which is populated by the registry after detection.

```python
@dataclass
class DetectionResult:
    span: tuple[int, int]    # character offsets in original text: (start_inclusive, end_exclusive)
    raw_value: str           # exact matched string from original text
    category: str            # snake_case label: "api_key", "jwt", "private_key",
                             #   "url_credential", "email", "ip_address", "credit_card"
    tier: int                # 1, 2, or 3
    confidence: float        # 0.0–1.0, see Confidence Composition Rules below
    detector: str            # class name, e.g. "ApiKeyDetector", "EmailDetector"
    placeholder: str | None  # None at detection time; assigned by registry before substitution
```

`span` uses Python slice semantics: `original_text[span[0]:span[1]] == raw_value` must always hold. Any detector that produces a span where this is false has a bug.

`placeholder` must be `None` when the detector returns results. The registry is the only component that sets it. A detector that pre-fills `placeholder` is incorrect.

---

## Confidence Composition Rules

These rules govern how confidence scores are calculated across all detectors. Individual detector tables define base scores; this section defines how boosts, suppressions, and ceilings are applied uniformly.

### Ceiling
Confidence is capped at **1.0**. Boosts are additive up to the cap. A base score of 0.97 with a +0.15 boost yields 1.0, not 1.12.

### Boosts
Boosts are additive and applied after the base score is established. Multiple boosts stack. Example: a Bearer token without header context (base 0.68) in a context containing `api` (+0.15) yields min(0.68 + 0.15, 1.0) = 0.83.

### Suppressions
Suppression rules lower confidence to a fixed floor of **0.20**, regardless of the base score. If multiple suppression conditions apply, the result is still 0.20 — suppressions do not stack below the floor. Suppression overrides boosts: if both a boost condition and a suppression condition apply to the same match, suppression wins and the score is 0.20.

The 0.20 floor is intentional. It means suppressed matches are still logged (anything above 0.0 is logged) but never actioned. A score of 0.0 is reserved for "this is structurally not a match" — suppression is "this looks like a match but context says probably not."

### Threshold boundary
The auto-redact threshold is **≥ 0.85** (inclusive). A score of exactly 0.85 auto-redacts. The Tier 1 block range is confidence ≥ 0.50 and < 0.85. Below 0.50 is log-only.

### Summary table

| Score range | Action |
|---|---|
| ≥ 0.85 | Auto-redact (all tiers) |
| ≥ 0.50 and < 0.85 | Tier 1: block for review; Tier 2: flag for review; Tier 3: log only |
| < 0.50 | Log only, no action (all tiers) |
| 0.20 | Suppressed match floor — logged, never actioned |

---

## Token Definition

Context windows throughout this spec are measured in **tokens**. A token is a contiguous sequence of word characters as matched by `\w+` in Python's `re` module (`[a-zA-Z0-9_]`). Punctuation, operators, whitespace, and symbols are token boundaries but are not themselves tokens.

**Examples:**
- `ANTHROPIC_API_KEY=sk-ant-api03-xxx` → tokens: `ANTHROPIC_API_KEY`, `sk`, `ant`, `api03`, `xxx` (five tokens; `=` and `-` are boundaries)
- `Authorization: Bearer ghp_abc123` → tokens: `Authorization`, `Bearer`, `ghp_abc123` (three tokens; `:` and space are boundaries)
- `for example, imagine 10.0.1.45` → tokens: `for`, `example`, `imagine`, `10`, `0`, `1`, `45` (seven tokens; `.` and `,` are boundaries)

**Window sizes** are intentionally different per detector. ApiKey uses a 10-token window (credentials appear close to their variable name). IpAddress uses a 15-token window (IPs appear in more varied prose contexts where suppression signals may be further away). Do not standardize these without benchmarking the precision impact.

**Context window implementation:** Given a match at character position `[start, end]` in the original text, the context window is computed by tokenizing the full input and finding the token indices bracketing the match span, then taking N tokens to the left and N tokens to the right of the matched span. Tokens that overlap with the match span itself are excluded from the context window.

---

## Interactive Review Flow — GUI Notes

The interactive review flow is triggered for Tier 1 entities detected with confidence ≥ 0.50 and < 0.85. In the CLI, this presents a terminal prompt. In the desktop GUI (Phase 4), this will present a modal dialog with the same five actions (Redact, Skip Once, Always Skip, Page Full Prompt, Abort) and a highlighted context window showing the surrounding text.

The core behavior — block before sending, show context, require explicit user action — is identical in both surfaces. The GUI modal is the Phase 4 implementation of the same logic the CLI implements in Phase 1. The detection results and confidence scores that drive the CLI review flow are the same data that will drive the GUI modal. No changes to detector logic are needed for GUI support.

**Action mapping (CLI → GUI):**
- `[r] Redact` → Redact button (primary)
- `[s] Skip once` → Skip This Message button
- `[a] Always skip` → Never Flag This Value button (with confirmation dialog explaining hash-based storage)
- `[p] Page full prompt` → View Full Message button (opens scrollable preview)
- `[x] Abort` → Cancel button

---

## Detector 1 — Private Keys and Certificates

> **Build order note:** Detector headings are numbered to match the implementation order (PrivateKey → JWT → ApiKey → UrlCredential → Email → IpAddress → CreditCard). Build and benchmark them in this sequence.

**File:** `detectors/api_keys.py`
**Tier:** 1
**Recall target:** ≥ 0.99

### Patterns
PEM block markers are unambiguous:
```
-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
-----BEGIN PUBLIC KEY-----   # lower risk but still flag
```

### Confidence Rules

| Condition | Score |
|---|---|
| Full PEM block (BEGIN + base64 content + END) | 0.99 |
| BEGIN marker only, no END | 0.90 |
| BEGIN marker in a comment or documentation string | 0.85 — still redact |

### Edge Cases

| Case | Expected behavior |
|---|---|
| PEM block in a test fixture with obviously dummy content (`AAAA...`) | Detect and redact — do not trust content appearance |
| Single-line base64 that looks like a PEM body without markers | Out of scope |
| Public key only (no private key) | Detect and flag — treat as Tier 1, user decides |

---

## Detector 2 — JWTs

**File:** `detectors/api_keys.py` (same file as private keys)
**Tier:** 1
**Recall target:** ≥ 0.99

### Pattern
JWTs have a fixed three-segment base64url structure: `eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`

The header segment always begins with `eyJ` (base64url encoding of `{"`) — this is a reliable discriminator.

### Confidence Rules

| Condition | Score |
|---|---|
| Three-segment `eyJ...` pattern, all segments valid base64url | 0.97 |
| Three-segment `eyJ...` pattern, header decodes to valid JSON | 0.99 |
| Pattern matches but header does not decode cleanly | 0.72 |

### Synthetic Test Fixtures
```
# In a config file
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTcwODcyMzQ0NX0.abc123signaturehere

# Pasted into Slack
getting 403 — here's the token we're sending: eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoLXNlcnZpY2UifQ.signature

# Authorization header
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```

### Edge Cases

| Case | Expected behavior |
|---|---|
| JWT in a documentation example with dummy payload | Detect and redact — `eyJ` prefix is unambiguous |
| Truncated JWT (missing third segment) | Confidence 0.55 — block for Tier 1 review |
| JWT embedded in a URL query string | Detect and redact |

---

## Detector 3 — API Keys and Tokens

**File:** `detectors/api_keys.py` (same file)
**Tier:** 1
**Recall target:** ≥ 0.99

### Patterns

| Provider | Prefix Pattern | Example | Notes |
|---|---|---|---|
| Anthropic | `sk-ant-[a-zA-Z0-9\-]{20,}` | `sk-ant-api03-abc123...` | High confidence — prefix is unambiguous |
| OpenAI | `sk-proj-[a-zA-Z0-9]{20,}` | `sk-proj-abc123...` | High confidence |
| OpenAI legacy | `sk-[a-zA-Z0-9]{48}` | `sk-abc123...xyz` | Medium confidence — `sk-` is common |
| GitHub PAT classic | `ghp_[a-zA-Z0-9]{36}` | `ghp_abc123...` | High confidence |
| GitHub PAT fine-grained | `github_pat_[a-zA-Z0-9_]{82}` | `github_pat_abc...` | High confidence |
| GitHub OAuth | `gho_[a-zA-Z0-9]{36}` | `gho_abc123...` | High confidence |
| GitHub Actions | `ghs_[a-zA-Z0-9]{36}` | `ghs_abc123...` | High confidence |
| Bearer tokens | `Bearer [a-zA-Z0-9\-._~+/]{20,}` | `Authorization: Bearer abc...` | Context-dependent |
| Generic high-entropy | Entropy ≥ 4.5, length ≥ 32, no spaces | — | Fallback — medium confidence |

### Confidence Rules

| Condition | Score |
|---|---|
| Known vendor prefix + correct length | 0.97 |
| Known vendor prefix + incorrect length | 0.75 |
| `sk-` prefix without vendor sub-prefix | 0.72 |
| Bearer token in Authorization header context | 0.92 |
| Bearer token without header context | 0.68 |
| High entropy string ≥ 40 chars | 0.70 |
| High entropy string 32–39 chars | 0.60 |
| High entropy string with `key`, `token`, `secret`, `credential` in surrounding 10 tokens | +0.15 boost (see Confidence Composition Rules) |

### Context Disambiguation
- Surrounding context window: 10 tokens either side (see Token Definition)
- Boost confidence if context contains: `key`, `token`, `secret`, `api`, `auth`, `credential`, `bearer`, `authorization`
- Suppress confidence to 0.20 if context contains: `example`, `placeholder`, `redacted`, `dummy`, `fake`, `test`, `TODO`, `your_key_here`
- Suppress confidence to 0.20 if value is a known test fixture: `sk-ant-test`, `ghp_test`, etc.

### Synthetic Test Fixtures

```
# .env file context
ANTHROPIC_API_KEY=sk-ant-api03-xK9mP2qR7nL4vT8wY1zA3bC6dE0fG5hJ
GITHUB_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q

# Terraform variable
variable "github_token" {
  default = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8r"
}

# Code with hardcoded key
client = anthropic.Anthropic(api_key="sk-ant-api03-xK9mP2qR7nL4vT8wY1zA3bC6dE0fG5hJ")

# Slack paste
hey can you check this — getting 401 with sk-ant-api03-xK9mP2qR7nL4vT8wY1zA3bC6dE0fG5hJ

# Authorization header
curl -H "Authorization: Bearer ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8r" https://api.github.com
```

### Edge Cases

| Case | Expected behavior |
|---|---|
| `sk-` followed by a short dictionary word (e.g. `sk-learn`) | Confidence 0.30 — below threshold, log only |
| API key split across two lines with string concatenation | Out of scope — document as known limitation |
| Base64-encoded key | Out of scope — document as known limitation |
| Key in a comment `# formerly: sk-ant-api03-...` | Detect and redact — context suppression only applies to explicit example markers |
| Key in a git diff (`+ANTHROPIC_API_KEY=sk-ant-...`) | Detect and redact |
| Rotated/expired key explicitly labelled (`# old key, revoked`) | Detect and redact — do not trust inline labels |

### Out of Scope (Document, No False Positive Guarantee)
- Keys split across multiple lines without concatenation operator
- Base64 or hex-encoded keys
- Keys embedded in binary file content
- Homoglyph substitution attacks

---

## Detector 4 — URL Credentials

**File:** `detectors/urls.py`
**Tier:** 1
**Recall target:** ≥ 0.99

### Pattern
URLs with embedded credentials follow the format: `scheme://user:password@host`

```
(postgres|postgresql|mysql|mongodb|redis|amqp|ftp|sftp|https?):\/\/[^:@\s]+:[^@\s]+@[^\s]+
```

The password component (after `:` before `@`) is the sensitive element. The full URL including scheme and host is replaced to avoid leaking the host alongside a redacted credential.

### Confidence Rules

| Condition | Score |
|---|---|
| Known DB/service scheme + user:password@host pattern | 0.97 |
| `http://` or `https://` with user:password@host | 0.90 |
| URL with `@` but no `:password` pattern | 0.20 — likely an email in a URL, not a credential |

### Synthetic Test Fixtures
```
# Terraform database config
db_url = "postgres://appuser:s3cr3tP@ssw0rd@db.internal.company.com:5432/production"

# K8s secret
DATABASE_URL: mongodb://admin:hunter2@mongo-cluster.default.svc:27017/appdb

# .env file
REDIS_URL=redis://default:redispassword123@redis.company.com:6379

# Error log paste
connection failed: postgresql://deploy:P@ssw0rd!@10.0.1.45:5432/app_prod
```

### Edge Cases

| Case | Expected behavior |
|---|---|
| `user:password` with placeholder password (`user:password@host`) | Confidence 0.50 — block for review, likely a template |
| `user:@host` (empty password) | Confidence 0.40 — flag, probably a template |
| Git remote URL with token (`https://token@github.com/org/repo`) | Detect and redact — token is the credential |

---

## Detector 5 — Email Addresses

**File:** `detectors/email.py`
**Tier:** 2
**Recall target:** ≥ 0.95

### Pattern
```
[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}
```

### Confidence Rules

| Condition | Score |
|---|---|
| Valid pattern + real TLD + context suggests real communication | 0.92 |
| Valid pattern + real TLD, no strong context signal | 0.80 |
| Valid pattern + domain is a known placeholder (`example.com`, `test.com`, `foo.com`) | 0.25 — below threshold |
| Valid pattern in a code comment or documentation string | 0.55 — flag for review |
| `user@localhost` or `user@127.0.0.1` | 0.30 — log only |

### Context Disambiguation
- Suppress (→ 0.25) if domain is: `example.com`, `example.org`, `test.com`, `foo.com`, `bar.com`, `email.com`, `domain.com`, `yourdomain.com`, `yourcompany.com`
- Suppress if surrounding context contains: `example`, `sample`, `placeholder`, `your_email`, `test`
- Boost if surrounding context contains: `from:`, `to:`, `cc:`, `contact`, `email`, `sent by`, `assigned to`

### Synthetic Test Fixtures
```
# Customer support log
ticket opened by john.smith@acmecorp.com re: billing issue

# Terraform notification config
notification_email = "ops-alerts@company.com"

# Slack paste
@jane.doe@company.com can you look at this?

# Code with hardcoded recipient
send_alert(to="oncall@company.com", subject="disk full")

# K8s config
adminEmail: platform-team@company.internal
```

### Edge Cases

| Case | Expected behavior |
|---|---|
| `admin@example.com` | Confidence 0.25 — log only, known placeholder domain |
| Email in a stack trace (`raised by user@service`) | Detect unless domain matches suppression list |
| Email in a git commit message | Detect and redact |
| Malformed email (`user @domain.com` with space) | No match — correct behavior |

---

## Detector 6 — IP Addresses

**File:** `detectors/ip_address.py`
**Tier:** 2 (real server IPs) / Tier 3 (contextually ambiguous)
**Recall target:** ≥ 0.95 for Tier 2, ≥ 0.90 for Tier 3

### Patterns

**IPv4:**
```
\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
```

**IPv6:**
```
\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b
# Plus compressed forms: ::1, fe80::1, 2001:db8::
```

### Confidence and Tier Assignment

| Condition | Score | Tier |
|---|---|---|
| IP in server config, Terraform, K8s manifest, .env | 0.92 | 2 |
| IP in error log or stack trace | 0.88 | 2 |
| IP in natural language without example markers | 0.75 | 2 |
| IP in natural language with example markers (`e.g.`, `for example`, `such as`, `like`, `imagine`) | 0.30 | 3 |
| IP is a well-known documentation range (`192.0.2.x`, `198.51.100.x`, `203.0.113.x` — RFC 5737) | 0.15 | 3 |
| `127.0.0.1` or `::1` (loopback) | 0.40 | 3 |
| `0.0.0.0` | 0.15 | 3 |
| IP with port in connection string context | +0.10 boost | — |

### Context Disambiguation — Key Rule
Context-aware mode is the default. Suppress to Tier 3 / low confidence when any of these appear within 15 tokens of the IP:

Suppression tokens: `example`, `e.g.`, `for example`, `such as`, `imagine`, `suppose`, `let's say`, `sample`, `placeholder`, `dummy`, `fake`, `test`, `illustration`, `hypothetical`

Do not suppress for: `# example config` comments that appear on a different line from the IP — proximity matters.

### Synthetic Test Fixtures
```
# Terraform
resource "aws_instance" "app" {
  private_ip = "10.0.1.45"
}

# Error log
connection refused: 10.0.1.45:5432 (timeout after 30s)

# K8s manifest
hostIP: 172.16.0.10

# Slack paste
the pod on 10.0.2.33 is OOMKilled again

# Natural language — should suppress
for example, imagine a server at 192.168.1.50 that receives the request

# .env
DB_HOST=10.0.1.45
```

### Edge Cases

| Case | Expected behavior |
|---|---|
| IP in a CIDR block (`10.0.0.0/8`) | Detect the IP portion, leave the `/8` — replace as `[sess_x:IP_1]/8`. Note: host IPs from the same subnet get separate placeholders. Semantic relationship between network and host addresses is a Phase 3 concern. |
| IP range (`10.0.1.1-10.0.1.254`) | Detect both endpoints separately |
| IPv6 loopback `::1` | Confidence 0.40, Tier 3 — log only |
| `255.255.255.255` (broadcast) | Confidence 0.35 — log only |
| IP in a URL (already caught by UrlCredentialDetector) | Deduplicate — UrlCredentialDetector takes priority via longest-span rule |

---

## Detector 7 — Credit Card Numbers

**File:** `detectors/credit_cards.py`
**Tier:** 2
**Recall target:** ≥ 0.95

### Pattern
```
# With separators (spaces or dashes)
\b(?:4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|  # Visa
   5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|  # Mastercard
   3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}|                    # Amex
   6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}  # Discover
)\b
```

All matches must pass Luhn algorithm validation before being flagged.

### Confidence Rules

| Condition | Score |
|---|---|
| Luhn-valid + known card prefix + context suggests payment | 0.95 |
| Luhn-valid + known card prefix, neutral context | 0.85 |
| Luhn-valid + unknown prefix | 0.70 |
| Luhn-valid but surrounded by example/test markers | 0.25 |

### Context Boost
Boost confidence if context contains: `card`, `payment`, `billing`, `charge`, `visa`, `mastercard`, `amex`, `cvv`, `expiry`, `expire`

### Synthetic Test Fixtures
```
# Customer support ticket
customer's card ending in 4532015112830366 was declined

# Config / test data that should NOT fire
test_card = "4111111111111111"   # suppressed by 'test' context

# Slack paste
can you refund 4532-0151-1283-0366? customer says it was charged twice
```

### Edge Cases

| Case | Expected behavior |
|---|---|
| `4111111111111111` (Luhn-valid test card) with `test` in context | Confidence 0.25 — suppress |
| `4111111111111111` without test context | Confidence 0.85 — auto-redact |
| 16-digit number that fails Luhn | No detection |
| Card number split with spaces `4532 0151 1283 0366` | Detect as single entity, replace whole span |

---

## Overlap Resolution

When two detectors match overlapping spans, the following rules apply in order:

1. **Longer span wins** — the match that covers more characters takes precedence
2. **Tier priority breaks ties** — lower tier number (higher risk) wins on equal span length
3. **Explicit beats implicit** — a detector with a known vendor prefix beats a generic entropy detector on equal span

Examples:
- A URL credential containing an IP address: UrlCredentialDetector wins (longer span)
- A JWT that also matches the generic high-entropy pattern: JwtDetector wins (Tier 1, explicit prefix)
- An email inside a URL: EmailDetector and UrlCredentialDetector both checked — longest span wins

---

## Adversarial Coverage Requirements

Each detector must have documented test cases for the following adversarial patterns. Tests must pass (correct behavior documented) before Phase 1 exit.

| Pattern | Detectors affected | Expected behavior |
|---|---|---|
| Base64-encoded credential | ApiKey, JWT | Out of scope — document, no false positive |
| Hex-encoded IP (`0x0a000145` for `10.0.1.69`) | IpAddress | Out of scope — document, no false positive |
| Split API key across two lines | ApiKey | Out of scope — document, no false positive |
| Dot-separated email (`john [dot] smith [at] company [dot] com`) | Email | Out of scope — document, no false positive |
| Unicode homoglyph substitution in a key | ApiKey | Out of scope — document, no false positive |
| Credential in a git diff (`+API_KEY=sk-ant-...`) | ApiKey | In scope — detect and redact |
| Credential in a JSON string with escape sequences | All | In scope — detect after JSON parsing |
| IP in CIDR notation | IpAddress | In scope — detect IP portion only |
| JWT with tampered signature segment | JWT | In scope — detect on header/payload match |
| Credit card with non-standard separator (`.`) | CreditCard | Out of scope — document, no false positive |

---

## Benchmark Dashboard Format

The benchmark suite outputs the following format after each detector implementation:

```
┌─────────────────────────────────────────────────────────────────────┐
│ BENCHMARK RESULTS — 2026-02-28 (Phase 1 Final)                      │
├──────────────┬──────────┬──────────┬──────────┬────────────────────┤
│ TIER SUMMARY │  Recall  │ Target   │ Precision│ Status             │
├──────────────┼──────────┼──────────┼──────────┼────────────────────┤
│ Tier 1       │  1.000   │ ≥ 0.99   │  1.000   │ ✓ PASS             │
│ Tier 2       │  1.000   │ ≥ 0.95   │  1.000   │ ✓ PASS             │
│ Tier 3       │  1.000   │ ≥ 0.90   │  1.000   │ ✓ PASS             │
├──────────────┴──────────┴──────────┴──────────┴────────────────────┤
│ CATEGORY BREAKDOWN                                                  │
├──────────────┬──────────┬──────────┬──────────┬────────────────────┤
│ Detector     │  Recall  │ Target   │ Precision│ Status             │
├──────────────┼──────────┼──────────┼──────────┼────────────────────┤
│ ApiKey/JWT   │  1.000   │ ≥ 0.99   │  1.000   │ ✓ PASS             │
│ PrivateKey   │  1.000   │ ≥ 0.99   │  1.000   │ ✓ PASS             │
│ UrlCredential│  1.000   │ ≥ 0.99   │  1.000   │ ✓ PASS             │
│ Email        │  1.000   │ ≥ 0.95   │  1.000   │ ✓ PASS             │
│ IpAddress    │  1.000   │ ≥ 0.95   │  1.000   │ ✓ PASS             │
│ CreditCard   │  1.000   │ ≥ 0.95   │  1.000   │ ✓ PASS             │
└──────────────┴──────────┴──────────┴──────────┴────────────────────┘
Phase 1 exit criteria: ALL tiers must pass. Current: ✓ ALL PASS
```

---

## Implementation Order

> **Status (2026-02-28): ✓ ALL COMPLETE** — all 7 detectors implemented and benchmarked at recall=1.000, precision=1.000. Phase 1 exit gate (full-pipeline benchmark with overlap resolution) passed.

Build and benchmark one detector at a time. Do not proceed to the next until the current one passes its tier target.

1. `PrivateKey` ✓ — simplest pattern (PEM markers), highest confidence, good calibration baseline
2. `JWT` ✓ — unambiguous `eyJ` prefix, fast to get to 0.99
3. `ApiKey` ✓ — most complex, most important, Anthropic and GitHub formats first
4. `UrlCredential` ✓ — builds on regex foundation, important for DevOps use case
5. `Email` ✓ — introduce context disambiguation logic here
6. `IpAddress` ✓ — most nuanced context rules, build last when disambiguation patterns are proven
7. `CreditCard` ✓ — Luhn validation, lowest real-world frequency in target prompts

**After all seven detectors pass individually:** run the full-pipeline benchmark with overlap resolution active. This is the Phase 1 exit gate.

---

## Synthetic Data Generation Requirements

The benchmark harness generates test prompts using Faker. Coverage requirements per category:

| Prompt type | Min count | Notes |
|---|---|---|
| `.env` file snippets | 50 | Mix of all Tier 1 categories |
| Terraform / K8s manifests | 50 | IPs, URLs, API keys in config context |
| Code with hardcoded credentials | 75 | All detectors, multiple languages |
| Error logs and stack traces | 50 | IPs, emails in realistic log format |
| Natural language / Slack pastes | 75 | All categories, conversational context |
| Adversarial inputs | 30 min | One per documented adversarial pattern |
| Negative examples (no sensitive data) | 100 | Precision testing — nothing should fire |

Synthetic data must not contain real credentials, real email addresses, or real IP addresses from production systems.
