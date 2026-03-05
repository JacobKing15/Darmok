"""
Darmok CLI — privacy firewall for LLM prompts.

Phase 1 usage (detection and redaction):
    cat prompt.txt | darmok
    darmok --input prompt.txt --output clean.txt
    darmok --interactive
    darmok --dry-run --input prompt.txt

Phase 2 usage (vault and session management):
    darmok --vault-init
    darmok --session-start "project-name" --input prompt.txt
    darmok --session-resume sess_a3f9b2 --input prompt.txt
    darmok --restore --session sess_a3f9b2 --input response.txt
    darmok --sessions
    darmok --session-end sess_a3f9b2
    darmok --audit sess_a3f9b2
    darmok --vault-purge-expired
    darmok --vault-compact
    darmok --vault-rekey
    darmok --allowlist
    darmok --allowlist-remove <id>
    darmok --vault-reinitialize
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pydoc
import sys
from collections import Counter
from typing import IO, Callable

from darmok.config import DarmokConfig
from darmok.detectors.base import DetectionResult
from darmok.pipeline import Pipeline
from darmok.substitutor import Substitutor

AUTO_REDACT_THRESHOLD = 0.85
TIER1_BLOCK_THRESHOLD = 0.50

_CATEGORY_DISPLAY: dict[str, str] = {
    "private_key":    "private key",
    "jwt":            "JWT",
    "api_key":        "API key",
    "url_credential": "URL credential",
    "email":          "email",
    "ip_address":     "IP address",
    "credit_card":    "credit card",
}

_BOX_WIDTH = 70


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _print_review_box(
    result: DetectionResult,
    file: IO[str] = sys.stderr,
) -> None:
    """Print the TIER 1 BLOCK interactive review box."""
    inner = _BOX_WIDTH - 2
    label_w = inner - 14

    def _row(label: str, value: str) -> str:
        truncated = value[:label_w]
        return f"│ {label:<11}: {truncated:<{label_w}}│"

    conf_str = f"{result.confidence:.2f}"
    ph_str = result.placeholder or "(pending)"

    lines = [
        "┌─ TIER 1 BLOCK " + "─" * (inner - 16) + "┐",
        _row("Detector", result.detector),
        _row("Match", result.raw_value),
        _row("Confidence", conf_str),
        _row("Placeholder", ph_str),
        "└" + "─" * inner + "┘",
    ]
    for line in lines:
        print(line, file=file)
    print("  [r] Redact — replace with placeholder", file=file)
    print("  [s] Skip once — send in plaintext this prompt only", file=file)
    print("  [a] Always skip — add to allowlist, never flag again", file=file)
    print("  [p] Page full prompt — view in pager, then return here", file=file)
    print("  [x] Abort — cancel prompt, send nothing", file=file)


def _run_review(
    result: DetectionResult,
    full_text: str,
    allowlist: set[str],
    input_fn: Callable[[], str],
    output: IO[str] = sys.stderr,
) -> str:
    """
    Interactive review for one Tier 1 entity.

    Returns: 'r' (redact), 's' (skip once), 'a' (always skip), 'x' (abort).
    """
    if _sha256(result.raw_value) in allowlist:
        return "s"

    _print_review_box(result, file=output)

    while True:
        try:
            action = input_fn().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "x"

        if action == "p":
            pydoc.pager(full_text)
            _print_review_box(result, file=output)
        elif action in ("r", "s", "a", "x"):
            return action
        else:
            print("  Invalid action. Enter r, s, a, p, or x.", file=output)


def _print_summary(
    redacted: list[DetectionResult],
    session_id: str,
    dry_run: bool = False,
    file: IO[str] = sys.stderr,
) -> None:
    """Print the post-run summary."""
    tier_cats: dict[int, Counter[str]] = {1: Counter(), 2: Counter(), 3: Counter()}
    for r in redacted:
        display = _CATEGORY_DISPLAY.get(r.category, r.category)
        tier_cats[r.tier][display] += 1

    def _fmt_line(tier: int) -> str:
        cat_counter = tier_cats[tier]
        total = sum(cat_counter.values())
        verb = "flagged" if tier == 3 else "redacted"
        if total == 0:
            return f"  Tier {tier} — 0 {verb}"
        parts = [f"{v} {k}{'s' if v > 1 else ''}" for k, v in cat_counter.items()]
        return f"  Tier {tier} — {total} {verb} ({', '.join(parts)})"

    prefix = "[DRY RUN] " if dry_run else ""
    print(f"\n{prefix}✓ Sanitization complete", file=file)
    print(_fmt_line(1), file=file)
    print(_fmt_line(2), file=file)
    print(_fmt_line(3), file=file)
    print(f"  Session: {session_id}", file=file)
    print(file=file)
    print("  Note: redaction covers recognized structured secrets only.", file=file)
    print("  Unstructured content is not in scope.", file=file)


# ── Core sanitization function (library-consumable) ───────────────────────────


def sanitize_interactive(
    text: str,
    pipeline: Pipeline,
    dry_run: bool = False,
    input_fn: Callable[[], str] | None = None,
    stderr: IO[str] = sys.stderr,
    stdout: IO[str] = sys.stdout,
) -> tuple[str, dict[str, str]]:
    """
    Run the sanitization pipeline, including interactive Tier 1 review.

    Returns (sanitized_text, outbound_manifest).
    On abort ([x] action): raises SystemExit(1).
    """
    if input_fn is None:
        input_fn = input

    candidates = pipeline.detect_candidates(text, min_confidence=TIER1_BLOCK_THRESHOLD)

    auto_redact = [r for r in candidates if r.confidence >= AUTO_REDACT_THRESHOLD]
    tier1_review = [
        r for r in candidates
        if r.tier == 1
        and TIER1_BLOCK_THRESHOLD <= r.confidence < AUTO_REDACT_THRESHOLD
    ]

    allowlist: set[str] = set()

    to_redact = list(auto_redact)
    for result in tier1_review:
        action = _run_review(result, text, allowlist, input_fn=input_fn, output=stderr)
        if action == "x":
            print("\nAborted. Nothing sent.", file=stderr)
            raise SystemExit(1)
        elif action == "r":
            to_redact.append(result)
        elif action == "a":
            allowlist.add(_sha256(result.raw_value))

    session_id = pipeline.session_id

    if dry_run:
        _print_summary(to_redact, session_id, dry_run=True, file=stderr)
        return text, {}

    if not to_redact:
        _print_summary([], session_id, file=stderr)
        return text, {}

    for r in to_redact:
        r.placeholder = pipeline._registry.register(r.raw_value, r.category)

    substitutor = Substitutor()
    sanitized, _ = substitutor.substitute(text, to_redact)
    manifest: dict[str, str] = {r.placeholder: r.raw_value for r in to_redact}  # type: ignore[index]

    _print_summary(to_redact, session_id, file=stderr)
    return sanitized, manifest


# ── Phase 2 vault helpers ─────────────────────────────────────────────────────


def _open_vault(config: DarmokConfig, passphrase_env: str | None = None):
    """
    Open the vault and return it.

    passphrase_env: name of env var to read passphrase from (--passphrase-env).
    When None, vault.open() will prompt via getpass.
    """
    from darmok.vault import Vault, VaultError
    vault = Vault(config)
    pp: str | None = None
    if passphrase_env:
        import os
        pp = os.environ.get(passphrase_env)
        if pp is None:
            print(
                f"✗ --passphrase-env: environment variable {passphrase_env!r} is not set.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            f"\n⚠ Reading passphrase from environment variable {passphrase_env!r}.\n"
            f"  This is less secure than interactive input — use only in CI/CD pipelines.\n",
            file=sys.stderr,
        )
    try:
        vault.open(pp)
    except VaultError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    return vault


# ── CLI entry point ────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="darmok",
        description="Privacy firewall for LLM prompts — detects and redacts structured secrets.",
    )

    # ── Input / output ────────────────────────────────────────────────────────
    parser.add_argument("--input",  "-i", metavar="FILE", help="Input file (default: stdin)")
    parser.add_argument("--output", "-o", metavar="FILE", help="Output file (default: stdout)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be redacted without modifying output")
    parser.add_argument("--interactive", action="store_true",
                        help="Read input interactively from terminal (Ctrl-D to finish)")

    # ── Config ────────────────────────────────────────────────────────────────
    parser.add_argument("--config", metavar="FILE",
                        help="Override config file path (default: ~/.darmok/config.yaml)")
    parser.add_argument("--passphrase-env", metavar="VAR",
                        help="Read vault passphrase from env var (CI/CD use; prints warning)")

    # ── Phase 2: session commands ─────────────────────────────────────────────
    parser.add_argument("--session-start", metavar="NAME",
                        help="Start a new named session")
    parser.add_argument("--session-resume", metavar="ID",
                        help="Resume an existing session")
    parser.add_argument("--session-end", metavar="ID",
                        help="End a session")
    parser.add_argument("--session", metavar="ID",
                        help="Session ID (used with --restore and --audit)")
    parser.add_argument("--sessions", action="store_true",
                        help="List all sessions")

    # ── Phase 2: restore / audit ──────────────────────────────────────────────
    parser.add_argument("--restore", action="store_true",
                        help="Reconstruct LLM response using vault (requires --session)")
    parser.add_argument("--audit", metavar="ID",
                        help="Show session audit summary")

    # ── Phase 2: vault management ─────────────────────────────────────────────
    parser.add_argument("--vault-init", action="store_true",
                        help="Initialize the vault (prompts for passphrase)")
    parser.add_argument("--vault-reinitialize", action="store_true",
                        help="Destroy and recreate the vault (with confirmation)")
    parser.add_argument("--vault-purge-expired", action="store_true",
                        help="Purge all hard-expired sessions from the vault")
    parser.add_argument("--vault-compact", action="store_true",
                        help="Run VACUUM on vault to reclaim disk space")
    parser.add_argument("--vault-rekey", action="store_true",
                        help="Re-key vault with a new passphrase")

    # ── Phase 2: allowlist ────────────────────────────────────────────────────
    parser.add_argument("--allowlist", action="store_true",
                        help="List current allowlist entries")
    parser.add_argument("--allowlist-remove", metavar="ID", type=int,
                        help="Remove an entry from the allowlist by ID")

    args = parser.parse_args(argv)

    # ── Load config ────────────────────────────────────────────────────────────
    config = DarmokConfig.load(path=args.config)
    pp_env = args.passphrase_env

    # ── --vault-init ──────────────────────────────────────────────────────────
    if args.vault_init:
        from darmok.vault import Vault
        vault = Vault(config)
        vault.open(None if pp_env is None else os.environ.get(pp_env))
        vault.close()
        print(f"✓ Vault initialized at {config.vault_path}", file=sys.stderr)
        return

    # ── --vault-reinitialize ──────────────────────────────────────────────────
    if args.vault_reinitialize:
        try:
            confirm = input(
                "WARNING: This will permanently destroy all vault data.\n"
                "Type 'yes' to confirm: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            confirm = ""
        if confirm != "yes":
            print("Aborted.", file=sys.stderr)
            sys.exit(0)
        from darmok.vault import Vault
        vault = Vault(config)
        vault.reinitialize()
        print("✓ Vault reinitialized.", file=sys.stderr)
        return

    # ── --vault-purge-expired ─────────────────────────────────────────────────
    if args.vault_purge_expired:
        vault = _open_vault(config, pp_env)
        count = vault.purge_expired()
        vault.close()
        print(f"✓ Purged {count} expired session(s).", file=sys.stderr)
        return

    # ── --vault-compact ───────────────────────────────────────────────────────
    if args.vault_compact:
        vault = _open_vault(config, pp_env)
        vault.compact()
        vault.close()
        print("✓ Vault compacted.", file=sys.stderr)
        return

    # ── --vault-rekey ─────────────────────────────────────────────────────────
    if args.vault_rekey:
        vault = _open_vault(config, pp_env)
        try:
            vault.rekey()
            vault.close()
            print("✓ Vault re-keyed successfully.", file=sys.stderr)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        return

    # ── --sessions ────────────────────────────────────────────────────────────
    if args.sessions:
        from darmok.session import SessionManager
        sm = SessionManager(config)
        sessions = sm.list_sessions()
        if not sessions:
            print("No sessions found.", file=sys.stderr)
            return
        print(f"{'ID':<10}  {'Name':<30}  {'Expires':<20}  {'Type':<6}  Status",
              file=sys.stderr)
        print("-" * 80, file=sys.stderr)
        for s in sessions:
            status = "ended" if s.ended else ("expired" if s.is_expired() else "active")
            print(
                f"{s.session_id:<10}  {s.name:<30}  {s.expires_at[:16]:<20}  "
                f"{s.expiry_type:<6}  {status}",
                file=sys.stderr,
            )
        return

    # ── --session-end ─────────────────────────────────────────────────────────
    if args.session_end:
        from darmok.session import SessionManager
        sm = SessionManager(config)
        sm.end(args.session_end)
        print(f"✓ Session {args.session_end} ended.", file=sys.stderr)
        return

    # ── --audit ───────────────────────────────────────────────────────────────
    if args.audit:
        vault = _open_vault(config, pp_env)
        result = vault.audit(args.audit)
        vault.close()
        print(f"Session: {result['session_id']}", file=sys.stderr)
        print(f"Entities: {result['entity_count']}", file=sys.stderr)
        for e in result["entities"]:
            print(
                f"  {e['placeholder']:<45}  {e['category']:<15}  "
                f"expires={e['expires_at'][:16]}  type={e['expiry_type']}",
                file=sys.stderr,
            )
        return

    # ── --allowlist ───────────────────────────────────────────────────────────
    if args.allowlist:
        vault = _open_vault(config, pp_env)
        entries = vault.list_allowlist()
        vault.close()
        if not entries:
            print("Allowlist is empty.", file=sys.stderr)
            return
        print(f"{'ID':<6}  {'Hash (SHA-256)':<66}  Created", file=sys.stderr)
        print("-" * 100, file=sys.stderr)
        for e in entries:
            print(f"{e['id']:<6}  {e['value_hash']:<66}  {e['created_at']}", file=sys.stderr)
        return

    # ── --allowlist-remove ────────────────────────────────────────────────────
    if args.allowlist_remove is not None:
        vault = _open_vault(config, pp_env)
        removed = vault.remove_from_allowlist(args.allowlist_remove)
        vault.close()
        if removed:
            print(f"✓ Allowlist entry {args.allowlist_remove} removed.", file=sys.stderr)
        else:
            print(f"✗ Allowlist entry {args.allowlist_remove} not found.", file=sys.stderr)
            sys.exit(1)
        return

    # ── --restore ─────────────────────────────────────────────────────────────
    if args.restore:
        if not args.session:
            print("✗ --restore requires --session <session_id>", file=sys.stderr)
            sys.exit(1)

        # Read input (LLM response text)
        if args.input:
            try:
                with open(args.input, encoding="utf-8") as f:
                    response_text = f.read()
            except FileNotFoundError:
                print(f"✗ Input file not found: {args.input}", file=sys.stderr)
                sys.exit(1)
        else:
            response_text = sys.stdin.read()

        vault = _open_vault(config, pp_env)
        try:
            from darmok.reconstructor import Reconstructor
            # Build manifest from vault for this session
            audit = vault.audit(args.session)
            manifest: dict[str, str] = {}
            for entity in audit["entities"]:
                ph = entity["placeholder"]
                raw = vault.get_entity(ph)
                if raw is not None:
                    manifest[ph] = raw

            rec = Reconstructor()
            reconstructed = rec.reconstruct(response_text, manifest)
        finally:
            vault.close()

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(reconstructed)
        else:
            sys.stdout.write(reconstructed)
        return

    # ── --session-start / --session-resume → sanitization with vault ──────────
    vault_instance = None
    session_meta = None

    if args.session_start or args.session_resume:
        from darmok.session import SessionManager, SessionError
        from darmok.vault import Vault

        sm = SessionManager(config)
        vault_instance = _open_vault(config, pp_env)

        if args.session_start:
            session_meta = sm.start(name=args.session_start)
        else:
            try:
                session_meta = sm.resume(args.session_resume)
            except SessionError as exc:
                vault_instance.close()
                print(str(exc), file=sys.stderr)
                sys.exit(1)

    # ── Read input ────────────────────────────────────────────────────────────
    if args.interactive:
        print("Enter your prompt (Ctrl-D to finish):", file=sys.stderr)
        text = sys.stdin.read()
    elif args.input:
        try:
            with open(args.input, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            print(f"✗ Input file not found: {args.input}", file=sys.stderr)
            if vault_instance:
                vault_instance.close()
            sys.exit(1)
    else:
        text = sys.stdin.read()

    # ── Build pipeline ────────────────────────────────────────────────────────
    if vault_instance and session_meta:
        from datetime import datetime, timedelta, timezone
        expires_at = session_meta.expires_at
        pipeline = Pipeline(
            vault=vault_instance,
            session_id=session_meta.session_id,
            expires_at=expires_at,
            expiry_type=session_meta.expiry_type,
        )
    else:
        pipeline = Pipeline()

    try:
        sanitized, _ = sanitize_interactive(text, pipeline, dry_run=args.dry_run)
    finally:
        if vault_instance:
            vault_instance.close()

    # ── Write output ──────────────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(sanitized)
    else:
        sys.stdout.write(sanitized)


if __name__ == "__main__":
    main()
