"""
Darmok config loader — reads ~/.darmok/config.yaml (or DARMOK_CONFIG env var).

Loading rules (DARMOK_PROJECT_CONTEXT.md §Config File §Loading Rules):
  1. Location: ~/.darmok/config.yaml; overridable via DARMOK_CONFIG env var or --config flag.
  2. Missing file: create with defaults; log INFO.
  3. Missing key: use default, no error.
  4. Unknown key: WARN and ignore.
  5. Invalid value type: hard fail with exact message.
  6. Invalid value range: hard fail with exact message.
  7. Permissions check (Unix/Mac): warn if not 600.

Neech override pattern:
    from darmok.config import DarmokConfig
    cfg = DarmokConfig.load(overrides={"redaction_mode": "dry-run"})

When overrides are provided directly, config.yaml is still read (overrides
take precedence over file values). If the file is absent, defaults apply.
"""

from __future__ import annotations

import logging
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ── Defaults ─────────────────────────────────────────────────────────────────

_DEFAULTS: dict[str, Any] = {
    "thresholds": {
        "auto_redact": 0.85,
        "tier1_block": 0.50,
        "log_floor": 0.0,
        "suppression_floor": 0.20,
    },
    "detectors": {
        "api_key":        {"enabled": True},
        "jwt":            {"enabled": True},
        "private_key":    {"enabled": True},
        "url_credential": {"enabled": True},
        "email":          {"enabled": True},
        "ip_address":     {"enabled": True},
        "credit_card":    {"enabled": True},
    },
    "context_windows": {
        "api_key":        10,
        "jwt":            10,
        "private_key":    5,
        "url_credential": 5,
        "email":          10,
        "ip_address":     15,
        "credit_card":    10,
    },
    "registry": {
        "placeholder_format": "sess_{session_id}:{CATEGORY}_{index}",
    },
    "vault": {
        "path":                       "~/.darmok/vault.db",
        "salt_path":                  "~/.darmok/vault.salt",
        "default_expiry_hours":       4,
        "default_expiry_type":        "hard",
        "soft_expiry_max_recoveries": 3,
        "rekey_threshold":            16777216,
        "argon2": {
            "time_cost":   3,
            "memory_cost": 65536,
            "parallelism": 1,
        },
    },
    "session": {
        "schema_version":      "1.2",
        "sessions_json_path":  "~/.darmok/sessions.json",
    },
    "thread_context": {
        "budget_pct":               0.20,
        "decay_window_sessions":    3,
        "compaction_interval":      5,
    },
    "warnings": {
        "permission_check":   True,
        "warn_vault_in_cloud": True,
    },
    "output": {
        "show_post_run_summary": True,
        "show_tier_breakdown":   True,
        "log_path":              "~/.darmok/error.log",
    },
    "redaction_mode": "off",
}

# ── Validation spec ──────────────────────────────────────────────────────────

def _hard_fail(msg: str) -> None:
    """Print a hard-fail message and exit non-zero."""
    print(f"✗ {msg}", file=sys.stderr)
    raise SystemExit(1)


def _expect_type(key: str, value: Any, expected_type: type, type_name: str) -> None:
    if not isinstance(value, expected_type):
        actual = type(value).__name__
        _hard_fail(f"config.yaml: {key} expected {type_name}, got {actual} {value!r}")


def _expect_float_range(key: str, value: float, lo: float, hi: float) -> None:
    if not (lo <= value <= hi):
        _hard_fail(f"config.yaml: {key} must be between {lo} and {hi}, got {value}")


def _expect_int_range(key: str, value: int, lo: int, hi: int) -> None:
    if not (lo <= value <= hi):
        _hard_fail(f"config.yaml: {key} must be between {lo} and {hi}, got {value}")


def _expect_choices(key: str, value: Any, choices: tuple[str, ...]) -> None:
    if value not in choices:
        _hard_fail(
            f"config.yaml: {key} must be one of {list(choices)}, got {value!r}"
        )


# ── Deep merge ────────────────────────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into a copy of base. override wins on conflict."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# ── Permission check ──────────────────────────────────────────────────────────

def _check_permissions(path: Path, label: str) -> None:
    """Warn if path exists and is not mode 600 (Unix/Mac only)."""
    if platform.system() == "Windows":
        return
    if not path.exists():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        octal = oct(mode)[2:]
        print(
            f"\n⚠ Security warning: {label} has permissions {octal} (expected 600).\n"
            f"\n  Other users on this system may be able to read your {label} file."
            f"\n  The vault is still encrypted, but this is not the recommended configuration."
            f"\n\n  To fix: chmod 600 {path}"
            f"\n\n  Continuing. To suppress this warning: set permission_check: false in config.yaml\n",
            file=sys.stderr,
        )
        logger.warning("permission_check %s mode=%s expected=600", label, octal)


# ── Default YAML content ──────────────────────────────────────────────────────

_DEFAULT_YAML = """\
# ─── Detection Thresholds ────────────────────────────────────────────────────
thresholds:
  auto_redact: 0.85
  tier1_block: 0.50
  log_floor: 0.0
  suppression_floor: 0.20

# ─── Detector-Specific Overrides ─────────────────────────────────────────────
detectors:
  api_key:
    enabled: true
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

# ─── Context Windows ──────────────────────────────────────────────────────────
context_windows:
  api_key: 10
  jwt: 10
  private_key: 5
  url_credential: 5
  email: 10
  ip_address: 15
  credit_card: 10

# ─── Entity Registry ──────────────────────────────────────────────────────────
registry:
  placeholder_format: "sess_{session_id}:{CATEGORY}_{index}"

# ─── Vault ────────────────────────────────────────────────────────────────────
vault:
  path: "~/.darmok/vault.db"
  salt_path: "~/.darmok/vault.salt"
  default_expiry_hours: 4
  default_expiry_type: "hard"
  soft_expiry_max_recoveries: 3
  rekey_threshold: 16777216
  argon2:
    time_cost: 3
    memory_cost: 65536
    parallelism: 1

# ─── Session ──────────────────────────────────────────────────────────────────
session:
  schema_version: "1.2"
  sessions_json_path: "~/.darmok/sessions.json"

# ─── Thread Context ───────────────────────────────────────────────────────────
thread_context:
  budget_pct: 0.20
  decay_window_sessions: 3
  compaction_interval: 5

# ─── Warnings and Checks ─────────────────────────────────────────────────────
warnings:
  permission_check: true
  warn_vault_in_cloud: true

# ─── Output ───────────────────────────────────────────────────────────────────
output:
  show_post_run_summary: true
  show_tier_breakdown: true
  log_path: "~/.darmok/error.log"

# ─── Redaction Mode ───────────────────────────────────────────────────────────
redaction_mode: "off"
"""


# ── DarmokConfig ─────────────────────────────────────────────────────────────

class DarmokConfig:
    """
    Validated runtime configuration for Darmok.

    Usage:
        cfg = DarmokConfig.load()                      # file defaults
        cfg = DarmokConfig.load(path="/my/config.yaml")
        cfg = DarmokConfig.load(overrides={"redaction_mode": "dry-run"})
        cfg = DarmokConfig.load(overrides={"thresholds": {"auto_redact": 0.90}})
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        self._validate()

    @classmethod
    def load(
        cls,
        path: str | Path | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> "DarmokConfig":
        """
        Load config from file, apply overrides, return validated DarmokConfig.

        path=None → use DARMOK_CONFIG env var, then ~/.darmok/config.yaml.
        """
        resolved_path = cls._resolve_path(path)
        raw = cls._load_file(resolved_path)
        merged = _deep_merge(_DEFAULTS, raw)
        if overrides:
            merged = _deep_merge(merged, overrides)
        return cls(merged)

    # ── Private: path resolution ──────────────────────────────────────────────

    @staticmethod
    def _resolve_path(path: str | Path | None) -> Path:
        if path is not None:
            return Path(path)
        env_path = os.environ.get("DARMOK_CONFIG")
        if env_path:
            return Path(env_path)
        return Path.home() / ".darmok" / "config.yaml"

    @classmethod
    def _load_file(cls, path: Path) -> dict[str, Any]:
        """Load YAML from path, creating default if absent. Returns raw dict."""
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_DEFAULT_YAML, encoding="utf-8")
            if platform.system() != "Windows":
                path.chmod(0o600)
            logger.info("config created at %s with defaults", path)
            print(f"INFO config created at {path} with defaults", file=sys.stderr)
            return {}  # defaults will be applied by caller via _deep_merge

        with path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        if not isinstance(raw, dict):
            _hard_fail(f"config.yaml: expected a YAML mapping at root, got {type(raw).__name__}")

        return raw

    # ── Private: validation ───────────────────────────────────────────────────

    def _validate(self) -> None:
        d = self._data

        # Check for unknown top-level keys
        known_top = set(_DEFAULTS.keys())
        for k in d:
            if k not in known_top:
                logger.warning("config unknown key: %s", k)
                print(f"WARN config unknown key: {k}", file=sys.stderr)

        # thresholds
        t = d.get("thresholds", {})
        ar = t.get("auto_redact", 0.85)
        tb = t.get("tier1_block", 0.50)
        sf = t.get("suppression_floor", 0.20)

        _expect_type("thresholds.auto_redact",     ar, (int, float), "float")
        _expect_type("thresholds.tier1_block",     tb, (int, float), "float")
        _expect_type("thresholds.log_floor",       t.get("log_floor", 0.0), (int, float), "float")
        _expect_type("thresholds.suppression_floor", sf, (int, float), "float")

        _expect_float_range("thresholds.auto_redact",     float(ar), 0.0, 1.0)
        _expect_float_range("thresholds.tier1_block",     float(tb), 0.0, 1.0)
        _expect_float_range("thresholds.suppression_floor", float(sf), 0.0, 1.0)

        # relationship constraints
        if not (float(tb) < float(ar)):
            _hard_fail(
                f"config.yaml: thresholds.tier1_block ({tb}) must be strictly less than "
                f"thresholds.auto_redact ({ar})"
            )
        if not (float(sf) < float(tb)):
            _hard_fail(
                f"config.yaml: thresholds.suppression_floor ({sf}) must be strictly less than "
                f"thresholds.tier1_block ({tb})"
            )

        # vault
        v = d.get("vault", {})
        _expect_type("vault.default_expiry_hours", v.get("default_expiry_hours", 4), int, "int")
        _expect_int_range("vault.default_expiry_hours", v.get("default_expiry_hours", 4), 1, 720)
        _expect_choices("vault.default_expiry_type", v.get("default_expiry_type", "hard"), ("hard", "soft"))
        _expect_type("vault.soft_expiry_max_recoveries", v.get("soft_expiry_max_recoveries", 3), int, "int")
        _expect_int_range("vault.soft_expiry_max_recoveries", v.get("soft_expiry_max_recoveries", 3), 1, 10)
        _expect_type("vault.rekey_threshold", v.get("rekey_threshold", 16777216), int, "int")
        if v.get("rekey_threshold", 16777216) < 1000:
            _hard_fail(f"config.yaml: vault.rekey_threshold must be >= 1000, got {v['rekey_threshold']}")

        a2 = v.get("argon2", {})
        _expect_type("vault.argon2.time_cost",   a2.get("time_cost", 3), int, "int")
        _expect_int_range("vault.argon2.time_cost",   a2.get("time_cost", 3), 1, 10)
        _expect_type("vault.argon2.memory_cost", a2.get("memory_cost", 65536), int, "int")
        _expect_int_range("vault.argon2.memory_cost", a2.get("memory_cost", 65536), 16384, 1048576)
        _expect_type("vault.argon2.parallelism", a2.get("parallelism", 1), int, "int")
        _expect_int_range("vault.argon2.parallelism", a2.get("parallelism", 1), 1, 8)

        # thread_context
        tc = d.get("thread_context", {})
        _expect_type("thread_context.budget_pct", tc.get("budget_pct", 0.20), (int, float), "float")
        _expect_float_range("thread_context.budget_pct", float(tc.get("budget_pct", 0.20)), 0.05, 0.50)
        _expect_type("thread_context.decay_window_sessions", tc.get("decay_window_sessions", 3), int, "int")
        _expect_int_range("thread_context.decay_window_sessions", tc.get("decay_window_sessions", 3), 1, 20)
        _expect_type("thread_context.compaction_interval", tc.get("compaction_interval", 5), int, "int")
        _expect_int_range("thread_context.compaction_interval", tc.get("compaction_interval", 5), 3, 20)

        # context_windows
        cw = d.get("context_windows", {})
        for det_key, val in cw.items():
            _expect_type(f"context_windows.{det_key}", val, int, "int")
            _expect_int_range(f"context_windows.{det_key}", val, 1, 50)

        # detectors
        dets = d.get("detectors", {})
        for det_key, det_cfg in dets.items():
            if isinstance(det_cfg, dict):
                if "enabled" in det_cfg:
                    _expect_type(f"detectors.{det_key}.enabled", det_cfg["enabled"], bool, "bool")

        # redaction_mode
        _expect_choices("redaction_mode", d.get("redaction_mode", "off"), ("off", "dry-run", "on"))

    # ── Public properties ─────────────────────────────────────────────────────

    @property
    def auto_redact_threshold(self) -> float:
        return float(self._data["thresholds"]["auto_redact"])

    @property
    def tier1_block_threshold(self) -> float:
        return float(self._data["thresholds"]["tier1_block"])

    @property
    def log_floor(self) -> float:
        return float(self._data["thresholds"]["log_floor"])

    @property
    def suppression_floor(self) -> float:
        return float(self._data["thresholds"]["suppression_floor"])

    @property
    def vault_path(self) -> Path:
        return Path(self._data["vault"]["path"]).expanduser()

    @property
    def salt_path(self) -> Path:
        return Path(self._data["vault"]["salt_path"]).expanduser()

    @property
    def default_expiry_hours(self) -> int:
        return int(self._data["vault"]["default_expiry_hours"])

    @property
    def default_expiry_type(self) -> str:
        return str(self._data["vault"]["default_expiry_type"])

    @property
    def soft_expiry_max_recoveries(self) -> int:
        return int(self._data["vault"]["soft_expiry_max_recoveries"])

    @property
    def rekey_threshold(self) -> int:
        return int(self._data["vault"]["rekey_threshold"])

    @property
    def argon2_time_cost(self) -> int:
        return int(self._data["vault"]["argon2"]["time_cost"])

    @property
    def argon2_memory_cost(self) -> int:
        return int(self._data["vault"]["argon2"]["memory_cost"])

    @property
    def argon2_parallelism(self) -> int:
        return int(self._data["vault"]["argon2"]["parallelism"])

    @property
    def schema_version(self) -> str:
        return str(self._data["session"]["schema_version"])

    @property
    def sessions_json_path(self) -> Path:
        return Path(self._data["session"]["sessions_json_path"]).expanduser()

    @property
    def redaction_mode(self) -> str:
        return str(self._data["redaction_mode"])

    @property
    def permission_check(self) -> bool:
        return bool(self._data["warnings"]["permission_check"])

    @property
    def warn_vault_in_cloud(self) -> bool:
        return bool(self._data["warnings"]["warn_vault_in_cloud"])

    @property
    def log_path(self) -> Path:
        return Path(self._data["output"]["log_path"]).expanduser()

    def detector_enabled(self, category: str) -> bool:
        """Return True if detector is enabled (default: True)."""
        dets = self._data.get("detectors", {})
        det = dets.get(category, {})
        if isinstance(det, dict):
            return bool(det.get("enabled", True))
        return True

    def context_window(self, category: str) -> int:
        """Return context window for category, or per-spec default."""
        defaults = {
            "api_key": 10, "jwt": 10, "private_key": 5,
            "url_credential": 5, "email": 10, "ip_address": 15, "credit_card": 10,
        }
        cw = self._data.get("context_windows", {})
        return int(cw.get(category, defaults.get(category, 10)))

    def get(self, key: str, default: Any = None) -> Any:
        """Dotted-key accessor, e.g. get('thresholds.auto_redact')."""
        parts = key.split(".")
        node: Any = self._data
        for p in parts:
            if isinstance(node, dict) and p in node:
                node = node[p]
            else:
                return default
        return node
