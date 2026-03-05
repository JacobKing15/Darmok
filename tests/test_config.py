"""
Tests for darmok/config.py — DarmokConfig loader.

Covers all 7 loading rules and validation constraints.
"""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

import pytest
import yaml

from darmok.config import DarmokConfig


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_config(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data), encoding="utf-8")


# ── Rule 2: Missing file → create with defaults ───────────────────────────────

def test_missing_file_creates_defaults(tmp_path):
    """Missing config file is created with defaults; properties return defaults."""
    cfg_path = tmp_path / "config.yaml"
    assert not cfg_path.exists()

    cfg = DarmokConfig.load(path=cfg_path)

    assert cfg_path.exists(), "config.yaml should have been created"
    assert cfg.auto_redact_threshold == pytest.approx(0.85)
    assert cfg.tier1_block_threshold == pytest.approx(0.50)
    assert cfg.default_expiry_hours == 4
    assert cfg.redaction_mode == "off"


def test_missing_file_default_values(tmp_path):
    """Verify several defaults when file is absent."""
    cfg = DarmokConfig.load(path=tmp_path / "config.yaml")
    assert cfg.argon2_time_cost == 3
    assert cfg.argon2_memory_cost == 65536
    assert cfg.argon2_parallelism == 1
    assert cfg.default_expiry_type == "hard"
    assert cfg.soft_expiry_max_recoveries == 3
    assert cfg.rekey_threshold == 16777216
    assert cfg.schema_version == "1.2"


# ── Rule 3: Missing key → use default ────────────────────────────────────────

def test_missing_key_uses_default(tmp_path):
    """A key present in the file but not overriding threshold still returns default."""
    cfg_path = tmp_path / "config.yaml"
    # Write a file with only redaction_mode set
    _write_config(cfg_path, {"redaction_mode": "dry-run"})

    cfg = DarmokConfig.load(path=cfg_path)
    assert cfg.auto_redact_threshold == pytest.approx(0.85)  # default
    assert cfg.redaction_mode == "dry-run"


def test_partial_thresholds_use_defaults(tmp_path):
    """Partial thresholds — only auto_redact set, others remain default."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"thresholds": {"auto_redact": 0.90}})

    cfg = DarmokConfig.load(path=cfg_path)
    assert cfg.auto_redact_threshold == pytest.approx(0.90)
    assert cfg.tier1_block_threshold == pytest.approx(0.50)  # default
    assert cfg.suppression_floor == pytest.approx(0.20)      # default


# ── Rule 4: Unknown key → warn and ignore ────────────────────────────────────

def test_unknown_top_level_key_warns_continues(tmp_path, capsys):
    """Unknown top-level key produces WARN message but does not error."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"unknown_future_key": "some_value", "redaction_mode": "off"})

    cfg = DarmokConfig.load(path=cfg_path)
    captured = capsys.readouterr()
    assert "unknown_future_key" in captured.err
    assert cfg.redaction_mode == "off"


# ── Rule 5: Invalid type → hard fail ─────────────────────────────────────────

def test_invalid_type_auto_redact_fails(tmp_path):
    """auto_redact as string → SystemExit with correct message."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"thresholds": {"auto_redact": "high"}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_invalid_type_expiry_hours_fails(tmp_path):
    """default_expiry_hours as string → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"default_expiry_hours": "four"}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_invalid_type_expiry_hours_float_fails(tmp_path):
    """default_expiry_hours as float → SystemExit (must be int)."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"default_expiry_hours": 4.5}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_invalid_type_enabled_fails(tmp_path):
    """detectors.api_key.enabled as string → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"detectors": {"api_key": {"enabled": "yes"}}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


# ── Rule 6: Invalid range → hard fail ────────────────────────────────────────

def test_auto_redact_too_high_fails(tmp_path):
    """auto_redact > 1.0 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"thresholds": {"auto_redact": 1.5}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_auto_redact_too_low_fails(tmp_path):
    """auto_redact < 0.0 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"thresholds": {"auto_redact": -0.1}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_expiry_hours_too_high_fails(tmp_path):
    """default_expiry_hours > 720 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"default_expiry_hours": 721}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_expiry_hours_too_low_fails(tmp_path):
    """default_expiry_hours < 1 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"default_expiry_hours": 0}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_rekey_threshold_too_low_fails(tmp_path):
    """rekey_threshold < 1000 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"rekey_threshold": 500}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_invalid_expiry_type_fails(tmp_path):
    """default_expiry_type not 'hard' or 'soft' → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"default_expiry_type": "never"}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_invalid_redaction_mode_fails(tmp_path):
    """redaction_mode with invalid value → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"redaction_mode": "always"})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_context_window_too_high_fails(tmp_path):
    """context_windows.ip_address > 50 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"context_windows": {"ip_address": 99}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_argon2_time_cost_too_high_fails(tmp_path):
    """argon2.time_cost > 10 → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"vault": {"argon2": {"time_cost": 11}}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


# ── Relationship constraints ──────────────────────────────────────────────────

def test_tier1_block_must_be_less_than_auto_redact(tmp_path):
    """tier1_block >= auto_redact → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    # tier1_block == auto_redact → violation
    _write_config(cfg_path, {"thresholds": {"auto_redact": 0.85, "tier1_block": 0.85}})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


def test_suppression_floor_must_be_less_than_tier1_block(tmp_path):
    """suppression_floor >= tier1_block → SystemExit."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"thresholds": {
        "auto_redact": 0.85,
        "tier1_block": 0.50,
        "suppression_floor": 0.60,
    }})

    with pytest.raises(SystemExit):
        DarmokConfig.load(path=cfg_path)


# ── Neech override pattern ────────────────────────────────────────────────────

def test_neech_override_redaction_mode(tmp_path):
    """Neech can override redaction_mode via dict."""
    cfg_path = tmp_path / "config.yaml"
    cfg = DarmokConfig.load(path=cfg_path, overrides={"redaction_mode": "dry-run"})
    assert cfg.redaction_mode == "dry-run"


def test_neech_override_threshold(tmp_path):
    """Neech can override auto_redact threshold via nested dict."""
    cfg_path = tmp_path / "config.yaml"
    cfg = DarmokConfig.load(
        path=cfg_path,
        overrides={"thresholds": {"auto_redact": 0.90}},
    )
    assert cfg.auto_redact_threshold == pytest.approx(0.90)
    assert cfg.tier1_block_threshold == pytest.approx(0.50)  # default preserved


def test_neech_override_does_not_require_file(tmp_path):
    """Override pattern works even when file does not yet exist."""
    cfg_path = tmp_path / "nonexistent" / "config.yaml"
    cfg = DarmokConfig.load(
        path=cfg_path,
        overrides={"redaction_mode": "on"},
    )
    assert cfg.redaction_mode == "on"


# ── DARMOK_CONFIG env var ──────────────────────────────────────────────────────

def test_env_var_config_path(tmp_path, monkeypatch):
    """DARMOK_CONFIG env var sets the config file path."""
    cfg_path = tmp_path / "custom_config.yaml"
    _write_config(cfg_path, {"redaction_mode": "dry-run"})
    monkeypatch.setenv("DARMOK_CONFIG", str(cfg_path))

    cfg = DarmokConfig.load()
    assert cfg.redaction_mode == "dry-run"


# ── Properties round-trip ─────────────────────────────────────────────────────

def test_all_properties_accessible(tmp_path):
    """All public properties return without error on a default config."""
    cfg = DarmokConfig.load(path=tmp_path / "config.yaml")
    # Just verify they don't raise
    _ = cfg.auto_redact_threshold
    _ = cfg.tier1_block_threshold
    _ = cfg.log_floor
    _ = cfg.suppression_floor
    _ = cfg.vault_path
    _ = cfg.salt_path
    _ = cfg.default_expiry_hours
    _ = cfg.default_expiry_type
    _ = cfg.soft_expiry_max_recoveries
    _ = cfg.rekey_threshold
    _ = cfg.argon2_time_cost
    _ = cfg.argon2_memory_cost
    _ = cfg.argon2_parallelism
    _ = cfg.schema_version
    _ = cfg.sessions_json_path
    _ = cfg.redaction_mode
    _ = cfg.permission_check
    _ = cfg.warn_vault_in_cloud
    _ = cfg.log_path


def test_detector_enabled_defaults_true(tmp_path):
    """detector_enabled returns True for all categories by default."""
    cfg = DarmokConfig.load(path=tmp_path / "config.yaml")
    for cat in ("api_key", "jwt", "private_key", "url_credential", "email", "ip_address", "credit_card"):
        assert cfg.detector_enabled(cat) is True


def test_detector_can_be_disabled(tmp_path):
    """Detector can be disabled via config."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"detectors": {"email": {"enabled": False}}})
    cfg = DarmokConfig.load(path=cfg_path)
    assert cfg.detector_enabled("email") is False
    assert cfg.detector_enabled("api_key") is True  # others unaffected


def test_context_window_override(tmp_path):
    """context_window returns override if present, default otherwise."""
    cfg_path = tmp_path / "config.yaml"
    _write_config(cfg_path, {"context_windows": {"ip_address": 20}})
    cfg = DarmokConfig.load(path=cfg_path)
    assert cfg.context_window("ip_address") == 20
    assert cfg.context_window("api_key") == 10  # default


def test_dotted_get(tmp_path):
    """get() dotted accessor returns nested values."""
    cfg = DarmokConfig.load(path=tmp_path / "config.yaml")
    assert cfg.get("thresholds.auto_redact") == pytest.approx(0.85)
    assert cfg.get("vault.argon2.time_cost") == 3
    assert cfg.get("nonexistent.key", "fallback") == "fallback"
