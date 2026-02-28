# Benchmark dashboard — outputs the exact tiered format from detector_spec.md
# §Benchmark Dashboard Format: TIER SUMMARY table + CATEGORY BREAKDOWN table.
# Plain text with Unicode box-drawing characters; no external dependencies.

from __future__ import annotations

from datetime import datetime

from tests.harness import (
    ALL_CATEGORIES,
    CATEGORY_TIER,
    TIER_PRECISION_TARGET,
    TIER_RECALL_TARGET,
    BenchmarkResult,
    CategoryResult,
)

# ── Column widths (match detector_spec.md example exactly) ────────────────────
# Col widths: name=14, recall=10, target=10, precision=10, status=20
# Inner width: 14+1+10+1+10+1+10+1+20 = 68  |  Total width: 70

_W = (14, 10, 10, 10, 20)
_INNER = sum(_w for _w in _W) + len(_W) - 1  # 68

# Display names for each category (fits in 13 chars so 1-space left padding holds)
_DISPLAY_NAME: dict[str, str] = {
    "private_key":    "PrivateKey",
    "jwt":            "JWT",
    "api_key":        "ApiKey",
    "url_credential": "UrlCred",
    "email":          "Email",
    "ip_address":     "IpAddress",
    "credit_card":    "CreditCard",
}

# ── Box-drawing primitives ────────────────────────────────────────────────────


def _top() -> str:
    return "┌" + "─" * _INNER + "┐"


def _bot() -> str:
    return "└" + "┴".join("─" * w for w in _W) + "┘"


def _tee() -> str:
    """Separator that opens columns downward (├──┬──┬──┤)."""
    return "├" + "┬".join("─" * w for w in _W) + "┤"


def _cross() -> str:
    """Full-width row separator (├──┼──┼──┼──┼──┤)."""
    return "├" + "┼".join("─" * w for w in _W) + "┤"


def _btee() -> str:
    """Separator that closes columns upward (├──┴──┴──┤)."""
    return "├" + "┴".join("─" * w for w in _W) + "┤"


def _span_title(text: str) -> str:
    """Full-width title row spanning all columns."""
    return "│" + (" " + text).ljust(_INNER) + "│"


def _col_row(c1: str, c2: str, c3: str, c4: str, c5: str) -> str:
    """Data row with five columns at exact widths."""
    return (
        "│" + c1.ljust(_W[0])
        + "│" + c2.ljust(_W[1])
        + "│" + c3.ljust(_W[2])
        + "│" + c4.ljust(_W[3])
        + "│" + c5.ljust(_W[4])
        + "│"
    )


# ── Cell formatters ────────────────────────────────────────────────────────────


def _name_cell(text: str) -> str:
    """14-char name cell with 1-space left padding."""
    return (" " + text).ljust(_W[0])


def _metric_cell(value: float, width: int) -> str:
    """Centered metric value (e.g. '  0.991   ')."""
    return f"{value:.3f}".center(width)


def _target_cell(target: float) -> str:
    """Left-padded target string (e.g. ' ≥ 0.99   ')."""
    return f" \u2265 {target:.2f}".ljust(_W[2])


def _status_cell(passed: bool) -> str:
    """20-char status cell."""
    sym = "\u2713" if passed else "\u2717"
    label = "PASS" if passed else "FAIL"
    return f" {sym} {label}".ljust(_W[4])


def _na_cell(width: int) -> str:
    return "  —".ljust(width)


# ── Public API ─────────────────────────────────────────────────────────────────


def print_dashboard(result: BenchmarkResult, timestamp: str | None = None) -> None:
    """
    Print the tiered benchmark dashboard in the exact format from detector_spec.md
    §Benchmark Dashboard Format.
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append(_top())
    lines.append(_span_title(f"BENCHMARK RESULTS \u2014 {timestamp}"))

    # ── Tier Summary section ───────────────────────────────────────────────────
    lines.append(_tee())
    lines.append(_col_row(
        _name_cell("TIER SUMMARY"),
        "Recall".center(_W[1]),
        " Target".ljust(_W[2]),
        " Precision".ljust(_W[3]),
        " Status".ljust(_W[4]),
    ))
    lines.append(_cross())

    for t in (1, 2, 3):
        tr = result.tiers.get(t)
        if tr is None:
            lines.append(_col_row(
                _name_cell(f"Tier {t}"),
                _na_cell(_W[1]),
                _target_cell(TIER_RECALL_TARGET[t]),
                _na_cell(_W[3]),
                _na_cell(_W[4]),
            ))
        else:
            lines.append(_col_row(
                _name_cell(f"Tier {t}"),
                _metric_cell(tr.recall, _W[1]),
                _target_cell(tr.recall_target),
                _metric_cell(tr.precision, _W[3]),
                _status_cell(tr.passed),
            ))

    # ── Category Breakdown section ─────────────────────────────────────────────
    lines.append(_btee())
    lines.append(_span_title("CATEGORY BREAKDOWN"))
    lines.append(_tee())
    lines.append(_col_row(
        _name_cell("Detector"),
        "Recall".center(_W[1]),
        " Target".ljust(_W[2]),
        " Precision".ljust(_W[3]),
        " Status".ljust(_W[4]),
    ))
    lines.append(_cross())

    for category in ALL_CATEGORIES:
        display = _DISPLAY_NAME.get(category, category)
        tier = CATEGORY_TIER.get(category, 3)
        r_target = TIER_RECALL_TARGET[tier]
        p_target = TIER_PRECISION_TARGET[tier]
        cr: CategoryResult | None = result.categories.get(category)

        if cr is None or (cr.tp + cr.fp) == 0:
            # Stub detector — no detections made
            lines.append(_col_row(
                _name_cell(display),
                _na_cell(_W[1]),
                _target_cell(r_target),
                _na_cell(_W[3]),
                _name_cell("— not implemented"),
            ))
        else:
            passed = cr.recall >= r_target and cr.precision >= p_target
            lines.append(_col_row(
                _name_cell(display),
                _metric_cell(cr.recall, _W[1]),
                _target_cell(r_target),
                _metric_cell(cr.precision, _W[3]),
                _status_cell(passed),
            ))

    lines.append(_bot())

    # ── Exit criteria summary ──────────────────────────────────────────────────
    all_tiers_pass = all(
        result.tiers[t].passed for t in (1, 2, 3) if t in result.tiers
    )
    # Only report all-pass when every tier has real data (non-empty tiers dict)
    implemented_tiers = {
        CATEGORY_TIER.get(cat, 3)
        for cat, cr in result.categories.items()
        if cr.tp + cr.fp > 0
    }
    if all_tiers_pass and implemented_tiers >= {1, 2}:
        status_line = "Phase 1 exit criteria: ALL tiers must pass. Current: \u2713 ALL PASS"
    else:
        failing = [
            f"Tier {t}"
            for t in (1, 2, 3)
            if t in result.tiers and not result.tiers[t].passed
        ]
        if not failing:
            status_line = "Phase 1 exit criteria: ALL tiers must pass. Current: detectors pending"
        else:
            status_line = (
                "Phase 1 exit criteria: ALL tiers must pass. "
                f"Current: \u2717 FAILING ({', '.join(failing)})"
            )

    print("\n".join(lines))
    print(status_line)
