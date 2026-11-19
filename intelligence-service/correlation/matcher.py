"""Pure matching logic (ADR 0003): installed software vs NVD CPE configurations.

evaluate() returns None when the CVE does not name the product (no edge is written), otherwise a
MatchResult with status confirmed | possible | not_affected | unknown and a human-readable reason.
When in doubt the weaker status wins; nothing here guesses.
"""

from dataclasses import dataclass
from typing import Any

from correlation.cpe import Cpe, is_wildcard, normalize_token, parse_cpe23
from correlation.versions import compare, parse_version

MATCHED_BY = "cpe-matcher/1"
_EXTRA_FIELDS = ("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other")

IN_RANGE, OUT_OF_RANGE, UNDECIDABLE = "in_range", "out_of_range", "undecidable"


@dataclass(frozen=True)
class InstalledSoftware:
    vendor: str
    product: str
    version: str | None
    cpe: str | None


@dataclass(frozen=True)
class MatchResult:
    status: str
    reason: str
    matched_criteria: str | None = None


@dataclass(frozen=True)
class _Verdict:
    outcome: str
    detail: str
    caps: tuple[str, ...]
    criteria_id: str | None


def _identity(software: InstalledSoftware) -> tuple[str, str, Cpe | None]:
    inv = parse_cpe23(software.cpe)
    if inv is not None:
        return inv.vendor, inv.product, inv
    return normalize_token(software.vendor, vendor=True), normalize_token(software.product), None


def _installed_version(software: InstalledSoftware, inv: Cpe | None) -> str | None:
    if software.version and software.version.strip():
        return software.version.strip()
    if inv is not None and not is_wildcard(inv.version):
        return inv.version
    return None


def _describe_bounds(m: dict[str, Any]) -> str:
    parts = []
    if m.get("versionStartIncluding"):
        parts.append(f">={m['versionStartIncluding']}")
    if m.get("versionStartExcluding"):
        parts.append(f">{m['versionStartExcluding']}")
    if m.get("versionEndIncluding"):
        parts.append(f"<={m['versionEndIncluding']}")
    if m.get("versionEndExcluding"):
        parts.append(f"<{m['versionEndExcluding']}")
    return ", ".join(parts)


def _check_bounds(installed: tuple[int, ...], m: dict[str, Any]) -> str:
    """IN_RANGE / OUT_OF_RANGE / UNDECIDABLE for a `*` version with optional bounds."""
    rules = (
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    )
    present = [(k, ok) for k, ok in rules if m.get(k)]
    parsed = []
    for key, ok in present:
        bound = parse_version(str(m[key]))
        if bound is None:
            return UNDECIDABLE
        parsed.append((compare(installed, bound), ok))
    return IN_RANGE if all(ok(c) for c, ok in parsed) else OUT_OF_RANGE


def _extra_field_effect(crit: Cpe, inv: Cpe | None) -> tuple[str, str | None]:
    """('applies'|'differs', note). A restriction the inventory cannot confirm caps at possible; a
    restriction the inventory contradicts means this entry does not cover the installed build."""
    cap = None
    for name in _EXTRA_FIELDS:
        wanted = getattr(crit, name)
        if wanted == "*":
            continue
        have = getattr(inv, name) if inv is not None else "*"
        if have == wanted:
            continue
        if have == "*":
            cap = f"criteria restricts {name} to '{wanted}' which the inventory does not record"
        else:
            return "differs", f"installed {name} '{have}' differs from '{wanted}'"
    return "applies", cap


def _evaluate_entry(
    m: dict[str, Any], crit: Cpe, installed_raw: str | None, caps: tuple[str, ...], inv: Cpe | None
) -> _Verdict:
    effect, extra_cap = _extra_field_effect(crit, inv)
    cid = m.get("matchCriteriaId")
    label = f"{crit.vendor}:{crit.product}"
    if effect == "differs":
        return _Verdict(OUT_OF_RANGE, f"{extra_cap} for {label}", caps, cid)
    caps = caps + ((extra_cap,) if extra_cap else ())
    if installed_raw is None:
        return _Verdict(UNDECIDABLE, f"installed version is unknown; CVE lists affected versions of {label}", caps, cid)
    installed = parse_version(installed_raw)
    if installed is None:
        return _Verdict(
            UNDECIDABLE,
            f"installed version '{installed_raw}' is not a dotted numeric version and cannot be compared for {label}",
            caps, cid,
        )
    if crit.version == "*":
        bounds = _describe_bounds(m)
        if not bounds:
            return _Verdict(IN_RANGE, f"installed {installed_raw} is in range: all versions of {label}", caps, cid)
        outcome = _check_bounds(installed, m)
        if outcome == UNDECIDABLE:
            return _Verdict(UNDECIDABLE, f"a version bound ({bounds}) for {label} is not comparable", caps, cid)
        text = f"installed {installed_raw} {'is within' if outcome == IN_RANGE else 'is outside'} {bounds} of {label}"
        return _Verdict(outcome, text, caps, cid)
    if crit.version == "-":
        return _Verdict(UNDECIDABLE, f"criteria for {label} has no applicable version", caps, cid)
    wanted = parse_version(crit.version)
    if wanted is not None:
        same = compare(installed, wanted) == 0
        text = f"installed {installed_raw} {'equals' if same else 'differs from'} affected version {crit.version} of {label}"
        return _Verdict(IN_RANGE if same else OUT_OF_RANGE, text, caps, cid)
    if crit.version == installed_raw.lower():
        return _Verdict(IN_RANGE, f"installed {installed_raw} equals affected version {crit.version} of {label}", caps, cid)
    return _Verdict(UNDECIDABLE, f"affected version '{crit.version}' of {label} is not comparable", caps, cid)


def evaluate(software: InstalledSoftware, configurations: list[dict[str, Any]]) -> MatchResult | None:
    vendor, product, inv = _identity(software)
    if not vendor or not product:
        return None
    installed_raw = _installed_version(software, inv)
    name_only = inv is None
    verdicts: list[_Verdict] = []

    for config in configurations or []:
        nodes = config.get("nodes") or []
        platform_conditional = config.get("operator") == "AND" and len(nodes) > 1
        for node in nodes:
            matches = [m for m in node.get("cpeMatch") or [] if isinstance(m, dict)]
            node_caps: list[str] = []
            if platform_conditional:
                node_caps.append("match is part of an AND configuration; the platform or companion condition is not verified")
            if node.get("operator") == "AND" and len(matches) > 1:
                node_caps.append("match is part of an AND group; the other conditions are not verified")
            if node.get("negate"):
                node_caps.append("negated condition is not evaluated")
            if name_only:
                node_caps.append("product identified by name only (no CPE in inventory)")
            for m in matches:
                if m.get("vulnerable") is not True:
                    continue
                crit = parse_cpe23(m.get("criteria"))
                if crit is None or is_wildcard(crit.vendor) or is_wildcard(crit.product):
                    continue
                if crit.vendor != vendor or crit.product != product:
                    continue
                verdicts.append(_evaluate_entry(m, crit, installed_raw, tuple(node_caps), inv))

    if not verdicts:
        return None
    label = f"{vendor}:{product}"
    in_range = [v for v in verdicts if v.outcome == IN_RANGE]
    if in_range:
        clean = [v for v in in_range if not v.caps]
        if clean:
            v = clean[0]
            return MatchResult("confirmed", v.detail, v.criteria_id)
        v = in_range[0]
        return MatchResult("possible", f"{v.detail}; unverified: {'; '.join(v.caps)}", v.criteria_id)
    undecidable = [v for v in verdicts if v.outcome == UNDECIDABLE]
    if undecidable:
        v = undecidable[0]
        return MatchResult("unknown", v.detail, v.criteria_id)
    return MatchResult(
        "not_affected",
        f"installed {installed_raw} is outside all {len(verdicts)} affected range(s) listed for {label}",
        verdicts[0].criteria_id,
    )
