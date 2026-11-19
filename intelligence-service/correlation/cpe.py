"""CPE 2.3 formatted-string parsing and name normalization (ADR 0003)."""

import re
from dataclasses import dataclass

CPE_FIELDS = ("part", "vendor", "product", "version", "update", "edition", "language",
              "sw_edition", "target_sw", "target_hw", "other")
_SPLIT = re.compile(r"(?<!\\):")
_UNESCAPE = re.compile(r"\\(.)")
_VENDOR_SUFFIXES = {"inc", "incorporated", "corp", "corporation", "ltd", "limited", "llc", "gmbh", "co", "company"}


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str


def parse_cpe23(value: str | None) -> Cpe | None:
    """Parse `cpe:2.3:...` (13 components). Returns None for anything malformed."""
    if not isinstance(value, str) or len(value) > 1000:
        return None
    parts = _SPLIT.split(value.strip())
    if len(parts) != 13 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    fields = [_UNESCAPE.sub(r"\1", p).strip().lower() for p in parts[2:]]
    if fields[0] not in {"a", "o", "h"} or any(f == "" for f in fields):
        return None
    return Cpe(*fields)


def normalize_token(value: str, *, vendor: bool = False) -> str:
    """Lower-case, collapse punctuation/whitespace to `_`; optionally drop trailing corporate suffixes."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", value.lower()) if t]
    while vendor and len(tokens) > 1 and tokens[-1] in _VENDOR_SUFFIXES:
        tokens.pop()
    return "_".join(tokens)


def is_wildcard(value: str) -> bool:
    return value in {"*", "-"}
