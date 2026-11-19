"""Conservative version comparison (ADR 0003): dotted numeric versions only, else not comparable."""

import re

_NUMERIC = re.compile(r"^[0-9]{1,9}(?:\.[0-9]{1,9}){0,5}$")  # ASCII digits only (\d also matches other scripts)


def parse_version(value: str | None) -> tuple[int, ...] | None:
    """Return a tuple of ints, or None when the version is missing or not purely dotted-numeric."""
    if value is None:
        return None
    text = value.strip()
    if not _NUMERIC.fullmatch(text):
        return None
    return tuple(int(part) for part in text.split("."))


def compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """-1, 0 or 1; shorter versions are zero-padded (1.0 == 1.0.0)."""
    width = max(len(a), len(b))
    pa = a + (0,) * (width - len(a))
    pb = b + (0,) * (width - len(b))
    return (pa > pb) - (pa < pb)
