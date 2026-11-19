"""Prompt-injection and grounding guards (ADR 0007).

Nothing here decides authorization; it only reduces what hostile text can do inside the model's context and
checks that the narrative stays inside what the tools returned.
"""

import json
import re
import unicodedata
from typing import Any

from agent.registry import ASSET_RE, CVE_RE, TENANT_RE

EVIDENCE_RE = re.compile(r"\bEVID-[A-Z0-9]+(?:-[A-Z0-9]+)*\b", re.IGNORECASE)
MAX_FIELD_CHARS = 1000
FLAG = "[FLAGGED: instruction-like text in external data] "
UNVERIFIED = "[unverified identifier]"

# Text that tries to address the model rather than describe a vulnerability or asset.
_INJECTION = [
    r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|messages|rules)",
    r"disregard (all |any |the )?(previous|prior|above|earlier|your) ",
    r"forget (all |any |the )?(previous|prior|above|earlier|your) ",
    r"\bnew (instructions|rules|system prompt)\b",
    r"\byou are now\b",
    r"\bact as (an? )?(admin|administrator|root|different|new)",
    r"\b(reveal|print|show|output|leak|repeat) (me )?(your|the) (system prompt|instructions|api key|secret|credentials|prompt)",
    r"</?\s*(system|assistant|user|tool|instructions?)\s*>",
    r"<\|?(im_start|im_end|system|endoftext)\|?>",
    r"\b(call|invoke|use|run|execute) (the )?(tool|function|get_|search_)",
    r"\bdo not (tell|inform|mention|reveal)\b",
    r"\b(switch|change|set) (to )?(the )?(tenant|organization|role|permissions?)\b",
    r"\bsystem\s*:\s*",
]
_INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in _INJECTION), re.IGNORECASE)
_STRIP_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn"}  # control, format (zero-width, bidi), surrogate, private, unassigned


def sanitize_text(value: str, limit: int = MAX_FIELD_CHARS) -> str:
    """Remove control/invisible characters, collapse whitespace and cap the length."""
    cleaned = "".join(ch for ch in value if unicodedata.category(ch) not in _STRIP_CATEGORIES or ch in "\n\t")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned if len(cleaned) <= limit else cleaned[:limit].rstrip() + " ...[truncated]"


def looks_like_injection(value: str) -> bool:
    return bool(_INJECTION_RE.search(value))


def _leaf_names(untrusted_fields: list[str]) -> set[str]:
    return {f.split(".")[-1] for f in untrusted_fields}


def scrub_result(body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Sanitize every untrusted text field in a tool envelope. Returns (clean copy, injection_suspected)."""
    untrusted = _leaf_names(body.get("untrusted_fields") or [])
    flagged = False

    def walk(node: Any) -> Any:
        nonlocal flagged
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if key in untrusted and isinstance(value, str):
                    text = sanitize_text(value)
                    if looks_like_injection(text):
                        flagged = True
                        text = FLAG + text
                    out[key] = text
                else:
                    out[key] = walk(value)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(body), flagged


def strip_untrusted(body: dict[str, Any]) -> dict[str, Any]:
    """A copy of a tool envelope without its untrusted text fields: what is left is safe to mine for identifiers."""
    untrusted = _leaf_names(body.get("untrusted_fields") or [])

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items() if k not in untrusted}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(body)


def tool_result_content(body: dict[str, Any], limit: int) -> str:
    """JSON for a tool_result block, hard-capped so a hostile or huge result cannot flood the context."""
    text = json.dumps(body, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text) <= limit:
        return text
    return json.dumps(
        {"truncated": True, "note": "result too large; ask a narrower question", "tool": body.get("tool"),
         "head": text[: max(0, limit - 200)]},
        ensure_ascii=False,
    )


# ---- grounding ----------------------------------------------------------------------------------------------


def identifiers(text: str) -> set[str]:
    found = set()
    for pattern in (CVE_RE, ASSET_RE, EVIDENCE_RE, TENANT_RE):
        found |= {m.upper() for m in pattern.findall(text)}
    return found


def verify_narrative(text: str, allowed: set[str]) -> tuple[str, list[str]]:
    """Replace any CVE, asset, evidence or tenant id that no tool result (or the question) contained."""
    ungrounded: list[str] = []

    def repl(match: re.Match[str]) -> str:
        ident = match.group(0).upper()
        if ident in allowed:
            return match.group(0)
        ungrounded.append(ident)
        return UNVERIFIED

    pattern = re.compile("|".join(f"(?:{p.pattern})" for p in (CVE_RE, ASSET_RE, EVIDENCE_RE, TENANT_RE)), re.IGNORECASE)
    cleaned = pattern.sub(repl, text)
    return cleaned, sorted(set(ungrounded))
