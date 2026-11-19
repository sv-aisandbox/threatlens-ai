"""Tool registry and MVP discovery (spec section 7, ADR 0007).

Pipeline: filter by role and risk -> detect entities in the question -> keyword/entity match -> top-k schemas for the
model. The model only ever sees the tools returned here, and the loop refuses calls to anything else. Semantic search
is post-MVP.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
ASSET_RE = re.compile(r"\bASSET-[A-Z0-9]+(?:-[A-Z0-9]+)*\b", re.IGNORECASE)
TENANT_RE = re.compile(r"\bTENANT-[A-Z0-9]+(?:-[A-Z0-9]+)*\b", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
ENV_WORDS = {
    "production": "production", "prod": "production",
    "staging": "staging", "stage": "staging",
    "development": "development", "dev": "development",
}
STOP_WORDS = frozenset(
    "a an and are as at be by do does for from how i if in is it me my of on or our that the their there these this "
    "to us was we what when where which who why with you your can could would should".split()
)
ALLOWED_RISK = frozenset({"read_only"})
DEFAULT_K = 5
MAX_OFFERED = 6
MIN_SCORE = 1.0


class RegistryError(RuntimeError):
    """The registry metadata and the tools the servers expose are out of step."""


@dataclass(frozen=True)
class Entities:
    cves: tuple[str, ...]
    assets: tuple[str, ...]
    environment: str | None
    words: frozenset[str]


def _stem(token: str) -> str:
    """Crude singularization: enough for keyword matching, and it makes 'assets' and 'asset' one concept."""
    return token[:-1] if len(token) > 3 and token.endswith("s") and not token.endswith("ss") else token


def _words(text: str) -> frozenset[str]:
    return frozenset(_stem(t) for t in _TOKEN_RE.findall(text.lower()) if t not in STOP_WORDS and len(t) >= 2)


def _norm_phrase(text: str) -> str:
    return " ".join(_stem(t) for t in _TOKEN_RE.findall(text.lower()))


def detect_entities(text: str) -> Entities:
    cves = tuple(dict.fromkeys(m.upper() for m in CVE_RE.findall(text)))
    assets = tuple(dict.fromkeys(m.upper() for m in ASSET_RE.findall(text)))
    words = _words(text)
    environment = next((ENV_WORDS[w] for w in _TOKEN_RE.findall(text.lower()) if w in ENV_WORDS), None)
    return Entities(cves, assets, environment, words)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    domain: str
    description: str
    input_entities: tuple[str, ...]
    output_entities: tuple[str, ...]
    risk_level: str
    permissions: tuple[str, ...]
    tags: tuple[str, ...]
    input_schema: dict[str, Any]
    requires_id: str | None = None  # "Vulnerability" or "Asset" when an identifier argument is required
    entry_point: bool = False  # broad tools offered when nothing more specific matches
    phrases: tuple[str, ...] = ()  # multi-word intents that outweigh single keywords

    def as_tool_param(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


ALL_ROLES = ("ADMIN", "SECURITY_ANALYST", "VIEWER")

# Curated metadata per tool (spec section 7). A test fails if this and the servers' tool lists drift apart.
METADATA: dict[str, dict[str, Any]] = {
    "get_affected_assets": dict(
        phrases=("affected by", "which asset", "exposed to", "am i exposed", "are we exposed"),
        server="threatlens-vulnerability", domain="vulnerability", input_entities=("Vulnerability",),
        output_entities=("Asset", "Software", "Evidence"), requires_id="Vulnerability",
        tags=("affected", "exposure", "exposed", "impact", "impacted", "vulnerable", "assets", "running", "organization",
              "confirmed", "possible", "unknown", "investigate"),
    ),
    "get_vulnerability_details": dict(
        server="threatlens-vulnerability", domain="vulnerability", input_entities=("Vulnerability",),
        output_entities=("Vulnerability", "Evidence"), requires_id="Vulnerability",
        tags=("details", "detail", "cvss", "severity", "kev", "exploited", "known", "score", "describe", "description",
              "published", "ransomware", "due"),
    ),
    "search_vulnerabilities": dict(
        phrases=("known exploited", "kev list", "find vulnerabilit", "list vulnerabilit"),
        server="threatlens-vulnerability", domain="vulnerability", input_entities=(),
        output_entities=("Vulnerability",), entry_point=True,
        tags=("search", "find", "list", "kev", "exploited", "cvss", "severity", "vulnerabilities", "vulnerability",
              "critical", "known", "log4j", "recent"),
    ),
    "get_vulnerability_evidence": dict(
        phrases=("evidence for", "source of", "where does", "how sure"),
        server="threatlens-vulnerability", domain="vulnerability", input_entities=("Vulnerability",),
        output_entities=("Evidence",), requires_id="Vulnerability",
        tags=("evidence", "source", "sources", "proof", "cite", "citation", "provenance", "hash", "nvd", "cisa", "where"),
    ),
    "search_assets": dict(
        phrases=("find asset", "list asset", "search asset", "internet exposed", "internet-exposed"),
        server="threatlens-asset", domain="asset", input_entities=(), output_entities=("Asset",), entry_point=True,
        tags=("search", "find", "list", "assets", "asset", "servers", "server", "hosts", "internet", "exposed", "named",
              "production", "staging", "development", "environment", "criticality", "payment", "investigate"),
    ),
    "get_asset_details": dict(
        server="threatlens-asset", domain="asset", input_entities=("Asset",), output_entities=("Asset",),
        requires_id="Asset",
        tags=("asset", "details", "detail", "criticality", "environment", "inventory", "imported"),
    ),
    "get_asset_software": dict(
        phrases=("software installed", "installed software", "running on", "what software", "software on"),
        server="threatlens-asset", domain="asset", input_entities=("Asset",), output_entities=("Software", "Vulnerability"),
        requires_id="Asset",
        tags=("software", "installed", "running", "versions", "version", "packages", "vulnerabilities", "findings",
              "investigate", "exposed", "exposure"),
    ),
    "get_critical_assets": dict(
        phrases=("critical asset", "crown jewel", "most critical", "most exposed", "most at risk", "worry about"),
        server="threatlens-asset", domain="asset", input_entities=(), output_entities=("Asset",), entry_point=True,
        tags=("critical", "crown", "jewels", "important", "priority", "worry", "risk", "riskiest", "exposed"),
    ),
}


class ToolRegistry:
    def __init__(self, specs: Sequence[ToolSpec]) -> None:
        self._specs = {s.name: s for s in specs}

    @classmethod
    def from_listing(cls, listing: Iterable[dict[str, Any]]) -> "ToolRegistry":
        """Build from the tools the MCP servers expose ({"name", "description", "input_schema"} each)."""
        specs, seen = [], set()
        for tool in listing:
            name = tool["name"]
            meta = METADATA.get(name)
            if meta is None:
                raise RegistryError(f"tool {name!r} has no registry metadata")
            seen.add(name)
            specs.append(
                ToolSpec(
                    name=name, server=meta["server"], domain=meta["domain"], description=tool["description"],
                    input_entities=meta["input_entities"], output_entities=meta["output_entities"],
                    risk_level="read_only", permissions=ALL_ROLES, tags=meta["tags"], input_schema=tool["input_schema"],
                    requires_id=meta.get("requires_id"), entry_point=meta.get("entry_point", False),
                    phrases=meta.get("phrases", ()),
                )
            )
        missing = set(METADATA) - seen
        if missing:
            raise RegistryError(f"registry metadata for tools the servers do not expose: {sorted(missing)}")
        return cls(specs)

    @property
    def names(self) -> list[str]:
        return list(self._specs)

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def eligible(self, roles: Iterable[str]) -> list[ToolSpec]:
        """Step 2 of the pipeline: filter by permission and risk level."""
        role_set = set(roles)
        return [s for s in self._specs.values() if s.risk_level in ALLOWED_RISK and role_set & set(s.permissions)]

    @staticmethod
    def _score(spec: ToolSpec, entities: Entities, text: str) -> float:
        score = 0.0
        if entities.cves and "Vulnerability" in spec.input_entities:
            score += 4
        if entities.assets and "Asset" in spec.input_entities:
            score += 4
        if (entities.cves or entities.assets) and not spec.input_entities:
            score -= 3.0  # a question about a specific CVE or asset does not need a broad search tool
        if spec.requires_id == "Vulnerability" and not entities.cves:
            score -= 3.0  # cannot be called without a CVE id; expand() adds it once an id has been found
        if spec.requires_id == "Asset" and not entities.assets:
            score -= 3.0
        score += 1.5 * len(entities.words & {_stem(t) for t in spec.tags})
        normalized = _norm_phrase(text)
        score += 3.0 * sum(1 for phrase in spec.phrases if _norm_phrase(phrase) in normalized)
        score += 0.2 * len(entities.words & _words(spec.description))
        return score

    def discover(self, text: str, roles: Iterable[str], k: int = DEFAULT_K, exclude: Iterable[str] = ()) -> list[ToolSpec]:
        """Top-k eligible tools for the text, best first. Broad entry-point tools are the fallback."""
        entities = detect_entities(text)
        excluded = set(exclude)
        scored = sorted(
            ((self._score(s, entities, text), s) for s in self.eligible(roles) if s.name not in excluded),
            key=lambda pair: (-pair[0], pair[1].name),
        )
        picked = [s for score, s in scored if score >= MIN_SCORE][:k]
        if not picked and not excluded:
            picked = [s for _, s in scored if s.entry_point][:3]
        return picked

    def expand(self, offered: list[ToolSpec], text: str, roles: Iterable[str], cap: int = MAX_OFFERED) -> list[ToolSpec]:
        """Add (never remove) newly relevant tools after a tool round, up to `cap`."""
        room = cap - len(offered)
        if room <= 0:
            return offered
        extra = self.discover(text, roles, k=room, exclude=[s.name for s in offered])
        return offered + [s for s in extra if s.name not in {o.name for o in offered}][:room]
