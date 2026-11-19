"""CISA KEV feed -> Vulnerability KEV properties (+ Evidence), per roadmap gap G10."""

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from normalization.nvd import CVE_ID_RE, RecordRejected, content_hash

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cveID: str = Field(pattern=CVE_ID_RE.pattern)
    vulnerabilityName: str | None = None
    dateAdded: date
    dueDate: date | None = None
    requiredAction: str | None = None
    knownRansomwareCampaignUse: str = "Unknown"


class KevHeader(BaseModel):
    model_config = ConfigDict(extra="ignore")

    catalogVersion: str
    dateReleased: datetime
    vulnerabilities: list[Any]


def parse_feed(raw: Any) -> KevHeader:
    try:
        return KevHeader.model_validate(raw)
    except ValidationError:
        raise RecordRejected("KEV feed header is invalid") from None


def normalize_entry(raw: Any, collected_at: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RecordRejected("KEV entry is not an object")
    try:
        e = KevEntry.model_validate(raw)
    except ValidationError as exc:
        problems = ", ".join(f"{'.'.join(map(str, x['loc']))}:{x['type']}" for x in exc.errors()[:5])
        raise RecordRejected(f"invalid KEV entry ({problems})") from None
    props = {
        "cve_id": e.cveID,
        "kev_listed": True,
        "kev_date_added": e.dateAdded.isoformat(),
        "kev_due_date": e.dueDate.isoformat() if e.dueDate else None,
        # "known" / "unknown" as reported; "unknown" is not evidence of no ransomware use.
        "kev_ransomware_use": e.knownRansomwareCampaignUse.strip().lower(),
        "kev_name": e.vulnerabilityName,
        "kev_required_action": (e.requiredAction or "")[:1000] or None,
    }
    evidence = {
        "evidence_id": f"EVID-KEV-{e.cveID}",
        "source_name": "CISA KEV",
        "source_url": KEV_FEED_URL,
        "collected_at": collected_at,
        "content_hash": content_hash(raw),
    }
    return {"props": props, "evidence": evidence}
