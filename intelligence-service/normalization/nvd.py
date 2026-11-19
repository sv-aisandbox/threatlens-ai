"""NVD CVE 2.0 record -> Vulnerability + Evidence properties. Feed content is untrusted: validate first."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
# Preference order for the headline score (see docs/architecture/nvd-field-mapping.md).
CVSS_PREFERENCE = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")


class RecordRejected(ValueError):
    """A feed record failed validation. The message never includes record content."""


class _Description(BaseModel):
    lang: str
    value: str


class _CvssData(BaseModel):
    version: str
    vectorString: str
    baseScore: float = Field(ge=0, le=10)
    baseSeverity: str | None = None


class _Metric(BaseModel):
    type: str | None = None
    cvssData: _CvssData
    baseSeverity: str | None = None  # CVSS v2 carries severity here


class NvdCve(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(pattern=CVE_ID_RE.pattern)
    published: datetime
    lastModified: datetime
    vulnStatus: str | None = None
    descriptions: list[_Description] = Field(min_length=1)
    metrics: dict[str, Any] = {}
    configurations: list[dict[str, Any]] = []


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=dt.tzinfo or UTC).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def content_hash(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _best_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in CVSS_PREFERENCE:
        candidates = []
        for raw in metrics.get(key) or []:
            try:
                candidates.append(_Metric.model_validate(raw))
            except ValidationError:
                continue  # a malformed metric is ignored; the CVE itself is still usable
        if not candidates:
            continue
        candidates.sort(key=lambda m: m.type != "Primary")  # NVD "Primary" first
        m = candidates[0]
        severity = m.cvssData.baseSeverity or m.baseSeverity
        return {
            "cvss_score": m.cvssData.baseScore,
            "severity": severity.lower() if severity else None,
            "cvss_version": m.cvssData.version,
            "cvss_vector": m.cvssData.vectorString,
        }
    return {"cvss_score": None, "severity": None, "cvss_version": None, "cvss_vector": None}


def normalize_cve(raw: Any, collected_at: str) -> dict[str, Any]:
    """Return {"props", "evidence"} for one NVD `cve` object, or raise RecordRejected."""
    if not isinstance(raw, dict):
        raise RecordRejected("record is not an object")
    try:
        rec = NvdCve.model_validate(raw)
    except ValidationError as exc:
        # Only field locations and error types: never echo untrusted values.
        problems = ", ".join(f"{'.'.join(map(str, e['loc']))}:{e['type']}" for e in exc.errors()[:5])
        raise RecordRejected(f"invalid NVD record ({problems})") from None

    english = next((d.value for d in rec.descriptions if d.lang == "en"), rec.descriptions[0].value)
    props = {
        "cve_id": rec.id,
        "description": english,
        **_best_cvss(rec.metrics),
        "published_at": _iso(rec.published),
        "last_modified_at": _iso(rec.lastModified),
        "vuln_status": rec.vulnStatus,
        # Source values preserved verbatim for matching (Module 05); not rendered anywhere.
        "configurations_json": json.dumps(rec.configurations, sort_keys=True, separators=(",", ":")),
    }
    evidence = {
        "evidence_id": f"EVID-NVD-{rec.id}",
        "source_name": "NVD",
        "source_url": NVD_DETAIL_URL.format(cve_id=rec.id),
        "collected_at": collected_at,
        "content_hash": content_hash(raw),
    }
    return {"props": props, "evidence": evidence}
