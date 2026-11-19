import copy
import json
import re

import pytest

from normalization.nvd import RecordRejected, normalize_cve
from tests.helpers import load

COLLECTED = "2026-11-19T00:00:00.000Z"


def log4j():
    return load("nvd/cve-2021-44228.json")["vulnerabilities"][0]["cve"]


def test_maps_real_record():
    out = normalize_cve(log4j(), COLLECTED)
    p, e = out["props"], out["evidence"]
    assert p["cve_id"] == "CVE-2021-44228"
    assert p["cvss_score"] == 10.0 and p["severity"] == "critical" and p["cvss_version"] == "3.1"
    assert p["cvss_vector"].startswith("CVSS:3.1/")
    assert "log4j" in p["description"].lower()
    assert p["published_at"] == "2021-12-10T10:15:09.143Z"
    assert p["last_modified_at"].endswith("Z")
    assert p["vuln_status"]
    configs = json.loads(p["configurations_json"])
    assert configs and "nodes" in configs[0]  # CPE match criteria preserved verbatim
    assert e["evidence_id"] == "EVID-NVD-CVE-2021-44228"
    assert e["source_name"] == "NVD" and e["source_url"].endswith("/CVE-2021-44228")
    assert re.fullmatch(r"[0-9a-f]{64}", e["content_hash"]) and e["collected_at"] == COLLECTED


def test_hash_changes_when_record_changes():
    a = normalize_cve(log4j(), COLLECTED)["evidence"]["content_hash"]
    changed = log4j()
    changed["lastModified"] = "2030-01-01T00:00:00.000"
    assert normalize_cve(changed, COLLECTED)["evidence"]["content_hash"] != a
    assert normalize_cve(log4j(), COLLECTED)["evidence"]["content_hash"] == a


def test_cvss_preference_and_absence():
    rec = log4j()
    v40 = copy.deepcopy(rec["metrics"]["cvssMetricV31"][0])
    v40["cvssData"].update(version="4.0", baseScore=8.8, baseSeverity="HIGH")
    rec["metrics"] = {"cvssMetricV40": [v40], "cvssMetricV2": rec["metrics"].get("cvssMetricV2", [])}
    p = normalize_cve(rec, COLLECTED)["props"]
    assert (p["cvss_version"], p["cvss_score"], p["severity"]) == ("4.0", 8.8, "high")
    rec["metrics"] = {}
    p = normalize_cve(rec, COLLECTED)["props"]
    assert p["cvss_score"] is None and p["severity"] is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(id="NOT-A-CVE"),
        lambda r: r.update(descriptions=[]),
        lambda r: r.pop("id"),
        lambda r: r.pop("published"),
        lambda r: r.update(published="yesterday-ish"),
    ],
)
def test_malformed_records_rejected(mutate):
    rec = log4j()
    mutate(rec)
    with pytest.raises(RecordRejected):
        normalize_cve(rec, COLLECTED)


def test_non_object_rejected():
    with pytest.raises(RecordRejected):
        normalize_cve("<script>alert(1)</script>", COLLECTED)


def test_rejection_message_never_echoes_untrusted_content():
    rec = log4j()
    rec["id"] = "<script>alert('xss')</script>"
    with pytest.raises(RecordRejected) as exc:
        normalize_cve(rec, COLLECTED)
    assert "script" not in str(exc.value) and "alert" not in str(exc.value)
