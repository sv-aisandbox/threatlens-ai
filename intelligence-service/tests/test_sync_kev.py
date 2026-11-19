from datetime import UTC, datetime

import httpx

from ingestion import source_sync, sync
from ingestion.nvd_client import NvdClient
from tests.helpers import FakeClock, load, nvd_transport

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)


def kev_fetch():
    return load("kev/kev-sample.json")


def run_kev(graph, pg, fetch=kev_fetch):
    return sync.run_kev_sync(graph, pg, fetch, now=lambda: NOW)


def vuln(graph, cve_id):
    with graph.session() as s:
        rec = s.run("MATCH (v:Vulnerability {cve_id: $c}) RETURN v", c=cve_id).single()
    return dict(rec["v"]) if rec else None


def count(graph, label):
    with graph.session() as s:
        return s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"]


def status(pg, source_id="cisa_kev"):
    return {r["source_id"]: r for r in source_sync.list_status(pg)}[source_id]


def test_kev_sets_flags_and_records_status(graph, pg):
    result = run_kev(graph, pg)
    assert (result.status, result.received, result.created, result.updated, result.rejected) == ("partial", 5, 4, 0, 1)
    v = vuln(graph, "CVE-2021-44228")
    assert v["kev_listed"] is True
    assert v["kev_date_added"] == "2021-12-10" and v["kev_due_date"] == "2021-12-24"
    assert v["kev_ransomware_use"] == "known"
    other = vuln(graph, "CVE-2024-10441")
    assert other["kev_ransomware_use"] == "unknown"  # unknown is not "false"
    assert count(graph, "Evidence") == 4
    with graph.session() as s:
        ev = s.run("MATCH (e:Evidence {evidence_id: 'EVID-KEV-CVE-2021-44228'})-[:SUPPORTS]->(v) RETURN e, v.cve_id AS c").single()
    assert ev["c"] == "CVE-2021-44228"
    assert ev["e"]["source_name"] == "CISA KEV" and len(ev["e"]["content_hash"]) == 64
    st = status(pg)
    assert st["last_status"] == "partial" and st["records_rejected"] == 1 and st["last_success_at"] is not None
    assert st["source_modified_at"] == datetime(2026, 11, 18, 19, 17, 41, 35400, tzinfo=UTC)


def test_kev_rerun_is_idempotent(graph, pg):
    run_kev(graph, pg)
    nodes = (count(graph, "Vulnerability"), count(graph, "Evidence"))
    second = run_kev(graph, pg)
    assert (second.created, second.updated) == (0, 0)
    assert (count(graph, "Vulnerability"), count(graph, "Evidence")) == nodes


def test_kev_and_nvd_data_coexist_and_nvd_resync_keeps_kev_flags(graph, pg):
    transport = nvd_transport({0: load("nvd/cve-2021-44228.json")})
    clock = FakeClock()
    client = NvdClient(None, httpx.Client(transport=transport), clock.sleep, clock.monotonic)
    sync.import_single_cve(graph, pg, client, "CVE-2021-44228", now=lambda: NOW)
    run_kev(graph, pg)
    v = vuln(graph, "CVE-2021-44228")
    assert v["kev_listed"] is True and v["cvss_score"] == 10.0
    assert count(graph, "Vulnerability") == 4  # one NVD+KEV node, three KEV-only nodes

    changed = load("nvd/cve-2021-44228.json")
    changed["vulnerabilities"][0]["cve"]["lastModified"] = "2030-01-01T00:00:00.000"
    client2 = NvdClient(None, httpx.Client(transport=nvd_transport({0: changed})), clock.sleep, clock.monotonic)
    result = sync.import_single_cve(graph, pg, client2, "CVE-2021-44228", now=lambda: NOW)
    assert result.updated == 1
    v = vuln(graph, "CVE-2021-44228")
    assert v["kev_listed"] is True and v["kev_date_added"] == "2021-12-10"  # NVD update did not wipe KEV flags
    assert count(graph, "Vulnerability") == 4


def test_invalid_feed_is_a_recorded_failure(graph, pg):
    result = run_kev(graph, pg, fetch=lambda: {"unexpected": "shape"})
    assert result.status == "failed"
    st = status(pg)
    assert st["last_status"] == "failed" and st["error_summary"] and st["last_success_at"] is None
    assert count(graph, "Vulnerability") == 0


def test_fetch_error_is_recorded_without_body(graph, pg):
    def boom():
        raise RuntimeError("KEV request failed with HTTP 503")

    result = run_kev(graph, pg, fetch=boom)
    assert result.status == "failed" and "503" in result.error_summary
