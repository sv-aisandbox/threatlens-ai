import copy
import logging
from datetime import UTC, datetime

import httpx
import pytest

from ingestion import source_sync, sync
from ingestion.nvd_client import NvdClient
from tests.helpers import FakeClock, load, nvd_transport

KEY = "SECRET-KEY-123"
SINCE = datetime(2026, 11, 1, tzinfo=UTC)
UNTIL = datetime(2026, 11, 2, tzinfo=UTC)
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)


def pages():
    return {0: load("nvd/page-0.json"), 2: load("nvd/page-2.json")}


def client_for(transport):
    clock = FakeClock()
    return NvdClient(KEY, httpx.Client(transport=transport), clock.sleep, clock.monotonic, max_retries=2)


def counts(driver):
    with driver.session() as s:
        v = s.run("MATCH (v:Vulnerability) RETURN count(v) AS c").single()["c"]
        e = s.run("MATCH (e:Evidence) RETURN count(e) AS c").single()["c"]
        r = s.run("MATCH (:Evidence)-[r:SUPPORTS]->(:Vulnerability) RETURN count(r) AS c").single()["c"]
    return v, e, r


def row(conn, source_id="nvd"):
    return {r["source_id"]: r for r in source_sync.list_status(conn)}[source_id]


def run(graph, pg, transport, **kw):
    return sync.run_nvd_sync(graph, pg, client_for(transport), since=SINCE, until=UNTIL, api_key=KEY, now=lambda: NOW, **kw)


def test_sync_populates_graph_and_source_status(graph, pg):
    result = run(graph, pg, nvd_transport(pages()))
    assert (result.status, result.received, result.created, result.updated, result.rejected) == ("success", 4, 4, 0, 0)
    assert counts(graph) == (4, 4, 4)
    status = row(pg)
    assert status["last_status"] == "success"
    assert (status["records_received"], status["records_created"], status["records_updated"], status["records_rejected"]) == (4, 4, 0, 0)
    assert status["last_attempt_at"] == NOW
    assert status["last_success_at"] is not None
    assert status["sync_cursor_at"] == UNTIL
    assert status["source_modified_at"] is not None
    assert status["error_summary"] is None
    with graph.session() as s:
        rec = s.run("MATCH (v:Vulnerability {cve_id: 'CVE-2026-7233'}) RETURN v").single()["v"]
    assert rec["description"] and rec["published_at"].endswith("Z") and "synthetic" not in rec


def test_rerun_creates_no_duplicates_and_updates_counters(graph, pg):
    run(graph, pg, nvd_transport(pages()))
    before = counts(graph)
    second = run(graph, pg, nvd_transport(pages()))
    assert (second.received, second.created, second.updated) == (4, 0, 0)
    assert counts(graph) == before
    status = row(pg)
    assert (status["records_received"], status["records_created"]) == (4, 0)  # counters describe the latest run


def test_changed_record_is_updated_not_duplicated(graph, pg):
    run(graph, pg, nvd_transport(pages()))
    changed = pages()
    changed[0]["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Revised description"
    second = run(graph, pg, nvd_transport(changed))
    assert (second.created, second.updated) == (0, 1)
    assert counts(graph) == (4, 4, 4)
    with graph.session() as s:
        rec = s.run("MATCH (v:Vulnerability {cve_id: $c}) RETURN v.description AS d", c=changed[0]["vulnerabilities"][0]["cve"]["id"]).single()
    assert rec["d"] == "Revised description"


def test_malformed_records_are_rejected_and_counted(graph, pg, caplog):
    with caplog.at_level(logging.WARNING):
        result = run(graph, pg, nvd_transport({0: load("nvd/page-malformed.json")}))
    assert (result.status, result.received, result.created, result.rejected) == ("partial", 3, 1, 2)
    assert counts(graph)[0] == 1
    status = row(pg)
    assert status["last_status"] == "partial" and status["records_rejected"] == 2
    assert status["last_success_at"] is not None


def test_failure_is_recorded_sanitized_and_keeps_last_success(graph, pg, caplog):
    run(graph, pg, nvd_transport(pages()))
    good = row(pg)

    def boom(request):
        return httpx.Response(500, text=f"upstream said apiKey={KEY}")

    with caplog.at_level(logging.DEBUG):
        failed = run(graph, pg, httpx.MockTransport(boom))
    assert failed.status == "failed"
    status = row(pg)
    assert status["last_status"] == "failed" and status["error_summary"]
    assert KEY not in status["error_summary"] and KEY not in caplog.text
    assert status["last_success_at"] == good["last_success_at"]  # still shows the last good sync
    assert status["sync_cursor_at"] == good["sync_cursor_at"]  # cursor not advanced on failure
    assert counts(graph) == (4, 4, 4)  # earlier data untouched


def test_incremental_sync_resumes_from_stored_cursor(graph, pg):
    run(graph, pg, nvd_transport(pages()))
    calls: list[httpx.Request] = []
    later = datetime(2026, 11, 5, tzinfo=UTC)
    sync.run_nvd_sync(graph, pg, client_for(nvd_transport({}, calls)), until=later, api_key=KEY, now=lambda: NOW)
    assert calls[0].url.params["lastModStartDate"] == "2026-11-02T00:00:00.000"
    assert calls[0].url.params["lastModEndDate"] == "2026-11-05T00:00:00.000"
    assert row(pg)["sync_cursor_at"] == later


def test_first_sync_without_since_uses_bounded_default_window(graph, pg):
    calls: list[httpx.Request] = []
    sync.run_nvd_sync(graph, pg, client_for(nvd_transport({}, calls)), api_key=KEY, now=lambda: NOW)
    assert calls[0].url.params["lastModStartDate"] == "2026-11-12T12:00:00.000"  # 7 days before NOW


def test_empty_window_is_a_recorded_failure(graph, pg):
    result = sync.run_nvd_sync(graph, pg, client_for(nvd_transport({})), since=UNTIL, until=SINCE, api_key=KEY, now=lambda: NOW)
    assert result.status == "failed" and "empty" in result.error_summary


def test_sanitize_error_strips_secrets():
    text = source_sync.sanitize_error(RuntimeError(f"failed apiKey={KEY} Authorization: Bearer abc.def"), [KEY])
    assert KEY not in text and "abc.def" not in text
    assert len(source_sync.sanitize_error(RuntimeError("x" * 5000))) <= source_sync.ERROR_SUMMARY_MAX


def test_import_single_cve(graph, pg):
    t = nvd_transport({0: load("nvd/cve-2021-44228.json")})
    result = sync.import_single_cve(graph, pg, client_for(t), "CVE-2021-44228", api_key=KEY, now=lambda: NOW)
    assert (result.status, result.created) == ("success", 1)
    assert counts(graph) == (1, 1, 1)
    again = sync.import_single_cve(graph, pg, client_for(t), "CVE-2021-44228", api_key=KEY, now=lambda: NOW)
    assert (again.created, again.updated) == (0, 0) and counts(graph) == (1, 1, 1)
    assert row(pg, "nvd_single_cve")["last_status"] == "success"


@pytest.mark.parametrize("bad", ["CVE-2021-44228&x=1", "cve-2021-44228", "CVE-21-1", "'; MATCH (n) DETACH DELETE n //", ""])
def test_single_import_rejects_bad_ids_before_any_request(graph, pg, bad):
    calls: list[httpx.Request] = []
    with pytest.raises(ValueError):
        sync.import_single_cve(graph, pg, client_for(nvd_transport({}, calls)), bad)
    assert calls == []


def test_single_import_not_found(graph, pg):
    result = sync.import_single_cve(graph, pg, client_for(nvd_transport({})), "CVE-2099-0001", api_key=KEY, now=lambda: NOW)
    assert result.status == "failed" and "not found" in result.error_summary
    assert counts(graph) == (0, 0, 0)


def test_does_not_modify_fixture_between_tests():
    original = load("nvd/page-0.json")
    assert copy.deepcopy(original) == load("nvd/page-0.json")
