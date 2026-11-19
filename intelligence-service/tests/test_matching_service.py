"""End-to-end: real NVD record (log4j, CVE-2021-44228) + synthetic inventory -> AFFECTED_BY edges -> query."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from correlation.match_service import run_matching
from correlation.matcher import MATCHED_BY
from graph_queries.affected_assets import get_affected_assets, get_affected_assets_with_freshness
from ingestion import source_sync, sync
from ingestion.inventory_import import import_inventory
from ingestion.nvd_client import NvdClient
from tests.helpers import FIXTURES, FakeClock, load, nvd_transport

CVE = "CVE-2021-44228"
TENANT = "TENANT-DEMO"
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
ALL = ["confirmed", "possible", "not_affected", "unknown"]


def nvd_client(pages):
    clock = FakeClock()
    return NvdClient(None, httpx.Client(transport=nvd_transport(pages)), clock.sleep, clock.monotonic)


def import_cve(graph, pg, fixture="nvd/cve-2021-44228.json", cve=CVE):
    sync.import_single_cve(graph, pg, nvd_client({0: load(fixture)}), cve, now=lambda: NOW)


def import_seed(graph, pg, name, tenant):
    data = (FIXTURES.parent / "seed" / f"{name}.json").read_bytes()
    r = import_inventory(graph, pg, tenant, data, "json", f"{name}.json", now=NOW)
    assert r.rows_rejected == 0
    return r


@pytest.fixture()
def world(graph, pg):
    import_cve(graph, pg)
    import_seed(graph, pg, "inventory-demo", TENANT)
    return graph, pg


def by_asset(rows):
    return {r["asset_id"]: r for r in rows}


def test_every_status_is_produced_and_honest(world):
    graph, _ = world
    summary = run_matching(graph, now=lambda: NOW)
    assert summary.created == 4
    rows = by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL))
    assert {k: v["match_status"] for k, v in rows.items()} == {
        "ASSET-013": "confirmed",      # 2.14.1 with CPE, inside 2.13.0 <= v < 2.15.0
        "ASSET-014": "not_affected",   # 2.17.1 outside every range
        "ASSET-015": "unknown",        # product named but no installed version: never guessed
        "ASSET-016": "possible",       # 2.14.1.0 without CPE: identified by name only
    }
    assert "2.14.1" in rows["ASSET-013"]["match_reason"] and ">=2.13.0" in rows["ASSET-013"]["match_reason"]
    assert "outside" in rows["ASSET-014"]["match_reason"]
    assert "unknown" in rows["ASSET-015"]["match_reason"]
    assert "name only" in rows["ASSET-016"]["match_reason"]


def test_default_query_excludes_not_affected_but_keeps_unknown_visible(world):
    graph, _ = world
    run_matching(graph, now=lambda: NOW)
    rows = by_asset(get_affected_assets(graph, TENANT, CVE))
    assert set(rows) == {"ASSET-013", "ASSET-015", "ASSET-016"}
    assert [a for a, r in rows.items() if r["match_status"] == "confirmed"] == ["ASSET-013"]  # only confirmed is exposure


def test_edges_carry_provenance_and_query_returns_evidence(world):
    graph, _ = world
    run_matching(graph, now=lambda: NOW)
    row = by_asset(get_affected_assets(graph, TENANT, CVE))["ASSET-013"]
    assert row["matched_by"] == MATCHED_BY and row["matched_at"] == "2026-11-19T12:00:00.000Z"
    assert row["source_ref"] == f"EVID-NVD-{CVE}"
    assert row["evidence"] and row["evidence"][0]["source_name"] in {"NVD", "CISA KEV"}
    assert any(e["evidence_id"] == f"EVID-NVD-{CVE}" for e in row["evidence"])
    assert row["software"]["cpe"].startswith("cpe:2.3:a:apache:log4j:")
    assert row["inventory_imported_at"] == "2026-11-19T12:00:00.000Z"


def test_rematch_is_idempotent_and_keeps_matched_at(world):
    graph, _ = world
    run_matching(graph, now=lambda: NOW)
    first = by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL))
    again = run_matching(graph, now=lambda: NOW + timedelta(days=1))
    assert (again.created, again.updated, again.removed, again.unchanged) == (0, 0, 0, 4)
    second = by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL))
    assert {k: v["matched_at"] for k, v in second.items()} == {k: v["matched_at"] for k, v in first.items()}
    with graph.session() as s:
        assert s.run("MATCH (:Software)-[m:AFFECTED_BY]->(:Vulnerability {cve_id:$c}) RETURN count(m) AS n", c=CVE).single()["n"] == 4


def test_changed_advisory_updates_and_stale_edges_are_removed(world):
    graph, _ = world
    run_matching(graph, now=lambda: NOW)
    # Advisory rewritten: only versions below 2.0 are affected now.
    changed = load("nvd/cve-2021-44228.json")["vulnerabilities"][0]["cve"]
    changed["configurations"] = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0",
         "matchCriteriaId": "NEW"}]}]}]
    changed["lastModified"] = "2030-01-01T00:00:00.000"
    from ingestion.graph_writer import upsert_batch
    from normalization.nvd import normalize_cve
    upsert_batch(graph, [normalize_cve(changed, "2030-01-02T00:00:00.000Z")])
    summary = run_matching(graph, now=lambda: NOW + timedelta(days=1))
    assert summary.updated >= 1
    rows = by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL))
    assert rows["ASSET-013"]["match_status"] == "not_affected"   # 2.14.1 is no longer in range
    assert rows["ASSET-013"]["matched_at"] == "2026-11-20T12:00:00.000Z"
    # Advisory loses its configuration entirely: the matcher's own edges go away, nothing is guessed.
    with graph.session() as s:
        s.run("MATCH (v:Vulnerability {cve_id:$c}) SET v.configurations_json = '[]'", c=CVE).consume()
    gone = run_matching(graph, now=lambda: NOW + timedelta(days=2))
    assert gone.removed == 4
    assert get_affected_assets(graph, TENANT, CVE, statuses=ALL) == []


def test_edges_from_other_sources_are_never_overwritten(world):
    graph, _ = world
    with graph.session() as s:
        s.run(
            "MATCH (s:Software {software_id:'SOFTWARE:apache:log4j:2_17_1'}), (v:Vulnerability {cve_id:$c}) "
            "CREATE (s)-[:AFFECTED_BY {match_status:'confirmed', match_reason:'scanner finding', matched_by:'scanner-x', source_ref:'S1'}]->(v)",
            c=CVE,
        ).consume()
    summary = run_matching(graph, now=lambda: NOW)
    assert summary.skipped_foreign == 1
    row = by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL))["ASSET-014"]
    assert (row["match_status"], row["matched_by"]) == ("confirmed", "scanner-x")
    again = run_matching(graph, now=lambda: NOW)
    assert again.removed == 0  # foreign edge not removed either


def test_tenant_isolation_with_a_second_tenant_running_the_same_software(world):
    graph, pg = world
    other = {"assets": [{"asset_id": "ASSET-O09", "name": "other-log", "asset_type": "server", "environment": "production",
                         "criticality": "critical", "internet_exposed": True,
                         "software": [{"vendor": "Apache", "product": "Log4j", "version": "2.14.1",
                                       "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}
    import_inventory(graph, pg, "TENANT-OTHER", json.dumps(other), "json", "other.json", now=NOW)
    run_matching(graph, now=lambda: NOW)
    mine = set(by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL)))
    theirs = set(by_asset(get_affected_assets(graph, "TENANT-OTHER", CVE, statuses=ALL)))
    assert theirs == {"ASSET-O09"}
    assert "ASSET-O09" not in mine and not (mine & theirs)
    assert get_affected_assets(graph, "TENANT-NOBODY", CVE, statuses=ALL) == []


def test_cves_without_configurations_create_no_edges(graph, pg):
    # Real fixture records; page-0 holds CVEs that NVD has not analyzed yet (no configurations).
    sync.run_nvd_sync(
        graph, pg, nvd_client({0: load("nvd/page-0.json"), 2: load("nvd/page-2.json")}),
        since=datetime(2026, 11, 1, tzinfo=UTC), until=datetime(2026, 11, 2, tzinfo=UTC), now=lambda: NOW,
    )
    import_seed(graph, pg, "inventory-demo", TENANT)
    with graph.session() as s:
        unconfigured = s.run(
            "MATCH (v:Vulnerability) WHERE v.configurations_json = '[]' RETURN count(v) AS n").single()["n"]
    assert unconfigured >= 1
    run_matching(graph, now=lambda: NOW)
    with graph.session() as s:
        edges = s.run("MATCH (:Software)-[m:AFFECTED_BY]->(v:Vulnerability) WHERE v.configurations_json = '[]' RETURN count(m) AS n").single()["n"]
    assert edges == 0


def test_matching_a_subset_of_software(world):
    graph, _ = world
    summary = run_matching(graph, ["SOFTWARE:apache:log4j:2_14_1"], now=lambda: NOW)
    assert (summary.software_considered, summary.created) == (1, 1)
    assert set(by_asset(get_affected_assets(graph, TENANT, CVE, statuses=ALL))) == {"ASSET-013"}


def test_unrelated_example_vendor_software_is_untouched(world):
    graph, _ = world
    run_matching(graph, now=lambda: NOW)
    with graph.session() as s:
        n = s.run("MATCH (s:Software {vendor:'Example Vendor'})-[m:AFFECTED_BY]->() RETURN count(m) AS n").single()["n"]
    assert n == 0


# ---- freshness (task 4.5) --------------------------------------------------------------------
def test_freshness_returns_both_timestamps(world):
    graph, pg = world
    run_matching(graph, now=lambda: NOW)
    now = NOW + timedelta(days=3)
    for sid in ("nvd", "cisa_kev"):
        source_sync.record_result(pg, source_sync.SyncResult(source_id=sid, attempted_at=NOW))
    with pg.cursor() as cur:  # make the intelligence syncs recent relative to `now`, the inventory old
        cur.execute("UPDATE source_sync SET last_success_at = %s", (now - timedelta(hours=1),))
    pg.commit()
    out = get_affected_assets_with_freshness(graph, pg, TENANT, CVE, now=now)
    assert {r["asset_id"] for r in out["results"]} == {"ASSET-013", "ASSET-015", "ASSET-016"}
    f = out["freshness"]
    assert f["intelligence"]["nvd_last_success_at"] and f["intelligence"]["kev_last_success_at"]
    assert f["inventory_last_imported_at"].startswith("2026-11-19T12:00:00")
    # A fresh CVE feed does not make an old inventory current: only the inventory is flagged.
    assert len(out["warnings"]) == 1 and "Asset inventory" in out["warnings"][0]


def test_freshness_warns_when_sources_were_never_synced(graph, pg):
    out = get_affected_assets_with_freshness(graph, pg, TENANT, CVE)
    assert out["results"] == []
    assert out["freshness"]["intelligence"] == {"nvd_last_success_at": None, "kev_last_success_at": None}
    assert out["freshness"]["inventory_last_imported_at"] is None
    assert len(out["warnings"]) == 3 and all("never" in w for w in out["warnings"])


def test_inventory_time_falls_back_to_graph_when_no_import_record(graph, pg):
    from ingestion import seed_loader

    seed_loader.load_seed(graph)  # writes assets with inventory_imported_at but no inventory_import row
    out = get_affected_assets_with_freshness(graph, pg, TENANT, CVE, now=datetime(2026, 11, 2, tzinfo=UTC))
    assert out["freshness"]["inventory_last_imported_at"] == "2026-11-01T00:00:00+00:00"
    assert not any("Asset inventory" in w for w in out["warnings"])  # imported yesterday relative to `now`


def test_old_intelligence_triggers_stale_warning_independent_of_inventory(world):
    graph, pg = world
    source_sync.record_result(pg, source_sync.SyncResult(source_id="nvd", attempted_at=NOW))
    source_sync.record_result(pg, source_sync.SyncResult(source_id="cisa_kev", attempted_at=NOW))
    later = datetime.now(UTC) + timedelta(days=30)
    out = get_affected_assets_with_freshness(graph, pg, TENANT, CVE, now=later)
    assert sum("older than" in w for w in out["warnings"]) == 3
