import pytest
from neo4j.exceptions import ClientError

from graph_queries.affected_assets import MAX_LIMIT, get_affected_assets
from ingestion import seed_loader


def ids(rows):
    return {r["asset_id"] for r in rows}


def counts(driver):
    with driver.session() as s:
        nodes = s.run("MATCH (n) WHERE n.synthetic = true RETURN count(n) AS c").single()["c"]
        rels = s.run(
            "MATCH (a {synthetic: true})-[r]->(b {synthetic: true}) RETURN count(r) AS c"
        ).single()["c"]
    return nodes, rels


def test_expected_assets_returned(seeded):
    rows = get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001")
    assert ids(rows) == {"ASSET-001", "ASSET-002", "ASSET-008"}
    row = next(r for r in rows if r["asset_id"] == "ASSET-001")
    assert row["match_status"] == "confirmed"
    assert row["match_reason"]
    assert row["software"]["version"] == "1.2.3"
    assert row["software"]["cpe"].startswith("cpe:2.3:a:")
    assert row["cve_id"] == "CVE-DEMO-0001"
    assert row["evidence"] and row["evidence"][0]["source_name"]
    assert row["evidence"][0]["collected_at"]


def test_negative_case_not_returned(seeded):
    # ASSET-003 runs the fixed release 1.3.0 (not_affected).
    assert "ASSET-003" not in ids(get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001"))
    # It is only visible when not_affected is explicitly requested, with that status.
    rows = get_affected_assets(
        seeded, "TENANT-DEMO", "CVE-DEMO-0001", statuses=["not_affected"]
    )
    assert [(r["asset_id"], r["match_status"]) for r in rows] == [("ASSET-003", "not_affected")]


def test_unknown_case_is_flagged_not_guessed(seeded):
    rows = {r["asset_id"]: r for r in get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0002")}
    assert set(rows) == {"ASSET-004", "ASSET-005", "ASSET-011"}
    assert rows["ASSET-004"]["match_status"] == "confirmed"
    assert rows["ASSET-005"]["match_status"] == "unknown"
    assert rows["ASSET-005"]["software"]["version"] is None


def test_unrelated_assets_never_returned(seeded):
    # ASSET-007 (DB 8.1.0) and ASSET-012 (no software) match nothing.
    all_ids = set()
    for cve in ("CVE-DEMO-0001", "CVE-DEMO-0002", "CVE-DEMO-0003"):
        all_ids |= ids(get_affected_assets(seeded, "TENANT-DEMO", cve))
    assert not all_ids & {"ASSET-007", "ASSET-009", "ASSET-010", "ASSET-012"}


def test_tenant_isolation(seeded):
    other = get_affected_assets(seeded, "TENANT-OTHER", "CVE-DEMO-0001")
    assert ids(other) == {"ASSET-O01"}
    demo = get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001")
    assert not any(i.startswith("ASSET-O") for i in ids(demo))
    assert not ids(other) & ids(demo)
    # A tenant that does not exist sees nothing.
    assert get_affected_assets(seeded, "TENANT-NOPE", "CVE-DEMO-0001") == []


def test_tenant_filter_also_applies_to_installation(seeded):
    # A corrupted installation edge (asset tenant OTHER, edge tenant DEMO) must match neither tenant.
    with seeded.session() as s:
        s.run(
            "MATCH (a:Asset {asset_id: 'ASSET-O01'}), (sw:Software {product: 'Example DB', version: '8.0.1'}) "
            "MERGE (a)-[r:RUNS]->(sw) SET r.tenant_id = 'TENANT-DEMO', r.synthetic = true"
        ).consume()
    assert ids(get_affected_assets(seeded, "TENANT-OTHER", "CVE-DEMO-0003")) == {"ASSET-O02"}
    assert "ASSET-O01" not in ids(get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0003"))


def test_reseed_is_idempotent(seeded):
    before = counts(seeded)
    assert before[0] > 0 and before[1] > 0
    seed_loader.load_seed(seeded)
    seed_loader.load_seed(seeded)
    assert counts(seeded) == before


def test_uniqueness_constraint_enforced(seeded):
    with pytest.raises(ClientError):
        with seeded.session() as s:
            s.run("CREATE (:Asset {asset_id: 'ASSET-001'})").consume()


def test_query_is_parameterized_against_injection(seeded):
    evil = "CVE-DEMO-0001' OR 1=1 //"
    assert get_affected_assets(seeded, "TENANT-DEMO", evil) == []
    assert get_affected_assets(seeded, "TENANT-DEMO' OR 1=1 //", "CVE-DEMO-0001") == []


def test_results_are_bounded(seeded):
    assert len(get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001", limit=1)) == 1
    with pytest.raises(ValueError):
        get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001", limit=0)
    with pytest.raises(ValueError):
        get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001", limit=MAX_LIMIT + 1)


def test_invalid_status_rejected(seeded):
    with pytest.raises(ValueError):
        get_affected_assets(seeded, "TENANT-DEMO", "CVE-DEMO-0001", statuses=["definitely"])
