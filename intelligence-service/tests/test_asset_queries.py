"""Direct tests of the tenant-scoped asset query functions that back the MCP asset tools."""

import pytest

from graph_queries import assets, vulnerability


def ids(result):
    return [r["asset_id"] for r in result["results"]]


def test_search_is_tenant_scoped_and_filterable(seeded):
    demo = assets.search_assets(seeded, "TENANT-DEMO", limit=100)
    other = assets.search_assets(seeded, "TENANT-OTHER", limit=100)
    assert len(demo["results"]) == 16 and len(other["results"]) == 5
    assert not set(ids(demo)) & set(ids(other))
    assert ids(assets.search_assets(seeded, "TENANT-DEMO", criticality="critical", environment="production")) == [
        "ASSET-001", "ASSET-002", "ASSET-006"]
    # the query matches asset names: ASSET-004 (edge-proxy-01) is internet-exposed and excluded by the filter
    assert ids(assets.search_assets(seeded, "TENANT-DEMO", internet_exposed=False, query="proxy")) == ["ASSET-005"]
    assert ids(assets.search_assets(seeded, "TENANT-DEMO", internet_exposed=True, query="proxy")) == ["ASSET-004"]
    assert assets.search_assets(seeded, "TENANT-NOBODY") == {"results": [], "truncated": False}


def test_search_matches_an_exact_asset_id_case_insensitively_but_only_within_the_tenant(seeded):
    assert ids(assets.search_assets(seeded, "TENANT-DEMO", query="asset-013")) == ["ASSET-013"]
    assert assets.search_assets(seeded, "TENANT-DEMO", query="asset-o05")["results"] == []


def test_search_is_parameterized(seeded):
    assert assets.search_assets(seeded, "TENANT-DEMO", query="x') OR true //")["results"] == []
    assert assets.search_assets(seeded, "TENANT-DEMO' OR 1=1 //", limit=100)["results"] == []


def test_limits_are_bounded_and_flag_truncation(seeded):
    page = assets.search_assets(seeded, "TENANT-DEMO", limit=3)
    assert len(page["results"]) == 3 and page["truncated"] is True
    for bad in (0, 101, -1, True, "5"):
        with pytest.raises(ValueError):
            assets.search_assets(seeded, "TENANT-DEMO", limit=bad)


@pytest.mark.parametrize("kwargs", [{"environment": "moon"}, {"criticality": "urgent"}, {"query": ""}, {"query": "x" * 101}])
def test_invalid_filters_are_rejected(seeded, kwargs):
    with pytest.raises(ValueError):
        assets.search_assets(seeded, "TENANT-DEMO", **kwargs)


def test_asset_details_and_cross_tenant_lookup(seeded):
    details = assets.get_asset(seeded, "TENANT-DEMO", "ASSET-001")
    assert details["name"] == "payment-api-01" and details["software_count"] == 1
    assert assets.get_asset(seeded, "TENANT-OTHER", "ASSET-001") is None  # another tenant's asset looks missing
    assert assets.get_asset(seeded, "TENANT-DEMO", "ASSET-999") is None
    assert assets.get_asset(seeded, "TENANT-DEMO", "ASSET-012")["software_count"] == 0  # asset with no software


@pytest.mark.parametrize("bad", ["", "asset-001", "ASSET-001'; MATCH (n) DETACH DELETE n //", "X" * 80, "../ASSET-1"])
def test_asset_ids_are_validated(seeded, bad):
    with pytest.raises(ValueError):
        assets.get_asset(seeded, "TENANT-DEMO", bad)
    with pytest.raises(ValueError):
        assets.get_asset_software(seeded, "TENANT-DEMO", bad)


def test_asset_software_findings(seeded):
    out = assets.get_asset_software(seeded, "TENANT-DEMO", "ASSET-001")
    sw = out["software"][0]
    assert (sw["vendor"], sw["product"], sw["version"]) == ("Example Vendor", "Example Server", "1.2.3")
    assert [(f["cve_id"], f["match_status"]) for f in sw["findings"]] == [("CVE-DEMO-0001", "confirmed")]
    assert assets.get_asset_software(seeded, "TENANT-OTHER", "ASSET-001") is None
    hidden = assets.get_asset_software(seeded, "TENANT-DEMO", "ASSET-003")["software"][0]["findings"]
    shown = assets.get_asset_software(seeded, "TENANT-DEMO", "ASSET-003", ("not_affected",))["software"][0]["findings"]
    assert hidden == [] and [f["match_status"] for f in shown] == ["not_affected"]
    with pytest.raises(ValueError):
        assets.get_asset_software(seeded, "TENANT-DEMO", "ASSET-001", ("definitely",))


def test_critical_assets_rank_by_confirmed_vulnerabilities_then_exposure(seeded):
    out = assets.get_critical_assets(seeded, "TENANT-DEMO")
    assert [(r["asset_id"], r["confirmed_vulnerabilities"], r["internet_exposed"]) for r in out["results"]] == [
        ("ASSET-001", 1, True), ("ASSET-002", 1, True), ("ASSET-006", 1, False)]
    assert ids(assets.get_critical_assets(seeded, "TENANT-DEMO", environment="staging")) == []
    # ASSET-O05 runs Log4j, but the real CVE is not loaded in this graph, so it ranks after ASSET-O01
    assert [(r["asset_id"], r["confirmed_vulnerabilities"]) for r in assets.get_critical_assets(seeded, "TENANT-OTHER")["results"]] == [
        ("ASSET-O01", 1), ("ASSET-O05", 0)]


def test_tenant_is_required(seeded):
    for fn in (assets.search_assets, assets.get_critical_assets):
        with pytest.raises(ValueError):
            fn(seeded, "")
    with pytest.raises(ValueError):
        assets.get_asset(seeded, None, "ASSET-001")


# ---- global vulnerability search / evidence ---------------------------------------------------------------------


def test_vulnerability_search_over_the_synthetic_seed(seeded):
    out = vulnerability.search_vulnerabilities(seeded, "fictional")
    assert [r["cve_id"] for r in out["results"]] == ["CVE-DEMO-0001", "CVE-DEMO-0003", "CVE-DEMO-0002"]  # by CVSS desc
    assert all(r["synthetic"] for r in out["results"])
    assert [r["cve_id"] for r in vulnerability.search_vulnerabilities(seeded, "cve-demo-0002")["results"]] == ["CVE-DEMO-0002"]
    assert vulnerability.search_vulnerabilities(seeded, kev_only=True)["results"] == []
    assert vulnerability.search_vulnerabilities(seeded, "%%", limit=5)["results"] == []  # no wildcard semantics


@pytest.mark.parametrize("kwargs", [{"query": "a"}, {"query": "x" * 101}, {"min_cvss": 10.1}, {"min_cvss": -0.1}, {"limit": 0}, {"limit": 51}])
def test_vulnerability_search_validation(seeded, kwargs):
    with pytest.raises(ValueError):
        vulnerability.search_vulnerabilities(seeded, **kwargs)


def test_vulnerability_evidence(seeded):
    out = vulnerability.get_vulnerability_evidence(seeded, "CVE-DEMO-0001")
    assert out["evidence"][0]["source_name"] == "Synthetic demo advisory" and out["evidence"][0]["content_hash"]
    assert vulnerability.get_vulnerability_evidence(seeded, "CVE-2099-0001") is None
