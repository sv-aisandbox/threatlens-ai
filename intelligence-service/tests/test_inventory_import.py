import json
from datetime import UTC, datetime

import pytest

from ingestion import inventory_import as inv
from ingestion.inventory_import import InventoryFileError, InventoryRow, import_inventory
from tests.helpers import FIXTURES

HEADER = "asset_id,name,asset_type,environment,criticality,internet_exposed,vendor,product,version,cpe\n"
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
GOOD_CSV = (
    HEADER
    + 'ASSET-100,web-01,server,production,high,true,"Example Vendor, Inc.",Example Server,1.2.3,cpe:2.3:a:example_vendor:example_server:1.2.3:*:*:*:*:*:*:*\n'
    + "ASSET-100,web-01,server,production,high,true,Example Vendor,Example Proxy,,\n"
    + "ASSET-101,db-01,database,staging,low,no,,,,\n"
)


def run(graph, pg, data, fmt="csv", tenant="TENANT-DEMO", **kw):
    return import_inventory(graph, pg, tenant, data, fmt, "test-file.csv", now=NOW, **kw)


def scalar(graph, cypher, **params):
    with graph.session() as s:
        return s.run(cypher, **params).single()[0]


def test_csv_import_creates_tenant_scoped_graph_and_import_record(graph, pg):
    r = run(graph, pg, GOOD_CSV)
    assert (r.rows_received, r.rows_accepted, r.rows_rejected, r.assets_imported, r.software_imported) == (3, 3, 0, 2, 2)
    assert scalar(graph, "MATCH (a:Asset {tenant_id:'TENANT-DEMO'}) RETURN count(a)") == 2
    assert scalar(graph, "MATCH (:Asset {tenant_id:'TENANT-DEMO'})-[r:RUNS {tenant_id:'TENANT-DEMO'}]->(:Software) RETURN count(r)") == 2
    assert scalar(graph, "MATCH (a:Asset {asset_id:'ASSET-100'}) RETURN a.inventory_imported_at") == "2026-11-19T12:00:00.000Z"
    assert scalar(graph, "MATCH (a:Asset {asset_id:'ASSET-101'}) RETURN a.internet_exposed") is False
    assert scalar(graph, "MATCH (t:Tenant {tenant_id:'TENANT-DEMO'})-[:OWNS]->(a) RETURN count(a)") == 2
    with pg.cursor() as cur:
        cur.execute("SELECT tenant_id, source_format, rows_received, rows_accepted, rows_rejected, imported_at FROM inventory_import")
        row = cur.fetchall()
    assert row == [("TENANT-DEMO", "csv", 3, 3, 0, NOW)]


def test_original_values_are_kept(graph, pg):
    run(graph, pg, GOOD_CSV)
    sw = scalar(graph, "MATCH (s:Software {product:'Example Server'}) RETURN s")
    assert sw["vendor"] == "Example Vendor, Inc." and sw["version"] == "1.2.3"
    assert sw["cpe"] == "cpe:2.3:a:example_vendor:example_server:1.2.3:*:*:*:*:*:*:*"
    assert scalar(graph, "MATCH (s:Software {product:'Example Proxy'}) RETURN s.version") is None  # unknown stays unknown


def test_reimport_is_idempotent_in_graph_but_audited_in_postgres(graph, pg):
    run(graph, pg, GOOD_CSV)
    before = scalar(graph, "MATCH (n) RETURN count(n)"), scalar(graph, "MATCH ()-[r]->() RETURN count(r)")
    run(graph, pg, GOOD_CSV)
    assert (scalar(graph, "MATCH (n) RETURN count(n)"), scalar(graph, "MATCH ()-[r]->() RETURN count(r)")) == before
    with pg.cursor() as cur:
        cur.execute("SELECT count(*) FROM inventory_import")
        assert cur.fetchone()[0] == 2


def test_row_level_rejects_import_only_accepted_rows(graph, pg):
    secret = "SECRET-VALUE-XYZ"
    csv_text = (
        HEADER
        + "ASSET-200,ok-01,server,production,high,true,,,,\n"                              # row 2 ok
        + f"ASSET-201,{secret},mainframe,production,high,true,,,,\n"                          # row 3 bad asset_type
        + "ASSET-202,half-01,server,production,high,true,OnlyVendor,,,\n"                   # row 4 vendor without product
        + "ASSET-203,badcpe-01,server,production,high,true,V,P,1.0,not-a-cpe\n"             # row 5 bad cpe
        + "bad id,x,server,production,high,true,,,,\n"                                       # row 6 bad asset id
        + "ASSET-204,flag-01,server,production,high,maybe,,,,\n"                            # row 7 bad boolean
        + "ASSET-200,ok-01,server,production,critical,true,V,P,1.0,\n"                      # row 8 conflicts with row 2
        + "ASSET-205,extra-01,server,production,high,true,,,,,surplus-cell\n"                # row 9 too many cells
    )
    r = run(graph, pg, csv_text)
    assert (r.rows_received, r.rows_accepted, r.rows_rejected) == (8, 1, 7)
    refs = {x["ref"]: x for x in r.rejects}
    assert set(refs) == {f"row {n}" for n in range(3, 10)}
    assert {e["field"] for e in refs["row 3"]["errors"]} >= {"asset_type"}
    assert refs["row 6"]["asset_id"] is None  # invalid ids are not echoed
    assert refs["row 8"]["errors"] == [{"field": "criticality", "type": "conflicts_with_earlier_row"}]
    assert scalar(graph, "MATCH (a:Asset) RETURN count(a)") == 1
    assert secret not in json.dumps(r.rejects) and "OnlyVendor" not in json.dumps(r.rejects)
    with pg.cursor() as cur:
        cur.execute("SELECT reject_report::text, rows_rejected FROM inventory_import")
        text, n = cur.fetchone()
    assert n == 7 and secret not in text


def test_fully_rejected_file_imports_nothing(graph, pg):
    r = run(graph, pg, HEADER + "x,x,x,x,x,x,,,,\n")
    assert r.rows_accepted == 0 and r.assets_imported == 0
    assert scalar(graph, "MATCH (n) RETURN count(n)") == 0


def test_json_import_with_nested_software(graph, pg):
    doc = {"tenant_id": "TENANT-DEMO", "tenant_name": "Demo", "assets": [
        {"asset_id": "ASSET-300", "name": "a", "asset_type": "server", "environment": "production",
         "criticality": "low", "internet_exposed": False,
         "software": [{"vendor": "V", "product": "P", "version": "1.0"}, {"vendor": "V", "product": "Q"}]},
        {"asset_id": "ASSET-301", "name": "bad", "asset_type": "server", "environment": "moon",
         "criticality": "low", "internet_exposed": False},
    ]}
    r = run(graph, pg, json.dumps(doc), fmt="json")
    assert (r.rows_received, r.rows_accepted, r.rows_rejected, r.assets_imported, r.software_imported) == (3, 2, 1, 1, 2)
    assert r.rejects[0]["ref"] == "assets[1]"
    assert scalar(graph, "MATCH (t:Tenant {tenant_id:'TENANT-DEMO'}) RETURN t.name") == "Demo"


@pytest.mark.parametrize(
    "data,fmt",
    [("not json", "json"), ('{"assets": "nope"}', "json"), ("[1,2]", "json"),
     ("asset_id,name\nA,B\n", "csv"), (b"\xff\xfe\x00bad", "csv")],
)
def test_unusable_files_raise(graph, pg, data, fmt):
    with pytest.raises(InventoryFileError):
        run(graph, pg, data, fmt=fmt)


def test_tenant_in_file_must_match_trusted_tenant(graph, pg):
    doc = {"tenant_id": "TENANT-OTHER", "assets": []}
    with pytest.raises(InventoryFileError, match="tenant"):
        run(graph, pg, json.dumps(doc), fmt="json")
    assert scalar(graph, "MATCH (n) RETURN count(n)") == 0


@pytest.mark.parametrize("tenant", ["tenant-demo", "TENANT-DEMO'; MATCH (n) DETACH DELETE n //", "", "OTHER"])
def test_invalid_tenant_ids_are_refused(graph, pg, tenant):
    with pytest.raises(ValueError):
        run(graph, pg, GOOD_CSV, tenant=tenant)


def test_asset_owned_by_another_tenant_is_rejected_generically(graph, pg):
    run(graph, pg, HEADER + "ASSET-400,theirs,server,production,high,true,,,,\n", tenant="TENANT-OTHER")
    r = run(graph, pg, HEADER + "ASSET-400,mine,server,staging,low,false,V,P,1.0,\n", tenant="TENANT-DEMO")
    assert (r.rows_accepted, r.rows_rejected) == (0, 1)
    assert r.rejects[0]["errors"] == [{"field": "asset_id", "type": "not_available"}]
    assert "OTHER" not in json.dumps(r.rejects)
    a = scalar(graph, "MATCH (a:Asset {asset_id:'ASSET-400'}) RETURN a")
    assert a["tenant_id"] == "TENANT-OTHER" and a["name"] == "theirs"  # not overwritten


def test_size_and_row_limits(graph, pg, monkeypatch):
    monkeypatch.setattr(inv, "MAX_BYTES", 50)
    with pytest.raises(InventoryFileError, match="large"):
        run(graph, pg, GOOD_CSV)
    monkeypatch.setattr(inv, "MAX_BYTES", 5 * 1024 * 1024)
    monkeypatch.setattr(inv, "MAX_ROWS", 2)
    with pytest.raises(InventoryFileError, match="too many"):
        run(graph, pg, GOOD_CSV)


def test_bom_and_formula_like_cells_are_plain_data(graph, pg):
    payload = "=HYPERLINK(\"http://evil.invalid\",\"x\")"
    text = "﻿" + HEADER + f'ASSET-500,"{payload.replace(chr(34), chr(34) * 2)}",server,production,low,false,,,,\n'
    r = run(graph, pg, text.encode("utf-8"))
    assert r.rows_accepted == 1
    assert scalar(graph, "MATCH (a:Asset {asset_id:'ASSET-500'}) RETURN a.name") == payload  # stored, never executed


def test_duplicate_software_rows_are_merged(graph, pg):
    row = "ASSET-600,a,server,production,low,false,V,P,1.0,\n"
    r = run(graph, pg, HEADER + row + row)
    assert (r.rows_accepted, r.software_imported) == (2, 1)
    assert scalar(graph, "MATCH (:Asset {asset_id:'ASSET-600'})-[r:RUNS]->() RETURN count(r)") == 1


def test_seed_inventories_import_cleanly(graph, pg):
    for name, tenant in (("inventory-demo", "TENANT-DEMO"), ("inventory-other", "TENANT-OTHER")):
        data = (FIXTURES.parent / "seed" / f"{name}.json").read_bytes()
        r = import_inventory(graph, pg, tenant, data, "json", f"{name}.json", now=NOW)
        assert r.rows_rejected == 0 and r.assets_imported > 0


def test_row_enums_match_the_json_schema():
    schema = json.loads((FIXTURES.parent / "schemas" / "inventory.schema.json").read_text())
    props = schema["$defs"]["asset"]["properties"]
    for field in ("asset_type", "environment", "criticality"):
        assert set(props[field]["enum"]) == set(InventoryRow.model_fields[field].annotation.__args__), field
