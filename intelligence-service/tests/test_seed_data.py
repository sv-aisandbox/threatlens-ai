import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "data/schemas/inventory.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


@pytest.mark.parametrize("name", ["inventory-demo", "inventory-other"])
def test_seed_inventories_match_schema(name):
    data = json.loads((ROOT / f"data/seed/{name}.json").read_text())
    VALIDATOR.validate(data)


def test_seed_has_expected_shape():
    demo = json.loads((ROOT / "data/seed/inventory-demo.json").read_text())
    other = json.loads((ROOT / "data/seed/inventory-other.json").read_text())
    assert demo["tenant_id"] == "TENANT-DEMO" and other["tenant_id"] == "TENANT-OTHER"
    assert 10 <= len(demo["assets"]) <= 20
    ids = [a["asset_id"] for a in demo["assets"] + other["assets"]]
    assert len(ids) == len(set(ids)), "asset ids must be globally unique"
    versions = [s["version"] for a in demo["assets"] for s in a["software"]]
    assert None in versions, "seed needs an unknown-version case"


def test_schema_rejects_bad_cpe():
    bad = {
        "tenant_id": "TENANT-X",
        "tenant_name": "x",
        "assets": [{
            "asset_id": "ASSET-X1", "name": "n", "asset_type": "server",
            "environment": "production", "criticality": "low", "internet_exposed": False,
            "software": [{"vendor": "v", "product": "p", "cpe": "not-a-cpe"}],
        }],
    }
    with pytest.raises(ValidationError):
        VALIDATOR.validate(bad)


def test_schema_accepts_cpe23_and_missing_version():
    ok = {
        "tenant_id": "TENANT-X",
        "tenant_name": "x",
        "assets": [{
            "asset_id": "ASSET-X1", "name": "n", "asset_type": "server",
            "environment": "production", "criticality": "low", "internet_exposed": False,
            "software": [{"vendor": "v", "product": "p", "version": None,
                          "cpe": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"}],
        }],
    }
    VALIDATOR.validate(ok)
