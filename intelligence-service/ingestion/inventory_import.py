"""Asset inventory importer (JSON or CSV) with row-level validation and a reject report.

The tenant is supplied by the caller (trusted context); a tenant_id inside a file must match it and is
never used to choose a tenant. Only accepted rows are imported. Original vendor/product/version/CPE
strings are stored unchanged. Reject reports contain field names and error types, never cell values.
"""

import csv
import io
import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import psycopg
from neo4j import Driver, ManagedTransaction
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from correlation.cpe import parse_cpe23

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 20_000
ASSET_ID_RE = re.compile(r"^ASSET-[A-Z0-9-]{1,40}$")
TENANT_ID_RE = re.compile(r"^TENANT-[A-Z0-9-]{1,40}$")
CSV_REQUIRED = ("asset_id", "name", "asset_type", "environment", "criticality", "internet_exposed")
CSV_OPTIONAL = ("vendor", "product", "version", "cpe")
ASSET_ATTRS = ("name", "asset_type", "environment", "criticality", "internet_exposed")

AssetType = Literal["server", "workstation", "network_device", "container", "database", "application"]
Environment = Literal["production", "staging", "development"]
Criticality = Literal["critical", "high", "medium", "low"]


class InventoryFileError(ValueError):
    """The whole file is unusable (wrong shape, too large, tenant mismatch).

    `code` is stable and drawn from a fixed set so callers can show their own message; `details` only ever holds
    names from our own fixed vocabulary (for example the required column names), never file content.
    """

    CODES = ("not_json", "bad_shape", "tenant_mismatch", "too_large", "not_utf8", "missing_columns", "too_many_rows", "bad_format")

    def __init__(self, code: str, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or []


class InventoryRow(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    asset_id: str = Field(pattern=ASSET_ID_RE.pattern)
    name: str = Field(min_length=1, max_length=200)
    asset_type: AssetType
    environment: Environment
    criticality: Criticality
    internet_exposed: bool
    vendor: str | None = Field(default=None, max_length=200)
    product: str | None = Field(default=None, max_length=200)
    version: str | None = Field(default=None, max_length=100)
    cpe: str | None = Field(default=None, max_length=500)

    @field_validator("vendor", "product", "version", "cpe", mode="before")
    @classmethod
    def _blank_to_none(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v

    @model_validator(mode="after")
    def _software_consistency(self) -> "InventoryRow":
        if (self.vendor is None) != (self.product is None):
            raise ValueError("vendor and product must be given together")
        if self.vendor is None and (self.version or self.cpe):
            raise ValueError("version/cpe need a vendor and product")
        if self.cpe is not None and parse_cpe23(self.cpe) is None:
            raise ValueError("cpe is not a valid CPE 2.3 string")
        return self


@dataclass
class ImportReport:
    import_id: str | None = None
    tenant_id: str = ""
    source_format: str = ""
    imported_at: datetime | None = None
    rows_received: int = 0
    rows_accepted: int = 0
    rows_rejected: int = 0
    assets_imported: int = 0
    software_imported: int = 0
    rejects: list[dict[str, Any]] = field(default_factory=list)
    software_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "import_id": self.import_id,
            "tenant_id": self.tenant_id,
            "rows_received": self.rows_received,
            "rows_accepted": self.rows_accepted,
            "rows_rejected": self.rows_rejected,
            "assets_imported": self.assets_imported,
            "software_imported": self.software_imported,
            "rejects": self.rejects,
        }


def software_id(vendor: str, product: str, version: str | None) -> str:
    """Deterministic ID so the same product/version is one shared Software node."""

    def slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")

    return f"SOFTWARE:{slug(vendor)}:{slug(product)}:{slug(version) if version else 'unknown'}"


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---- parsing ---------------------------------------------------------------------------------


def _json_rows(text: str, tenant_id: str) -> tuple[list[tuple[str, Any]], str | None]:
    try:
        doc = json.loads(text)
    except ValueError:
        raise InventoryFileError("not_json", "file is not valid JSON") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("assets"), list):
        raise InventoryFileError("bad_shape", "JSON must be an object with an 'assets' list")
    declared = doc.get("tenant_id")
    if declared is not None and declared != tenant_id:
        raise InventoryFileError("tenant_mismatch", "tenant_id in file does not match the import tenant")
    name = doc.get("tenant_name")
    rows: list[tuple[str, Any]] = []
    for i, asset in enumerate(doc["assets"]):
        if not isinstance(asset, dict):
            rows.append((f"assets[{i}]", asset))
            continue
        base = {k: v for k, v in asset.items() if k != "software"}
        software = asset.get("software")
        if software is None or software == []:
            rows.append((f"assets[{i}]", base))
        elif not isinstance(software, list):
            rows.append((f"assets[{i}].software", None))
        else:
            for j, sw in enumerate(software):
                merged = {**base, **sw} if isinstance(sw, dict) else None
                rows.append((f"assets[{i}].software[{j}]", merged))
    return rows, name if isinstance(name, str) else None


def _csv_rows(text: str) -> list[tuple[str, Any]]:
    reader = csv.DictReader(io.StringIO(text, newline=""))
    headers = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in CSV_REQUIRED if c not in headers]
    if missing:
        raise InventoryFileError("missing_columns", f"CSV is missing required columns: {', '.join(missing)}", missing)
    reader.fieldnames = headers
    rows = []
    for line_no, rec in enumerate(reader, start=2):
        if None in rec:  # more cells than headers
            rows.append((f"row {line_no}", None))
        else:
            rows.append((f"row {line_no}", {k: v for k, v in rec.items() if k in CSV_REQUIRED + CSV_OPTIONAL}))
    return rows


def _reject(ref: str, raw: Any, errors: list[dict[str, str]]) -> dict[str, Any]:
    candidate = raw.get("asset_id") if isinstance(raw, dict) else None
    shown = candidate if isinstance(candidate, str) and ASSET_ID_RE.fullmatch(candidate) else None
    return {"ref": ref, "asset_id": shown, "errors": errors}


def _validate(ref: str, raw: Any) -> tuple[InventoryRow | None, dict[str, Any] | None]:
    if not isinstance(raw, dict):
        return None, _reject(ref, raw, [{"field": "(row)", "type": "not_an_object"}])
    try:
        return InventoryRow.model_validate(raw), None
    except ValidationError as exc:
        errors = [
            {"field": ".".join(str(p) for p in e["loc"]) or "(row)", "type": e["type"]}
            for e in exc.errors()[:8]
        ]
        return None, _reject(ref, raw, errors)


# ---- graph write (shared with the synthetic seed loader) --------------------------------------


def write_assets(
    tx: ManagedTransaction,
    tenant_id: str,
    tenant_name: str,
    assets: list[dict[str, Any]],
    imported_at: str,
    synthetic: bool = False,
) -> None:
    """MERGE tenant, assets and installations. `assets` items carry a `software` list. Idempotent."""
    extra = {"synthetic": True} if synthetic else {}
    ids = [a["asset_id"] for a in assets]
    clash = tx.run(
        "MATCH (n:Asset) WHERE n.asset_id IN $ids AND n.tenant_id <> $tenant_id RETURN n.asset_id AS asset_id",
        ids=ids,
        tenant_id=tenant_id,
    ).data()
    if clash:
        raise ValueError("asset ids already belong to another tenant")
    tx.run(
        "MERGE (t:Tenant {tenant_id: $tenant_id}) "
        "ON CREATE SET t.name = $name SET t += $extra",
        tenant_id=tenant_id,
        name=tenant_name,
        extra=extra,
    )
    flat_assets = [{k: v for k, v in a.items() if k != "software"} for a in assets]
    tx.run(
        """
        MATCH (t:Tenant {tenant_id: $tenant_id})
        UNWIND $assets AS a
        MERGE (n:Asset {asset_id: a.asset_id})
        SET n.name = a.name, n.asset_type = a.asset_type, n.environment = a.environment,
            n.criticality = a.criticality, n.internet_exposed = a.internet_exposed,
            n.tenant_id = $tenant_id, n.inventory_imported_at = $imported_at, n += $extra
        MERGE (t)-[o:OWNS]->(n)
        SET o += $extra
        """,
        tenant_id=tenant_id,
        assets=flat_assets,
        imported_at=imported_at,
        extra=extra,
    )
    installs = [
        {
            "asset_id": a["asset_id"],
            "software_id": software_id(s["vendor"], s["product"], s.get("version")),
            "vendor": s["vendor"],
            "product": s["product"],
            "version": s.get("version"),
            "cpe": s.get("cpe"),
        }
        for a in assets
        for s in a.get("software", [])
    ]
    tx.run(
        """
        UNWIND $installs AS i
        MATCH (a:Asset {asset_id: i.asset_id, tenant_id: $tenant_id})
        MERGE (s:Software {software_id: i.software_id})
        SET s.vendor = i.vendor, s.product = i.product, s.version = i.version,
            s.cpe = coalesce(i.cpe, s.cpe), s += $extra
        MERGE (a)-[r:RUNS]->(s)
        SET r.tenant_id = $tenant_id, r += $extra
        """,
        tenant_id=tenant_id,
        installs=installs,
        extra=extra,
    )


# ---- public entry point -----------------------------------------------------------------------


def import_inventory(
    driver: Driver,
    conn: psycopg.Connection,
    tenant_id: str,
    data: bytes | str,
    fmt: Literal["json", "csv"],
    source_name: str,
    *,
    tenant_name: str | None = None,
    now: datetime | None = None,
) -> ImportReport:
    if not TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError("invalid tenant_id")
    raw_bytes = data.encode() if isinstance(data, str) else data
    if len(raw_bytes) > MAX_BYTES:
        raise InventoryFileError("too_large", "file is too large")
    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InventoryFileError("not_utf8", "file is not valid UTF-8") from None

    declared_name = None
    if fmt == "json":
        rows, declared_name = _json_rows(text, tenant_id)
    elif fmt == "csv":
        rows = _csv_rows(text)
    else:
        raise InventoryFileError("bad_format", "fmt must be 'json' or 'csv'")
    if len(rows) > MAX_ROWS:
        raise InventoryFileError("too_many_rows", f"too many rows (limit {MAX_ROWS})")

    imported_at = now or datetime.now(UTC)
    report = ImportReport(tenant_id=tenant_id, source_format=fmt, imported_at=imported_at, rows_received=len(rows))

    accepted: list[tuple[str, InventoryRow]] = []
    for ref, raw in rows:
        row, reject = _validate(ref, raw)
        if reject:
            report.rejects.append(reject)
        else:
            accepted.append((ref, row))

    # An asset's attributes must agree across all of its rows; the first row defines them.
    first: dict[str, InventoryRow] = {}
    consistent: list[tuple[str, InventoryRow]] = []
    for ref, row in accepted:
        base = first.setdefault(row.asset_id, row)
        diffs = [a for a in ASSET_ATTRS if getattr(base, a) != getattr(row, a)]
        if diffs:
            report.rejects.append(
                {"ref": ref, "asset_id": row.asset_id, "errors": [{"field": d, "type": "conflicts_with_earlier_row"} for d in diffs]}
            )
        else:
            consistent.append((ref, row))

    # Asset ids owned by another tenant are rejected with a generic reason (no cross-tenant disclosure).
    with driver.session() as session:
        foreign = {
            r["asset_id"]
            for r in session.run(
                "MATCH (n:Asset) WHERE n.asset_id IN $ids AND n.tenant_id <> $tenant_id RETURN n.asset_id AS asset_id",
                ids=list({r.asset_id for _, r in consistent}),
                tenant_id=tenant_id,
            )
        }
    final: list[InventoryRow] = []
    for ref, row in consistent:
        if row.asset_id in foreign:
            report.rejects.append({"ref": ref, "asset_id": row.asset_id, "errors": [{"field": "asset_id", "type": "not_available"}]})
        else:
            final.append(row)

    assets: dict[str, dict[str, Any]] = {}
    for row in final:
        asset = assets.setdefault(
            row.asset_id,
            {**{a: getattr(row, a) for a in ("asset_id",) + ASSET_ATTRS}, "software": []},
        )
        if row.vendor and row.product:
            entry = {"vendor": row.vendor, "product": row.product, "version": row.version, "cpe": row.cpe}
            sid = software_id(row.vendor, row.product, row.version)
            if all(software_id(s["vendor"], s["product"], s["version"]) != sid for s in asset["software"]):
                asset["software"].append(entry)

    report.rows_accepted = len(final)
    report.rows_rejected = len(report.rejects)
    report.assets_imported = len(assets)
    report.software_ids = sorted(
        {software_id(s["vendor"], s["product"], s["version"]) for a in assets.values() for s in a["software"]}
    )
    report.software_imported = len(report.software_ids)

    if assets:
        name = tenant_name or declared_name or tenant_id
        with driver.session() as session:
            session.execute_write(write_assets, tenant_id, name, list(assets.values()), _iso(imported_at))

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO inventory_import (tenant_id, source_name, source_format, imported_at, rows_received,
                rows_accepted, rows_rejected, assets_imported, software_imported, reject_report)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            RETURNING import_id
            """,
            (
                tenant_id,
                re.sub(r"[^A-Za-z0-9._ -]", "_", source_name)[:200] or "upload",
                fmt,
                imported_at,
                report.rows_received,
                report.rows_accepted,
                report.rows_rejected,
                report.assets_imported,
                report.software_imported,
                json.dumps(report.rejects),
            ),
        )
        report.import_id = str(cur.fetchone()[0])
    conn.commit()
    return report


def latest_import_time(conn: psycopg.Connection, tenant_id: str) -> datetime | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT max(imported_at) FROM inventory_import WHERE tenant_id = %s AND rows_accepted > 0",
            (tenant_id,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def list_imports(conn: psycopg.Connection, tenant_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """Recent import attempts for one tenant, newest first. Counters only; use get_import for the reject report."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT import_id, source_name, source_format, imported_at, rows_received, rows_accepted, rows_rejected,
                   assets_imported, software_imported
            FROM inventory_import WHERE tenant_id = %s ORDER BY imported_at DESC LIMIT %s
            """,
            (tenant_id, limit),
        )
        cols = ("import_id", "source_name", "source_format", "imported_at", "rows_received", "rows_accepted", "rows_rejected",
                "assets_imported", "software_imported")
        return [
            {**dict(zip(cols, row, strict=True)), "import_id": str(row[0]), "imported_at": row[3].isoformat()}
            for row in cur.fetchall()
        ]


def get_import(conn: psycopg.Connection, tenant_id: str, import_id: str) -> dict[str, Any] | None:
    """One import including its reject report. An import of another tenant is indistinguishable from a missing one."""
    try:
        wanted = str(uuid.UUID(import_id))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("import_id is not a valid identifier") from None
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT import_id, source_name, source_format, imported_at, rows_received, rows_accepted, rows_rejected,
                   assets_imported, software_imported, reject_report
            FROM inventory_import WHERE tenant_id = %s AND import_id = %s
            """,
            (tenant_id, wanted),
        )
        row = cur.fetchone()
    if row is None:
        return None
    cols = ("import_id", "source_name", "source_format", "imported_at", "rows_received", "rows_accepted", "rows_rejected",
            "assets_imported", "software_imported", "rejects")
    out = dict(zip(cols, row, strict=True))
    out["import_id"], out["imported_at"] = str(row[0]), row[3].isoformat()
    return out
