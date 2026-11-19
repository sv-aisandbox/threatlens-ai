"""Sync orchestration: NVD (incremental), CISA KEV (full feed) and single-CVE import.

Operational failures are recorded in `source_sync` (sanitized) and returned as status "failed";
programming errors in validation code are not hidden because only the run itself is wrapped.
"""

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import psycopg
from neo4j import Driver

from ingestion import source_sync
from ingestion.graph_writer import upsert_batch
from ingestion.nvd_client import NvdClient
from ingestion.source_sync import SyncResult
from normalization import kev as kev_norm
from normalization import nvd as nvd_norm
from normalization.nvd import RecordRejected

logger = logging.getLogger(__name__)

NVD_SOURCE = "nvd"
KEV_SOURCE = "cisa_kev"
SINGLE_CVE_SOURCE = "nvd_single_cve"
DEFAULT_INITIAL_DAYS = 7  # first NVD sync without --since; a full backfill must be requested explicitly
BATCH_SIZE = 500
KEV_MAX_BYTES = 20 * 1024 * 1024


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _finish(result: SyncResult) -> SyncResult:
    if result.status != "failed" and result.rejected:
        result.status = "partial"
    return result


def _process_nvd_records(
    driver: Driver, records: list[Any], collected_at: str, result: SyncResult
) -> None:
    rows = []
    for raw in records:
        result.received += 1
        try:
            cve = raw["cve"] if isinstance(raw, dict) else None
            rows.append(nvd_norm.normalize_cve(cve, collected_at))
        except (RecordRejected, KeyError) as exc:
            result.rejected += 1
            logger.warning("Rejected NVD record: %s", exc)
    created, updated = upsert_batch(driver, rows)
    result.created += created
    result.updated += updated


def run_nvd_sync(
    driver: Driver,
    conn: psycopg.Connection,
    client: NvdClient,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    source_id: str = NVD_SOURCE,
    api_key: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> SyncResult:
    started = now()
    result = SyncResult(source_id=source_id, attempted_at=started)
    source_sync.record_attempt(conn, source_id, started)
    try:
        end = until or started
        start = since or source_sync.get_cursor(conn, source_id) or end - timedelta(days=DEFAULT_INITIAL_DAYS)
        if start >= end:
            raise ValueError("sync window is empty (since must be before until)")
        newest: datetime | None = None
        for page in client.iter_modified(start, end):
            vulns = page.get("vulnerabilities")
            if not isinstance(vulns, list):
                raise ValueError("NVD page has no vulnerabilities list")
            _process_nvd_records(driver, vulns, _utc_iso(now()), result)
            for item in vulns:
                try:
                    modified = datetime.fromisoformat(item["cve"]["lastModified"])
                except (KeyError, TypeError, ValueError):
                    continue
                modified = modified.replace(tzinfo=modified.tzinfo or UTC)
                newest = max(newest, modified) if newest else modified
        result.cursor_at = end
        result.source_modified_at = newest
    except Exception as exc:  # noqa: BLE001 - recorded, sanitized, and surfaced as status "failed"
        logger.exception("NVD sync failed")
        result.status = "failed"
        result.error_summary = source_sync.sanitize_error(exc, [api_key])
    _finish(result)
    source_sync.record_result(conn, result)
    return result


def import_single_cve(
    driver: Driver,
    conn: psycopg.Connection,
    client: NvdClient,
    cve_id: str,
    *,
    api_key: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> SyncResult:
    """Allowlisted demo path: one CVE ID (strictly validated) fetched from the fixed NVD endpoint."""
    if not nvd_norm.CVE_ID_RE.fullmatch(cve_id):
        raise ValueError("invalid CVE id")
    started = now()
    result = SyncResult(source_id=SINGLE_CVE_SOURCE, attempted_at=started)
    source_sync.record_attempt(conn, SINGLE_CVE_SOURCE, started)
    try:
        page = client.fetch_cve(cve_id)
        vulns = page.get("vulnerabilities")
        if not isinstance(vulns, list):
            raise ValueError("NVD response has no vulnerabilities list")
        _process_nvd_records(driver, vulns, _utc_iso(started), result)
        if not vulns:
            result.status = "failed"
            result.error_summary = "CVE not found in NVD"
    except Exception as exc:  # noqa: BLE001
        logger.exception("Single CVE import failed")
        result.status = "failed"
        result.error_summary = source_sync.sanitize_error(exc, [api_key])
    _finish(result)
    source_sync.record_result(conn, result)
    return result


def fetch_kev_feed(http: httpx.Client | None = None) -> Any:
    """Download the KEV JSON from the fixed CISA URL (no redirects, size-capped)."""
    owns = http is None
    http = http or httpx.Client(timeout=30.0, follow_redirects=False)
    try:
        with http.stream("GET", kev_norm.KEV_FEED_URL) as resp:
            if resp.status_code != 200:
                raise RuntimeError(f"KEV request failed with HTTP {resp.status_code}")
            body = bytearray()
            for chunk in resp.iter_bytes():
                body.extend(chunk)
                if len(body) > KEV_MAX_BYTES:
                    raise RuntimeError("KEV response too large")
        return json.loads(bytes(body))
    finally:
        if owns:
            http.close()


def run_kev_sync(
    driver: Driver,
    conn: psycopg.Connection,
    fetch: Callable[[], Any] = fetch_kev_feed,
    *,
    source_id: str = KEV_SOURCE,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> SyncResult:
    started = now()
    result = SyncResult(source_id=source_id, attempted_at=started)
    source_sync.record_attempt(conn, source_id, started)
    try:
        feed = kev_norm.parse_feed(fetch())
        collected_at = _utc_iso(started)
        rows: list[dict[str, Any]] = []
        for raw in feed.vulnerabilities:
            result.received += 1
            try:
                rows.append(kev_norm.normalize_entry(raw, collected_at))
            except RecordRejected as exc:
                result.rejected += 1
                logger.warning("Rejected KEV entry: %s", exc)
        for i in range(0, len(rows), BATCH_SIZE):
            created, updated = upsert_batch(driver, rows[i : i + BATCH_SIZE])
            result.created += created
            result.updated += updated
        result.source_modified_at = feed.dateReleased.replace(tzinfo=feed.dateReleased.tzinfo or UTC)
        result.cursor_at = started
    except Exception as exc:  # noqa: BLE001
        logger.exception("KEV sync failed")
        result.status = "failed"
        result.error_summary = source_sync.sanitize_error(exc)
    _finish(result)
    source_sync.record_result(conn, result)
    return result
