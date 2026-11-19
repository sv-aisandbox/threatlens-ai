"""PostgreSQL `source_sync` access (spec section 20.3). Parameterized SQL only."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

ERROR_SUMMARY_MAX = 300


@dataclass
class SyncResult:
    source_id: str
    status: str = "success"  # success | partial | failed
    received: int = 0
    created: int = 0
    updated: int = 0
    rejected: int = 0
    error_summary: str | None = None
    source_modified_at: datetime | None = None
    cursor_at: datetime | None = None
    attempted_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "status": self.status,
            "records_received": self.received,
            "records_created": self.created,
            "records_updated": self.updated,
            "records_rejected": self.rejected,
            "error_summary": self.error_summary,
        }


def sanitize_error(exc: BaseException, secrets: list[str | None] | None = None) -> str:
    """Class name plus a short message with secrets and credential-looking text removed."""
    text = f"{type(exc).__name__}: {exc}"
    for secret in secrets or []:
        if secret:
            text = text.replace(secret, "[redacted]")
    text = re.sub(r"(?i)\b(bearer|basic)\s+\S+", r"\1 [redacted]", text)
    text = re.sub(
        r"(?i)\b(api[-_]?key|token|password|passwd|secret|authorization)\b\s*[=:]\s*(?!\[redacted\])\S+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text[:ERROR_SUMMARY_MAX]


def get_cursor(conn: psycopg.Connection, source_id: str) -> datetime | None:
    with conn.cursor() as cur:
        cur.execute("SELECT sync_cursor_at FROM source_sync WHERE source_id = %s", (source_id,))
        row = cur.fetchone()
    return row[0] if row else None


def record_attempt(conn: psycopg.Connection, source_id: str, at: datetime) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO source_sync (source_id, last_attempt_at) VALUES (%s, %s)
            ON CONFLICT (source_id) DO UPDATE SET last_attempt_at = EXCLUDED.last_attempt_at
            """,
            (source_id, at),
        )
    conn.commit()


def record_result(conn: psycopg.Connection, r: SyncResult) -> None:
    ok = r.status in ("success", "partial")
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO source_sync (
                source_id, last_attempt_at, last_success_at, last_status, records_received,
                records_created, records_updated, records_rejected, error_summary,
                source_modified_at, sync_cursor_at)
            VALUES (%(id)s, %(at)s, %(success_at)s, %(status)s, %(recv)s, %(cr)s, %(up)s, %(rej)s,
                    %(err)s, %(src_mod)s, %(cursor)s)
            ON CONFLICT (source_id) DO UPDATE SET
                last_attempt_at = EXCLUDED.last_attempt_at,
                last_success_at = COALESCE(EXCLUDED.last_success_at, source_sync.last_success_at),
                last_status = EXCLUDED.last_status,
                records_received = EXCLUDED.records_received,
                records_created = EXCLUDED.records_created,
                records_updated = EXCLUDED.records_updated,
                records_rejected = EXCLUDED.records_rejected,
                error_summary = EXCLUDED.error_summary,
                source_modified_at = COALESCE(EXCLUDED.source_modified_at, source_sync.source_modified_at),
                sync_cursor_at = COALESCE(EXCLUDED.sync_cursor_at, source_sync.sync_cursor_at)
            """,
            {
                "id": r.source_id,
                "at": r.attempted_at,
                "success_at": datetime.now(UTC) if ok else None,
                "status": r.status,
                "recv": r.received,
                "cr": r.created,
                "up": r.updated,
                "rej": r.rejected,
                "err": r.error_summary,
                "src_mod": r.source_modified_at,
                "cursor": r.cursor_at if ok else None,
            },
        )
    conn.commit()


def list_status(conn: psycopg.Connection) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM source_sync ORDER BY source_id")
        return cur.fetchall()
