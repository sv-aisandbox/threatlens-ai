"""Manual sync trigger.

  uv run python -m ingestion.cli sync nvd [--since 2026-11-01] [--until 2026-11-10]
  uv run python -m ingestion.cli sync kev
  uv run python -m ingestion.cli import-cve CVE-2021-44228
  uv run python -m ingestion.cli status
"""

import argparse
import json
import logging
import sys
from datetime import UTC, datetime

import psycopg

from app.config import get_driver, nvd_api_key, pg_conninfo
from ingestion import source_sync, sync
from ingestion.nvd_client import NvdClient


def _parse_when(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ingestion.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sync")
    s.add_argument("source", choices=["nvd", "kev"])
    s.add_argument("--since", type=_parse_when, help="NVD only: ISO date/time (UTC) to sync from")
    s.add_argument("--until", type=_parse_when, help="NVD only: ISO date/time (UTC) to sync to")
    c = sub.add_parser("import-cve")
    c.add_argument("cve_id")
    sub.add_parser("status")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    key = nvd_api_key()
    driver = get_driver()
    try:
        with psycopg.connect(pg_conninfo()) as conn:
            if args.command == "status":
                print(json.dumps(source_sync.list_status(conn), default=str, indent=2))
                return 0
            if args.command == "import-cve":
                result = sync.import_single_cve(driver, conn, NvdClient(key), args.cve_id, api_key=key)
            elif args.source == "nvd":
                result = sync.run_nvd_sync(
                    driver, conn, NvdClient(key), since=args.since, until=args.until, api_key=key
                )
            else:
                result = sync.run_kev_sync(driver, conn)
            print(json.dumps(result.as_dict(), indent=2))
            return 1 if result.status == "failed" else 0
    finally:
        driver.close()


if __name__ == "__main__":
    sys.exit(main())
