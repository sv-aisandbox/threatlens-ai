"""Load the real log4j CVE and the CISA KEV flags so the end-to-end demo has something to show.

  uv run python -m ingestion.demo_data              # live NVD + CISA; falls back to the fixtures if the network fails
  uv run python -m ingestion.demo_data --offline    # recorded fixtures only (data/fixtures, captured 2026-11-19)

The fixtures are real public records, but they are a recording: when they are used the output says so, and the
sync timestamps shown in the UI are the time of loading, not the time of capture.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import psycopg

from app.config import get_driver, nvd_api_key, pg_conninfo
from correlation.match_service import run_matching
from ingestion import sync
from ingestion.nvd_client import NvdClient

DEMO_CVE = "CVE-2021-44228"
FIXTURES = Path(__file__).resolve().parents[2] / "data" / "fixtures"


class _FixtureNvd:
    """Same surface as NvdClient.fetch_cve, answered from a recorded file."""

    def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        if cve_id != DEMO_CVE:
            raise ValueError("only the recorded demo CVE is available offline")
        return json.loads((FIXTURES / "nvd" / "cve-2021-44228.json").read_text(encoding="utf-8"))


def _fixture_kev() -> Any:
    return json.loads((FIXTURES / "kev" / "kev-sample.json").read_text(encoding="utf-8"))


def load(offline: bool) -> str:
    key = nvd_api_key()
    driver = get_driver()
    mode = "fixtures" if offline else "live"
    try:
        with psycopg.connect(pg_conninfo()) as conn:
            if not offline:
                cve = sync.import_single_cve(driver, conn, NvdClient(key), DEMO_CVE, api_key=key)
                kev = sync.run_kev_sync(driver, conn)
                if cve.status == "failed" or kev.status == "failed":
                    print(f"Live download failed ({cve.error_summary or kev.error_summary}); using the recorded fixtures.")
                    offline, mode = True, "fixtures"
            if offline:
                cve = sync.import_single_cve(driver, conn, _FixtureNvd(), DEMO_CVE)  # type: ignore[arg-type]
                kev = sync.run_kev_sync(driver, conn, fetch=_fixture_kev)
            if cve.status == "failed" or kev.status == "failed":
                raise RuntimeError(f"demo data could not be loaded: {cve.error_summary or kev.error_summary}")
        matching = run_matching(driver)
        print(f"Loaded {DEMO_CVE} and KEV flags from {mode}. Matching: {matching.__dict__}")
        if mode == "fixtures":
            print("NOTE: this is RECORDED data (captured 2026-11-19), not a fresh download.")
        return mode
    finally:
        driver.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="use the recorded fixtures, no network")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    load(args.offline)
    return 0


if __name__ == "__main__":
    sys.exit(main())
