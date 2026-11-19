"""Minimal NVD API 2.0 client: pagination, rate limiting, retry/backoff. The API key is sent only
as a request header and is never logged or included in error messages."""

import logging
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from normalization.nvd import CVE_ID_RE

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)  # httpx logs full URLs at INFO

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120  # NVD limit for lastModStartDate/lastModEndDate ranges
MAX_PAGE_SIZE = 2000  # NVD maximum resultsPerPage
RETRYABLE_STATUS = {403, 429, 500, 502, 503, 504}  # NVD answers 403 when rate limited
MAX_RESPONSE_BYTES = 50 * 1024 * 1024


class NvdError(Exception):
    """Operational NVD failure. Messages contain status codes only, never bodies or credentials."""


def nvd_timestamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")


def date_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=MAX_WINDOW_DAYS), end)
        yield cursor, window_end
        cursor = window_end


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        max_retries: int = 5,
        base_delay: float = 2.0,
    ) -> None:
        self._api_key = api_key
        self._http = http or httpx.Client(timeout=30.0, follow_redirects=False)
        self._sleep = sleep
        self._monotonic = monotonic
        self._max_retries = max_retries
        self._base_delay = base_delay
        # NVD allows 50 requests / 30 s with a key and 5 / 30 s without.
        self._min_interval = 0.6 if api_key else 6.0
        self._last_request: float | None = None

    def _throttle(self) -> None:
        if self._last_request is not None:
            wait = self._min_interval - (self._monotonic() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._monotonic()

    def _backoff(self, attempt: int, retry_after: float | None, problem: str) -> None:
        delay = retry_after if retry_after is not None else self._base_delay * (2**attempt)
        logger.warning("NVD request problem (%s); retrying in %.1fs", problem, delay)
        self._sleep(delay)

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        problem = "no attempt made"
        for attempt in range(self._max_retries + 1):
            self._throttle()
            retry_after: float | None = None
            try:
                resp = self._http.get(NVD_URL, params=params, headers=headers)
            except httpx.TransportError as exc:
                problem = type(exc).__name__
            else:
                if resp.status_code == 200:
                    if len(resp.content) > MAX_RESPONSE_BYTES:
                        raise NvdError("NVD response too large")
                    try:
                        body = resp.json()
                    except ValueError:
                        raise NvdError("NVD returned invalid JSON") from None
                    if not isinstance(body, dict):
                        raise NvdError("NVD returned unexpected JSON shape")
                    return body
                if resp.status_code not in RETRYABLE_STATUS:
                    raise NvdError(f"NVD request failed with HTTP {resp.status_code}")
                problem = f"HTTP {resp.status_code}"
                header = resp.headers.get("Retry-After", "")
                if re.fullmatch(r"\d{1,4}", header):
                    retry_after = float(header)
            if attempt < self._max_retries:
                self._backoff(attempt, retry_after, problem)
        raise NvdError(f"NVD request failed after {self._max_retries + 1} attempts ({problem})")

    def iter_pages(
        self, params: dict[str, Any] | None = None, page_size: int = MAX_PAGE_SIZE
    ) -> Iterator[dict[str, Any]]:
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        start_index = 0
        while True:
            page = self._get({**(params or {}), "resultsPerPage": page_size, "startIndex": start_index})
            yield page
            returned = len(page.get("vulnerabilities") or [])
            total = page.get("totalResults")
            start_index += returned
            if returned == 0 or not isinstance(total, int) or start_index >= total:
                return

    def iter_modified(
        self, start: datetime, end: datetime, page_size: int = MAX_PAGE_SIZE
    ) -> Iterator[dict[str, Any]]:
        for w_start, w_end in date_windows(start, end):
            yield from self.iter_pages(
                {"lastModStartDate": nvd_timestamp(w_start), "lastModEndDate": nvd_timestamp(w_end)},
                page_size,
            )

    def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        if not CVE_ID_RE.fullmatch(cve_id):
            raise ValueError("invalid CVE id")
        return self._get({"cveId": cve_id})
