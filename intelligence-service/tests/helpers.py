import json
from pathlib import Path

import httpx

FIXTURES = Path(__file__).resolve().parents[2] / "data" / "fixtures"


def load(rel: str):
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


class FakeClock:
    """Deterministic time: sleep() advances monotonic() instead of waiting."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


def nvd_transport(pages_by_start: dict[int, dict], calls: list[httpx.Request] | None = None):
    """Mock NVD: answers by startIndex with recorded fixture pages."""

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        start = int(request.url.params.get("startIndex", "0"))
        page = pages_by_start.get(start)
        if page is None:
            empty = {"resultsPerPage": 0, "startIndex": start, "totalResults": 0, "vulnerabilities": []}
            return httpx.Response(200, json=empty)
        return httpx.Response(200, json=page)

    return httpx.MockTransport(handler)
