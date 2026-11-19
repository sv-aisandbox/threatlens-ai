import logging
from datetime import UTC, datetime

import httpx
import pytest

from ingestion.nvd_client import MAX_WINDOW_DAYS, NvdClient, NvdError, date_windows
from tests.helpers import FakeClock, load, nvd_transport

KEY = "SECRET-KEY-123"


def make_client(handler_or_transport, key=KEY, **kw):
    clock = FakeClock()
    transport = (
        handler_or_transport
        if isinstance(handler_or_transport, httpx.BaseTransport)
        else httpx.MockTransport(handler_or_transport)
    )
    client = NvdClient(key, httpx.Client(transport=transport), clock.sleep, clock.monotonic, **kw)
    return client, clock


def test_pagination_walks_all_pages_with_key_header():
    calls: list[httpx.Request] = []
    pages = {0: load("nvd/page-0.json"), 2: load("nvd/page-2.json")}
    client, _ = make_client(nvd_transport(pages, calls))
    ids = [v["cve"]["id"] for page in client.iter_pages(page_size=2) for v in page["vulnerabilities"]]
    assert len(ids) == 4 and len(set(ids)) == 4
    assert [c.url.params["startIndex"] for c in calls] == ["0", "2"]
    assert all(c.url.params["resultsPerPage"] == "2" for c in calls)
    assert all(c.headers["apiKey"] == KEY for c in calls)
    assert all(KEY not in str(c.url) for c in calls)  # key is a header, never in the URL


def test_no_key_header_without_key():
    calls: list[httpx.Request] = []
    client, _ = make_client(nvd_transport({0: load("nvd/page-0.json")}, calls), key=None)
    list(client.iter_pages(page_size=2))
    assert "apikey" not in {k.lower() for k in calls[0].headers}


def test_date_windows_respect_maximum():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 9, 10, tzinfo=UTC)
    windows = list(date_windows(start, end))
    assert len(windows) == 3
    assert windows[0][0] == start and windows[-1][1] == end
    assert all((b - a).days <= MAX_WINDOW_DAYS for a, b in windows)
    assert all(windows[i][1] == windows[i + 1][0] for i in range(len(windows) - 1))


def test_retries_with_exponential_backoff_then_succeeds():
    attempts = []

    def handler(request):
        attempts.append(1)
        if len(attempts) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json=load("nvd/page-0.json"))

    client, clock = make_client(handler)
    assert client.fetch_cve("CVE-2026-7233")["totalResults"] == 4
    assert len(attempts) == 3
    assert clock.sleeps == [2.0, 4.0]


def test_rate_limit_403_and_retry_after_header_honoured():
    n = []

    def handler(request):
        n.append(1)
        if len(n) == 1:
            return httpx.Response(403, headers={"Retry-After": "7"})
        return httpx.Response(200, json=load("nvd/page-0.json"))

    client, clock = make_client(handler)
    client.fetch_cve("CVE-2026-7233")
    assert clock.sleeps == [7.0]


def test_transport_error_is_retried():
    n = []

    def handler(request):
        n.append(1)
        if len(n) == 1:
            raise httpx.ConnectError(f"boom {KEY}")
        return httpx.Response(200, json=load("nvd/page-0.json"))

    client, _ = make_client(handler)
    client.fetch_cve("CVE-2026-7233")
    assert len(n) == 2


def test_gives_up_after_max_retries_without_leaking_key(caplog):
    n = []

    def handler(request):
        n.append(1)
        return httpx.Response(500, text=f"internal error {KEY}")

    client, _ = make_client(handler, max_retries=3)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(NvdError) as exc:
            client.fetch_cve("CVE-2026-7233")
    assert len(n) == 4
    assert KEY not in str(exc.value) and KEY not in caplog.text


def test_non_retryable_status_fails_immediately():
    n = []

    def handler(request):
        n.append(1)
        return httpx.Response(404)

    client, clock = make_client(handler)
    with pytest.raises(NvdError, match="404"):
        client.fetch_cve("CVE-2026-7233")
    assert len(n) == 1 and clock.sleeps == []


def test_client_side_rate_limiting():
    client, clock = make_client(nvd_transport({0: load("nvd/page-0.json")}), key=None)
    client.fetch_cve("CVE-2026-7233")
    client.fetch_cve("CVE-2026-7233")
    assert clock.sleeps == [6.0]  # 5 requests / 30 s without a key
    keyed, kclock = make_client(nvd_transport({0: load("nvd/page-0.json")}))
    keyed.fetch_cve("CVE-2026-7233")
    keyed.fetch_cve("CVE-2026-7233")
    assert kclock.sleeps == [0.6]


def test_invalid_json_and_bad_cve_id():
    client, _ = make_client(lambda r: httpx.Response(200, text="<html>not json</html>"))
    with pytest.raises(NvdError, match="invalid JSON"):
        client.fetch_cve("CVE-2026-7233")
    with pytest.raises(ValueError):
        client.fetch_cve("CVE-2026-7233&apiKey=x")
