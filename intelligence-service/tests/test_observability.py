"""Structured JSON logs, secret redaction and the metrics endpoint."""

import json
import logging

import pytest
from fastapi.testclient import TestClient

from app import observability
from app.observability import JsonFormatter, Metrics, redact
from tests.helpers import SECRET, bearer, mint
from tests.test_api import env  # noqa: F401 - the shared app fixture


def record(msg, *args, exc_info=None, **extra):
    r = logging.LogRecord("threatlens.test", logging.INFO, __file__, 1, msg, args, exc_info)
    for key, value in extra.items():
        setattr(r, key, value)
    return r


def test_each_line_is_one_json_object_with_the_expected_fields():
    line = JsonFormatter().format(record("GET %s -> %s", "/x", 200, correlation_id="abc-123"))
    data = json.loads(line)
    assert set(data) == {"ts", "level", "logger", "message", "correlation_id"}
    assert data["message"] == "GET /x -> 200" and data["correlation_id"] == "abc-123" and data["level"] == "INFO"
    assert "\n" not in line


def test_the_correlation_id_comes_from_the_request_context():
    token = observability.correlation_id.set("ctx-42")
    try:
        assert json.loads(JsonFormatter().format(record("hello")))["correlation_id"] == "ctx-42"
    finally:
        observability.correlation_id.reset(token)


def test_newlines_in_messages_cannot_forge_extra_log_lines():
    line = JsonFormatter().format(record("user said: %s", 'x"\n{"level":"CRITICAL","message":"forged"}'))
    assert "\n" not in line and json.loads(line)["level"] == "INFO"


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"


@pytest.mark.parametrize("text", [
    f"Authorization: Bearer {JWT}",
    f"token leaked {JWT} in the middle",
    "password=hunter2hunter2",
    'api_key: "sk-abcdefghijklmnopqrstuvwx"',
    "secret = s3cr3t-value",
    "using sk-abcdefghijklmnopqrstuvwxyz0123456789",
])
def test_secrets_are_redacted_from_messages(text):
    out = redact(text)
    for leaked in (JWT, "hunter2", "sk-abcdef", "s3cr3t-value"):
        assert leaked not in out
    assert observability.REDACTED in out


def test_configured_secret_values_are_redacted_even_without_a_label(monkeypatch):
    monkeypatch.setenv("INTERNAL_JWT_SECRET", "a-very-long-internal-secret-value-123456")
    monkeypatch.setenv("MODEL_API_KEY", "model-key-value-0987654321")
    out = redact("connecting with a-very-long-internal-secret-value-123456 and model-key-value-0987654321 now")
    assert "a-very-long" not in out and "model-key" not in out


def test_exception_text_is_redacted_too():
    try:
        raise RuntimeError(f"upstream said Bearer {JWT}")
    except RuntimeError:
        import sys

        data = json.loads(JsonFormatter().format(record("failed", exc_info=sys.exc_info())))
    assert JWT not in data["exception"] and "RuntimeError" in data["exception"]


def test_ordinary_text_is_left_alone():
    assert redact("GET /internal/v1/overview -> 200 cid=3f2a") == "GET /internal/v1/overview -> 200 cid=3f2a"


# ---- metrics -----------------------------------------------------------------------------------------------------


def test_metrics_render_prometheus_text_with_bounded_labels():
    m = Metrics()
    m.observe("GET", "/internal/v1/overview", 200, 0.25)
    m.observe("GET", "/internal/v1/overview", 200, 0.75)
    m.count("auth_denied")
    text = m.render()
    assert 'threatlens_http_requests_total{method="GET",route="/internal/v1/overview",status="200"} 2' in text
    assert 'threatlens_http_request_seconds_sum{method="GET",route="/internal/v1/overview"} 1.000000' in text
    assert "threatlens_auth_denied_total 1" in text


def test_metrics_endpoint_is_admin_only(env):  # noqa: F811
    client: TestClient = env[0]
    assert client.get("/internal/v1/metrics").status_code == 401
    assert client.get("/internal/v1/metrics", headers=bearer(mint(roles=["SECURITY_ANALYST"]))).status_code == 403
    r = client.get("/internal/v1/metrics", headers=bearer(mint(roles=["ADMIN"])))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")


def test_metrics_count_requests_by_route_template_not_by_raw_path(env):  # noqa: F811
    client: TestClient = env[0]
    admin = bearer(mint(roles=["ADMIN"]))
    for cve in ("CVE-2021-44228", "CVE-2021-0001", "CVE-2020-0002"):
        client.get(f"/internal/v1/vulnerabilities/{cve}", headers=admin)
    client.get("/totally/unknown/path/12345")
    text = client.get("/internal/v1/metrics", headers=admin).text
    assert 'route="/internal/v1/vulnerabilities/{cve_id}"' in text
    assert "CVE-2021-0001" not in text and "12345" not in text, "raw paths would create unbounded labels"
    assert 'route="unmatched"' in text
    assert SECRET not in text
