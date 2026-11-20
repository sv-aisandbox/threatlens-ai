"""Structured JSON logs with secret redaction, and a tiny in-process metrics registry (Prometheus text format).

Logs are one JSON object per line: timestamp, level, logger, message, correlation_id and, when present, exception text.
Redaction runs on every message and exception text before it is written, so a token that slips into an error string
(for example from a library) is replaced rather than stored.
"""

import contextvars
import json
import logging
import os
import re
import threading
from datetime import UTC, datetime

correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")

REDACTED = "[REDACTED]"
SECRET_ENV_NAMES = ("INTERNAL_JWT_SECRET", "MODEL_API_KEY", "NVD_API_KEY", "POSTGRES_PASSWORD", "MEMGRAPH_PASSWORD")
_PATTERNS = [
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), f"Bearer {REDACTED}"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), REDACTED),  # JWT shape
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), REDACTED),  # API-key shape
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|apikey|token|authorization)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
     rf"\1\2{REDACTED}"),
]


def redact(text: str) -> str:
    for secret in _env_secrets():
        text = text.replace(secret, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _env_secrets() -> list[str]:
    values = (os.environ.get(name) for name in SECRET_ENV_NAMES)
    return [v for v in values if v and len(v) >= 8]  # very short values would redact ordinary words


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = redact(record.getMessage())
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "correlation_id": getattr(record, "correlation_id", None) or correlation_id.get(),
        }
        if record.exc_info:
            entry["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent: installs the JSON handler on the root logger unless something already configured logging."""
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.handlers[:] = [handler]
    root.setLevel(level)


# ---- metrics ---------------------------------------------------------------------------------------------------------


class Metrics:
    """Request counts and latency per route template. Labels are bounded: unknown paths collapse into one label."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str, int], int] = {}
        self._seconds: dict[tuple[str, str], float] = {}
        self._counters: dict[str, int] = {}

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        with self._lock:
            key = (method, route, status)
            self._requests[key] = self._requests.get(key, 0) + 1
            self._seconds[(method, route)] = self._seconds.get((method, route), 0.0) + seconds

    def count(self, name: str) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + 1

    def render(self) -> str:
        with self._lock:
            lines = ["# HELP threatlens_http_requests_total HTTP requests by method, route template and status.",
                     "# TYPE threatlens_http_requests_total counter"]
            for (method, route, status), n in sorted(self._requests.items()):
                lines.append(f'threatlens_http_requests_total{{method="{method}",route="{route}",status="{status}"}} {n}')
            lines += ["# HELP threatlens_http_request_seconds_sum Total request time by method and route template.",
                      "# TYPE threatlens_http_request_seconds_sum counter"]
            for (method, route), total in sorted(self._seconds.items()):
                lines.append(f'threatlens_http_request_seconds_sum{{method="{method}",route="{route}"}} {total:.6f}')
            for name, n in sorted(self._counters.items()):
                lines += [f"# TYPE threatlens_{name}_total counter", f"threatlens_{name}_total {n}"]
        return "\n".join(lines) + "\n"
