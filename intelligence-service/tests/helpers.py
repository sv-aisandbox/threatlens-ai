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


# ---- service JWT minting (mirrors what the Spring Boot backend does, ADR 0004) -----------------

SECRET = "unit-test-secret-" + "x" * 32


def mint(secret: str = SECRET, *, sub: str = "user-1", tenant: str | None = "TENANT-DEMO",
         roles: list[str] | None = None, ttl: int = 60, iat_offset: int = 0, algorithm: str = "HS256",
         iss: str = "threatlens-backend", aud: str = "threatlens-intelligence", drop: tuple[str, ...] = (),
         **extra) -> str:
    import time
    import uuid

    import jwt

    now = int(time.time()) + iat_offset
    claims = {"iss": iss, "aud": aud, "sub": sub, "tenant_id": tenant,
              "roles": ["SECURITY_ANALYST"] if roles is None else roles,
              "jti": str(uuid.uuid4()), "iat": now, "exp": now + ttl, **extra}
    for name in drop:
        claims.pop(name, None)
    if tenant is None:
        claims.pop("tenant_id")
    return jwt.encode(claims, secret, algorithm=algorithm)


def bearer(token: str, **headers) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **headers}
