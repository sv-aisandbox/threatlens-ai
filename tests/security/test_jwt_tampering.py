"""The internal service accepts one thing: a fresh HS256 token signed with the shared secret by the Spring backend."""

import base64
import json
import time

import jwt
import pytest

from tests.helpers import SECRET, bearer, mint

URL = "/internal/v1/overview"


def b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def forged(payload: dict, header: dict | None = None, signature: str = "") -> str:
    return f"{b64(header or {'alg': 'none', 'typ': 'JWT'})}.{b64(payload)}.{signature}"


def claims(**over):
    now = int(time.time())
    base = {"iss": "threatlens-backend", "aud": "threatlens-intelligence", "sub": "u", "tenant_id": "TENANT-DEMO",
            "roles": ["ADMIN"], "jti": "x", "iat": now, "exp": now + 60}
    return {**base, **over}


def status(world, token_or_headers):
    headers = token_or_headers if isinstance(token_or_headers, dict) else bearer(token_or_headers)
    return world.client.get(URL, headers=headers).status_code


def test_a_valid_token_works(world):
    assert status(world, mint()) == 200


@pytest.mark.parametrize("name,token", [
    ("alg none", forged(claims())),
    ("alg NONE", forged(claims(), {"alg": "NONE", "typ": "JWT"})),
    ("alg none with a junk signature", forged(claims(), signature="AAAA")),
    ("wrong secret", mint("another-secret-" + "y" * 32)),
    ("RS256 header over junk", forged(claims(), {"alg": "RS256", "typ": "JWT"}, "AAAA")),
    ("HS512 signed with the right secret", mint(algorithm="HS512")),
    ("expired", mint(ttl=-30, iat_offset=-90)),
    ("issued in the far future", mint(iat_offset=3600)),
    ("lifetime too long", mint(ttl=3600)),
    ("wrong audience", mint(aud="someone-else")),
    ("wrong issuer", mint(iss="someone-else")),
    ("no tenant", mint(tenant=None)),
    ("no subject", mint(drop=("sub",))),
    ("no expiry", mint(drop=("exp",))),
    ("no roles claim", mint(drop=("roles",))),
    ("only unknown roles", mint(roles=["ROOT", "SUPERUSER"])),
    ("tenant that is not a tenant id", mint(tenant="demo; MATCH (n) DETACH DELETE n")),
    ("tenant in lowercase", mint(tenant="tenant-demo")),
    ("garbage", "not.a.jwt"),
    ("one segment", "abc"),
    ("empty", ""),
])
def test_forged_or_invalid_tokens_are_401_and_reveal_nothing(world, name, token):
    r = world.client.get(URL, headers=bearer(token))
    assert r.status_code == 401, name
    body = r.text.lower()
    for hint in ("signature", "expired", "audience", "issuer", "secret", "traceback", SECRET):
        assert hint.lower() not in body


def test_editing_the_payload_of_a_real_token_breaks_the_signature(world):
    header, payload, signature = mint(roles=["VIEWER"], tenant="TENANT-DEMO").split(".")
    original = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    for change in ({"tenant_id": "TENANT-OTHER"}, {"roles": ["ADMIN"]}, {"exp": int(time.time()) + 100000}):
        edited = f"{header}.{b64({**original, **change})}.{signature}"
        assert status(world, edited) == 401, change


def test_swapping_the_signature_between_tokens_fails(world):
    a = mint(tenant="TENANT-DEMO", roles=["VIEWER"]).split(".")
    b = mint(tenant="TENANT-OTHER", roles=["ADMIN"]).split(".")
    assert status(world, ".".join([a[0], a[1], b[2]])) == 401


def test_extra_header_tricks_do_not_help(world):
    token = jwt.encode(claims(), "x" * 40, algorithm="HS256",
                       headers={"kid": "../../../dev/null", "jku": "http://evil/keys", "jwk": {"kty": "oct"}})
    assert status(world, token) == 401


@pytest.mark.parametrize("header", [
    {},
    {"Authorization": ""},
    {"Authorization": "Basic dXNlcjpwYXNz"},
    {"Authorization": "bearer"},
    {"Authorization": "Bearer"},
    {"Authorization": "Bearer  "},
    {"Authorization": "Token " + mint()},
])
def test_missing_or_wrong_scheme_is_401(world, header):
    assert status(world, header) == 401


def test_the_token_in_the_query_string_is_not_accepted(world):
    assert world.client.get(f"{URL}?access_token={mint()}").status_code == 401


def test_role_checks_use_the_signed_roles_only(world):
    viewer = bearer(mint(roles=["VIEWER"]))
    spoofed = viewer | {"X-Roles": "ADMIN", "X-Role": "ADMIN"}
    assert world.client.post("/internal/v1/sources/nvd/sync", headers=spoofed).status_code == 403
    assert world.client.post("/internal/v1/analyst/ask", json={"question": "hello there"}, headers=viewer).status_code == 403
