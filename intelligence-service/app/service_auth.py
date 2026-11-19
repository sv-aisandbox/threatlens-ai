"""Verification of the short-lived service JWT minted by the Spring Boot backend (ADR 0004).

Only HS256 is accepted. The principal (user, tenant, roles) comes from the token and nowhere else.
"""

import re
from dataclasses import dataclass

import jwt

ISSUER = "threatlens-backend"
AUDIENCE = "threatlens-intelligence"
ALGORITHM = "HS256"
KNOWN_ROLES = frozenset({"ADMIN", "SECURITY_ANALYST", "VIEWER"})
MAX_LIFETIME_SECONDS = 120
MIN_SECRET_BYTES = 32
TENANT_RE = re.compile(r"^TENANT-[A-Z0-9-]{1,40}$")
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "jti", "tenant_id", "roles"]


class AuthError(Exception):
    """The token is missing or invalid. The message is safe to log but is never sent to the client."""


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[str]

    def has_any(self, *roles: str) -> bool:
        return bool(self.roles & set(roles))


def validate_secret(secret: str | None) -> str:
    if not secret or len(secret.encode()) < MIN_SECRET_BYTES:
        raise RuntimeError(f"INTERNAL_JWT_SECRET must be set and at least {MIN_SECRET_BYTES} bytes long")
    return secret


def verify_service_token(token: str, secret: str) -> Principal:
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": REQUIRED_CLAIMS},
            leeway=5,
        )
    except jwt.PyJWTError as exc:
        raise AuthError(type(exc).__name__) from None

    if not isinstance(claims["exp"], int | float) or not isinstance(claims["iat"], int | float):
        raise AuthError("bad timestamps")
    if claims["exp"] - claims["iat"] > MAX_LIFETIME_SECONDS:
        raise AuthError("token lifetime too long")
    subject, tenant = claims["sub"], claims["tenant_id"]
    if not isinstance(subject, str) or not subject or len(subject) > 200:
        raise AuthError("bad subject")
    if not isinstance(tenant, str) or not TENANT_RE.fullmatch(tenant):
        raise AuthError("bad tenant")
    roles = claims["roles"]
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise AuthError("bad roles")
    known = frozenset(roles) & KNOWN_ROLES
    if not known:
        raise AuthError("no known role")
    return Principal(subject=subject, tenant_id=tenant, roles=known)
