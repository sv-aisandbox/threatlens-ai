"""Trusted tenant context for MCP servers (roadmap gap G7).

For local/demo use the tenant and roles come from the server's own environment at startup. They are never
read from a tool argument, so a model cannot choose or change them.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

from mcp_tools.errors import ToolFailure

TENANT_RE = re.compile(r"^TENANT-[A-Z0-9-]{1,40}$")
ACTOR_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,100}$")
KNOWN_ROLES = frozenset({"ADMIN", "SECURITY_ANALYST", "VIEWER"})
READ_ROLES = KNOWN_ROLES  # every role may read; the MCP servers expose no write tools
DEFAULT_ROLES = "VIEWER"  # least privilege


class ConfigError(RuntimeError):
    """The server cannot start: its trusted context is missing or malformed."""


@dataclass(frozen=True)
class TrustedContext:
    tenant_id: str
    roles: frozenset[str]
    actor: str

    def can_read(self) -> bool:
        return bool(self.roles & READ_ROLES)

    def require_read(self) -> None:
        """Tools re-check permission themselves; the model is never the authorization authority."""
        if not self.can_read():
            raise ToolFailure("forbidden", "The configured role is not allowed to use this tool.")

    @staticmethod
    def from_env(default_actor: str, env: Mapping[str, str] | None = None) -> "TrustedContext":
        env = os.environ if env is None else env
        tenant = (env.get("THREATLENS_TENANT_ID") or "").strip()
        if not TENANT_RE.fullmatch(tenant):
            raise ConfigError("THREATLENS_TENANT_ID must be set to a valid tenant id such as TENANT-DEMO")
        roles = frozenset(r.strip() for r in (env.get("THREATLENS_ROLES") or DEFAULT_ROLES).split(",") if r.strip())
        if not roles or not roles <= KNOWN_ROLES:
            raise ConfigError(f"THREATLENS_ROLES must be a comma-separated subset of {sorted(KNOWN_ROLES)}")
        actor = (env.get("THREATLENS_ACTOR") or default_actor).strip()
        if not ACTOR_RE.fullmatch(actor):
            raise ConfigError("THREATLENS_ACTOR contains characters that are not allowed")
        return TrustedContext(tenant_id=tenant, roles=roles, actor=actor)
