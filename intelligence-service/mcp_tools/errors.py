"""Stable tool error type. The code is machine-readable; the message is fixed text that never repeats caller input."""

from mcp.server.mcpserver.exceptions import ToolError

CODES = ("invalid_argument", "not_found", "forbidden", "unavailable", "internal_error")


class ToolFailure(ToolError):
    """An anticipated failure. Becomes {"error": {"code", "message", "correlation_id"}} for the client."""

    def __init__(self, code: str, message: str) -> None:
        if code not in CODES:
            raise ValueError(f"unknown error code {code!r}")
        super().__init__(message)
        self.code = code
        self.message = message
