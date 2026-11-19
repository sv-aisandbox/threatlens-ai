"""Keeps the published MCP documentation and Claude Code configuration in step with the code."""

import json
import re

import pytest

from app.config import REPO_ROOT
from mcp_tools import asset_server, vulnerability_server

CATALOGUE = (REPO_ROOT / "docs" / "mcp" / "tools.md").read_text(encoding="utf-8")


def catalogued_tools():
    return re.findall(r"^### `([a-z_]+)`$", CATALOGUE, flags=re.MULTILINE)


def test_catalogue_lists_exactly_the_implemented_tools():
    implemented = vulnerability_server.TOOL_NAMES + asset_server.TOOL_NAMES
    assert sorted(catalogued_tools()) == sorted(implemented)


@pytest.mark.parametrize("tool", vulnerability_server.TOOL_NAMES + asset_server.TOOL_NAMES)
def test_every_tool_has_a_parameter_table_and_a_returns_section(tool):
    block = CATALOGUE.split(f"### `{tool}`", 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]
    assert "| Parameter | Type | Required | Default |" in block and "**Returns**" in block


def test_catalogue_documents_every_error_code_and_status():
    from mcp_tools.errors import CODES

    for code in CODES:
        assert f"`{code}`" in CATALOGUE
    for status in ("confirmed", "possible", "unknown", "not_affected"):
        assert f"`{status}`" in CATALOGUE


def test_project_mcp_config_starts_both_servers_with_no_secrets():
    config = json.loads((REPO_ROOT / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert set(config) == {vulnerability_server.SERVER_NAME, asset_server.SERVER_NAME}
    assert "mcp_tools.vulnerability_server" in config[vulnerability_server.SERVER_NAME]["args"]
    assert "mcp_tools.asset_server" in config[asset_server.SERVER_NAME]["args"]
    for server in config.values():
        assert set(server["env"]) == {"THREATLENS_TENANT_ID", "THREATLENS_ROLES"}  # nothing secret, no tenant hard-coded
        assert server["env"]["THREATLENS_ROLES"].endswith(":-VIEWER}")  # least privilege by default
