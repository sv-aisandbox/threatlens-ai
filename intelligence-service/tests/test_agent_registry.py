"""Registry metadata and discovery: only the right tools reach the model."""

import asyncio

import pytest

from agent.registry import (
    METADATA, ToolRegistry, RegistryError, detect_entities,
)
from mcp_tools import asset_server, vulnerability_server

ROLES = ("SECURITY_ANALYST",)
LISTING = [
    {"name": n, "description": f"{n} description", "input_schema": {"type": "object", "properties": {}}}
    for n in METADATA
]


@pytest.fixture(scope="module")
def registry():
    return ToolRegistry.from_listing(LISTING)


def names(tools):
    return [t.name for t in tools]


# ---- metadata stays in step with the real servers -----------------------------------------------------------


def test_registry_covers_exactly_the_tools_the_servers_expose():
    assert sorted(METADATA) == sorted(vulnerability_server.TOOL_NAMES + asset_server.TOOL_NAMES)


def test_every_spec_follows_the_spec_metadata_shape(registry):
    for name in registry.names:
        spec = registry.get(name)
        assert spec.risk_level == "read_only" and spec.domain in {"vulnerability", "asset"}
        assert spec.permissions and spec.tags and spec.output_entities
        assert spec.server in {vulnerability_server.SERVER_NAME, asset_server.SERVER_NAME}
        assert set(spec.as_tool_param()) == {"name", "description", "input_schema"}


def test_missing_or_extra_metadata_is_detected():
    with pytest.raises(RegistryError, match="no registry metadata"):
        ToolRegistry.from_listing(LISTING + [{"name": "delete_everything", "description": "x", "input_schema": {}}])
    with pytest.raises(RegistryError, match="do not expose"):
        ToolRegistry.from_listing(LISTING[:-1])


# ---- entity detection ---------------------------------------------------------------------------------------


def test_entities_are_detected_and_normalized():
    e = detect_entities("Is asset-013 exposed to cve-2021-44228 in prod? Also CVE-2021-44228 again.")
    assert e.cves == ("CVE-2021-44228",) and e.assets == ("ASSET-013",) and e.environment == "production"
    assert detect_entities("anything on staging?").environment == "staging"
    assert detect_entities("no entities here").environment is None
    assert detect_entities("CVE-1 and ASSET").cves == ()  # malformed ids are not entities


# ---- discovery ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "question,expected_first,must_include,must_exclude",
    [
        ("Which of my assets are affected by CVE-2021-44228?", "get_affected_assets", {"get_vulnerability_details"}, {"get_critical_assets", "search_assets"}),
        ("What is the CVSS score and KEV status of CVE-2021-44228?", "get_vulnerability_details", set(), {"get_asset_software"}),
        ("Show the evidence and sources for CVE-2021-44228", "get_vulnerability_evidence", set(), {"get_critical_assets"}),
        ("What software is installed on ASSET-013?", "get_asset_software", {"get_asset_details"}, {"get_vulnerability_evidence", "get_affected_assets"}),
        ("Tell me about ASSET-013", "get_asset_details", set(), {"search_vulnerabilities"}),
        ("Which are my most critical assets?", "get_critical_assets", set(), {"get_vulnerability_evidence", "get_asset_software"}),
        ("Find KEV vulnerabilities with CVSS above 9", "search_vulnerabilities", set(), {"get_asset_software", "get_asset_details"}),
        ("List internet-exposed production servers", "search_assets", set(), {"get_vulnerability_evidence"}),
    ],
)
def test_discovery_selects_the_relevant_tools(registry, question, expected_first, must_include, must_exclude):
    found = names(registry.discover(question, ROLES))
    assert found[0] == expected_first, found
    assert must_include <= set(found)
    assert not must_exclude & set(found), found


def test_discovery_never_offers_every_tool_for_a_narrow_question(registry):
    for q in ("Which assets are affected by CVE-2021-44228?", "What software is on ASSET-013?"):
        assert len(registry.discover(q, ROLES)) < len(registry.names)


def test_k_bounds_the_result(registry):
    q = "Find the critical assets and vulnerabilities, list assets, show details, software, evidence for CVE-2021-44228 and ASSET-013"
    assert len(registry.discover(q, ROLES, k=3)) == 3
    assert len(registry.discover(q, ROLES, k=5)) <= 5


def test_a_question_without_signal_falls_back_to_broad_entry_tools(registry):
    found = names(registry.discover("hello there", ROLES))
    assert found and set(found) <= {"search_assets", "search_vulnerabilities", "get_critical_assets"}
    assert len(found) <= 3


def test_a_tool_that_needs_an_id_is_not_offered_without_one(registry):
    found = names(registry.discover("tell me about the details and evidence", ROLES))
    assert not {"get_vulnerability_evidence", "get_asset_software", "get_vulnerability_details"} & set(found)


def test_permission_and_risk_filters_apply_before_ranking(registry):
    assert registry.discover("Which assets are affected by CVE-2021-44228?", ()) == []  # no role, nothing eligible
    assert registry.discover("Which assets are affected by CVE-2021-44228?", ("UNKNOWN_ROLE",)) == []
    from dataclasses import replace

    risky = replace(registry.get("get_affected_assets"), risk_level="write")
    admin_only = replace(registry.get("get_critical_assets"), permissions=("ADMIN",))
    custom = ToolRegistry([risky, admin_only, registry.get("search_assets")])
    assert names(custom.eligible(("SECURITY_ANALYST",))) == ["search_assets"]
    assert set(names(custom.eligible(("ADMIN",)))) == {"get_critical_assets", "search_assets"}


def test_expand_adds_but_never_removes_and_respects_the_cap(registry):
    offered = registry.discover("Which assets are affected by CVE-2021-44228?", ROLES)
    grown = registry.expand(offered, "Which assets are affected by CVE-2021-44228? ASSET-013 software installed", ROLES)
    assert names(offered) == names(grown)[: len(offered)]  # existing order is kept
    assert "get_asset_software" in names(grown) and len(grown) <= 6
    assert registry.expand(grown, "list assets critical vulnerabilities evidence", ROLES, cap=len(grown)) == grown


def test_discovery_is_deterministic(registry):
    q = "Which production assets are affected by CVE-2021-44228?"
    assert names(registry.discover(q, ROLES)) == names(registry.discover(q, ROLES))


def test_real_listing_from_the_running_servers_builds_a_registry():
    from agent.bridge import McpBridge
    from tests.helpers import SECRET  # noqa: F401  (imported to keep helpers loaded)

    class NullAudit:
        def record(self, e):
            pass

    async def listing():
        async with McpBridge("TENANT-DEMO", frozenset({"VIEWER"}), "sub-1", driver=None, connect=None, audit=NullAudit()) as b:
            return b.listing

    reg = ToolRegistry.from_listing(asyncio.run(listing()))
    assert sorted(reg.names) == sorted(METADATA)
    assert reg.get("get_affected_assets").input_schema["properties"]["cve_id"]["pattern"]
