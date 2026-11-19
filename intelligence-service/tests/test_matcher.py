"""Table-driven matcher tests (ADR 0003). Pure logic: no database."""

import pytest

from correlation.matcher import InstalledSoftware, evaluate

LOG = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"


def M(criteria=LOG, vulnerable=True, **bounds):
    return {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "X", **bounds}


def cfg(*matches, operator=None, node_operator="OR", negate=False, extra_nodes=0):
    nodes = [{"operator": node_operator, "negate": negate, "cpeMatch": list(matches)}]
    nodes += [{"operator": "OR", "negate": False, "cpeMatch": [M("cpe:2.3:h:vendor:board:-:*:*:*:*:*:*:*", vulnerable=False)]}] * extra_nodes
    c = {"nodes": nodes}
    if operator:
        c["operator"] = operator
    return c


def sw(version, cpe=True, vendor="Apache", product="Log4j", cpe_str=None):
    if cpe_str is None and cpe:
        cpe_str = f"cpe:2.3:a:apache:log4j:{version or '*'}:*:*:*:*:*:*:*"
    return InstalledSoftware(vendor=vendor, product=product, version=version, cpe=cpe_str if cpe else None)


RANGES = [
    M(versionStartIncluding="2.0.1", versionEndExcluding="2.3.1"),
    M(versionStartIncluding="2.4.0", versionEndExcluding="2.12.2"),
    M(versionStartIncluding="2.13.0", versionEndExcluding="2.15.0"),
]


def status(software, configs):
    result = evaluate(software, configs)
    return None if result is None else result.status


# ---- range boundaries (real log4j-style ranges) ------------------------------------------------
@pytest.mark.parametrize(
    "version,expected",
    [
        ("2.0.0", "not_affected"),   # just below start
        ("2.0.1", "confirmed"),      # versionStartIncluding boundary
        ("2.3.0", "confirmed"),      # just below end
        ("2.3.1", "not_affected"),   # versionEndExcluding boundary
        ("2.3.2", "not_affected"),   # gap between ranges
        ("2.4.0", "confirmed"),
        ("2.12.1", "confirmed"),
        ("2.12.2", "not_affected"),
        ("2.13", "confirmed"),       # 2.13 == 2.13.0
        ("2.14.1", "confirmed"),
        ("2.15.0", "not_affected"),
        ("2.17.1", "not_affected"),
        ("1.2.17", "not_affected"),  # different major line
    ],
)
def test_range_boundaries(version, expected):
    assert status(sw(version), [cfg(*RANGES)]) == expected


@pytest.mark.parametrize(
    "version,expected",
    [("1.0", "not_affected"), ("1.0.1", "confirmed"), ("2.0", "confirmed"), ("2", "confirmed"),
     ("2.0.1", "not_affected")],
)
def test_start_excluding_and_end_including(version, expected):
    configs = [cfg(M(versionStartExcluding="1.0", versionEndIncluding="2.0"))]
    assert status(sw(version), configs) == expected


@pytest.mark.parametrize("version,expected", [("1.9.9", "confirmed"), ("2.0", "not_affected")])
def test_end_only_and_start_only(version, expected):
    assert status(sw(version), [cfg(M(versionEndExcluding="2.0"))]) == expected
    assert status(sw("5.0"), [cfg(M(versionStartIncluding="5.0"))]) == "confirmed"
    assert status(sw("4.9"), [cfg(M(versionStartIncluding="5.0"))]) == "not_affected"


@pytest.mark.parametrize(
    "version,expected",
    [("2.14.1", "confirmed"), ("2.14.1.0", "confirmed"), ("2.14.2", "not_affected")],
)
def test_exact_version_criteria(version, expected):
    exact = M("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert status(sw(version), [cfg(exact)]) == expected


def test_all_versions_when_no_bounds():
    assert status(sw("9.9"), [cfg(M())]) == "confirmed"


# ---- unknown: never guess ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "software",
    [
        sw(None),                              # no version recorded
        sw("1.2.3p1", cpe=False),              # not purely numeric
        sw("2.0-beta"),                        # pre-release string
        sw("8.0.1-r2"),
    ],
)
def test_unknown_when_version_missing_or_not_comparable(software):
    result = evaluate(software, [cfg(*RANGES)])
    assert result is not None and result.status == "unknown"
    assert "version" in result.reason


def test_unknown_even_when_all_versions_are_affected_but_version_missing():
    assert status(sw(None), [cfg(M())]) == "unknown"


def test_unknown_when_a_bound_is_not_comparable():
    assert status(sw("2.0"), [cfg(M(versionEndExcluding="2.0-beta"))]) == "unknown"


def test_unknown_when_exact_criteria_not_comparable_and_different():
    assert status(sw("2.0"), [cfg(M("cpe:2.3:a:apache:log4j:2.0b:*:*:*:*:*:*:*"))]) == "unknown"


def test_one_undecidable_entry_beats_out_of_range():
    configs = [cfg(M(versionEndExcluding="1.0"), M(versionEndExcluding="2.0-rc"))]
    assert status(sw("3.0"), configs) == "unknown"


def test_in_range_entry_beats_undecidable_entry():
    configs = [cfg(M(versionEndExcluding="9.0"), M(versionEndExcluding="2.0-rc"))]
    assert status(sw("3.0"), configs) == "confirmed"


# ---- no edge when the CVE does not name the product -------------------------------------------
@pytest.mark.parametrize(
    "configs",
    [
        [],
        [cfg(M("cpe:2.3:a:other:product:*:*:*:*:*:*:*:*"))],
        [cfg(M(vulnerable=False))],                                   # platform entries are not "vulnerable"
        [cfg(M("cpe:2.3:a:*:log4j:*:*:*:*:*:*:*:*"))],                # wildcard vendor ignored
        [cfg(M("cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"))],               # wildcard product ignored
        [cfg(M("cpe:2.3:a:apache:log4j-extras:*:*:*:*:*:*:*:*"))],   # similar name is a different product
        [cfg(M("not-a-cpe"))],
    ],
)
def test_product_not_named_gives_no_match(configs):
    assert evaluate(sw("2.14.1"), configs) is None


# ---- vendor/product identity and normalization ------------------------------------------------
def test_unrelated_vendor_name_without_cpe_is_not_guessed():
    software = sw("2.14.1", cpe=False, vendor="Apache Software Foundation")
    assert evaluate(software, [cfg(*RANGES)]) is None  # no alias table: not equal to "apache"


@pytest.mark.parametrize("vendor", ["Apache", "APACHE", "  apache ", "Apache, Inc.", "Apache LLC"])
def test_vendor_name_normalization_is_name_only_so_at_most_possible(vendor):
    software = sw("2.14.1", cpe=False, vendor=vendor)
    result = evaluate(software, [cfg(*RANGES)])
    assert result is not None and result.status == "possible"
    assert "name" in result.reason


def test_product_name_normalization():
    for product in ("Log4J", "log4j", " LOG4J "):
        assert status(sw("2.14.1", cpe=False, product=product), [cfg(*RANGES)]) == "possible"
    assert evaluate(sw("2.14.1", cpe=False, product="Log 4j"), [cfg(*RANGES)]) is None


def test_inventory_cpe_wins_over_names():
    software = sw("2.14.1", vendor="Totally Different", product="Name")
    assert status(software, [cfg(*RANGES)]) == "confirmed"


def test_name_only_out_of_range_is_not_affected_and_unknown_stays_unknown():
    assert status(sw("2.17.1", cpe=False), [cfg(*RANGES)]) == "not_affected"
    assert status(sw(None, cpe=False), [cfg(*RANGES)]) == "unknown"


def test_version_taken_from_cpe_when_inventory_version_missing():
    software = InstalledSoftware("Apache", "Log4j", None, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert status(software, [cfg(*RANGES)]) == "confirmed"


# ---- caps: confirmed becomes possible ---------------------------------------------------------
def test_and_configuration_with_platform_node_is_possible():
    configs = [cfg(*RANGES, operator="AND", extra_nodes=1)]
    result = evaluate(sw("2.14.1"), configs)
    assert result.status == "possible" and "platform" in result.reason


def test_single_node_and_configuration_is_not_capped():
    assert status(sw("2.14.1"), [cfg(*RANGES, operator="AND")]) == "confirmed"


def test_and_node_with_several_matches_is_possible():
    configs = [cfg(*RANGES, node_operator="AND")]
    assert status(sw("2.14.1"), configs) == "possible"


def test_negated_node_is_possible():
    assert status(sw("2.14.1"), [cfg(*RANGES, negate=True)]) == "possible"


def test_uncapped_entry_elsewhere_wins():
    capped = cfg(*RANGES, operator="AND", extra_nodes=1)
    plain = cfg(*RANGES)
    assert status(sw("2.14.1"), [capped, plain]) == "confirmed"


def test_out_of_range_inside_and_configuration_is_still_not_affected():
    assert status(sw("2.17.1"), [cfg(*RANGES, operator="AND", extra_nodes=1)]) == "not_affected"


@pytest.mark.parametrize(
    "criteria_update,inventory_cpe,expected",
    [
        ("beta9", "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "possible"),    # inventory does not record update
        ("beta9", "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", "confirmed"),
        ("beta9", "cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*", "not_affected"),  # different update: entry n/a
        ("-", "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*", "confirmed"),
        ("-", "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "possible"),
        ("*", "cpe:2.3:a:apache:log4j:2.0:rc2:*:*:*:*:*:*", "confirmed"),
    ],
)
def test_update_field_handling(criteria_update, inventory_cpe, expected):
    software = InstalledSoftware("Apache", "Log4j", "2.0", inventory_cpe)
    criteria = f"cpe:2.3:a:apache:log4j:2.0:{criteria_update}:*:*:*:*:*:*"
    assert status(software, [cfg(M(criteria))]) == expected


# ---- reasons are informative ------------------------------------------------------------------
def test_reasons_explain_the_decision():
    confirmed = evaluate(sw("2.14.1"), [cfg(*RANGES)])
    assert "2.14.1" in confirmed.reason and ">=2.13.0" in confirmed.reason and "<2.15.0" in confirmed.reason
    assert "apache:log4j" in confirmed.reason
    negative = evaluate(sw("2.17.1"), [cfg(*RANGES)])
    assert "outside" in negative.reason and "2.17.1" in negative.reason
    assert confirmed.matched_criteria == "X"  # matchCriteriaId of the NVD entry that decided it
