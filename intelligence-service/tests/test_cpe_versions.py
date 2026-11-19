import pytest

from correlation.cpe import normalize_token, parse_cpe23
from correlation.versions import compare, parse_version


@pytest.mark.parametrize(
    "text,expected",
    [("1", (1,)), ("1.2.3", (1, 2, 3)), ("01.002", (1, 2)), ("10.0.0.0.0.1", (10, 0, 0, 0, 0, 1)),
     (" 2.0 ", (2, 0))],
)
def test_parse_version_accepts_dotted_numeric(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    "text",
    [None, "", "v1.2", "1.2.3p1", "2.0-beta", "1..2", "1.2.", ".1", "1.2.3.4.5.6.7", "1,2", "٣.١", "1e3", "latest", "1.x"],
)
def test_parse_version_rejects_everything_else(text):
    assert parse_version(text) is None


@pytest.mark.parametrize(
    "a,b,expected",
    [((1, 0), (1, 0, 0), 0), ((1, 2), (1, 10), -1), ((2,), (1, 9, 9), 1), ((1, 0, 1), (1, 0), 1)],
)
def test_compare_is_numeric_and_zero_padded(a, b, expected):
    assert compare(a, b) == expected
    assert compare(b, a) == -expected


def test_parse_cpe_basic_and_escapes():
    c = parse_cpe23("cpe:2.3:a:Apache:Log4j:2.14.1:*:*:*:*:*:*:*")
    assert (c.part, c.vendor, c.product, c.version, c.update) == ("a", "apache", "log4j", "2.14.1", "*")
    esc = parse_cpe23(r"cpe:2.3:a:ven\:dor:prod\.uct:1.0:*:*:*:*:*:*:*")
    assert esc.vendor == "ven:dor" and esc.product == "prod.uct"


@pytest.mark.parametrize(
    "bad",
    [None, "", "cpe:2.2:a:x:y", "cpe:2.3:a:x:y:1.0", "cpe:2.3:z:x:y:1.0:*:*:*:*:*:*:*",
     "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*:*", "cpe:2.3:a::y:1.0:*:*:*:*:*:*:*", "x" * 2000, 42],
)
def test_parse_cpe_rejects_malformed(bad):
    assert parse_cpe23(bad) is None


@pytest.mark.parametrize(
    "text,vendor,expected",
    [("Apache", True, "apache"), ("Example Vendor, Inc.", True, "example_vendor"), ("ACME Corp", True, "acme"),
     ("Inc", True, "inc"), ("Example Server", False, "example_server"), ("Foo-Bar_Baz 2", False, "foo_bar_baz_2"),
     ("Widgets Co", False, "widgets_co"), ("  ", False, "")],
)
def test_normalize_token(text, vendor, expected):
    assert normalize_token(text, vendor=vendor) == expected
