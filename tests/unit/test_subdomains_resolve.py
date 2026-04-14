from wotd.modules.subdomains_resolve import _extract_records


def test_extract_a_and_aaaa() -> None:
    entry = {
        "host": "api.example.com",
        "a": ["1.2.3.4", "5.6.7.8"],
        "aaaa": ["2001:db8::1"],
    }
    assert _extract_records(entry) == [
        ("api.example.com", "A", "1.2.3.4"),
        ("api.example.com", "A", "5.6.7.8"),
        ("api.example.com", "AAAA", "2001:db8::1"),
    ]


def test_extract_cname() -> None:
    entry = {"host": "www.example.com", "cname": ["example.com"]}
    assert _extract_records(entry) == [("www.example.com", "CNAME", "example.com")]


def test_extract_empty_when_no_records() -> None:
    assert _extract_records({"host": "example.com"}) == []


def test_extract_empty_when_missing_host() -> None:
    assert _extract_records({"a": ["1.2.3.4"]}) == []


def test_extract_ignores_non_string_values() -> None:
    entry = {"host": "example.com", "a": ["1.2.3.4", None, 42, ""]}
    assert _extract_records(entry) == [("example.com", "A", "1.2.3.4")]
