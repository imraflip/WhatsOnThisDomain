from wotd.parsers import normalize_hosts, parse_jsonl, parse_lines


def test_parse_lines_basic() -> None:
    output = "one\ntwo\nthree\n"
    assert parse_lines(output) == ["one", "two", "three"]


def test_parse_lines_strips_whitespace_and_empties() -> None:
    output = "  one  \n\n  two\n   \nthree\n"
    assert parse_lines(output) == ["one", "two", "three"]


def test_parse_jsonl_basic() -> None:
    output = '{"a": 1}\n{"b": 2}\n'
    assert parse_jsonl(output) == [{"a": 1}, {"b": 2}]


def test_parse_jsonl_skips_invalid_lines() -> None:
    output = '{"a": 1}\nnot json\n{"b": 2}\n'
    assert parse_jsonl(output) == [{"a": 1}, {"b": 2}]


def test_parse_jsonl_skips_non_objects() -> None:
    output = '{"a": 1}\n[1, 2, 3]\n42\n{"b": 2}\n'
    assert parse_jsonl(output) == [{"a": 1}, {"b": 2}]


def test_normalize_hosts_lowercases_and_strips() -> None:
    assert normalize_hosts(["  API.Example.COM  "]) == ["api.example.com"]


def test_normalize_hosts_drops_trailing_dot() -> None:
    assert normalize_hosts(["example.com."]) == ["example.com"]


def test_normalize_hosts_dedupes_and_sorts() -> None:
    assert normalize_hosts(
        ["b.example.com", "a.example.com", "A.example.com", "b.example.com."]
    ) == ["a.example.com", "b.example.com"]


def test_normalize_hosts_drops_empty() -> None:
    assert normalize_hosts(["", "  ", "example.com"]) == ["example.com"]
