from wotd.modules.subdomains_probe import _extract_service


def test_extract_full_entry() -> None:
    entry = {
        "input": "api.example.com",
        "url": "https://api.example.com",
        "status_code": 200,
        "title": "API",
        "tech": ["nginx", "cloudflare"],
        "content_length": 1234,
        "final_url": "https://api.example.com/",
    }
    assert _extract_service(entry) == {
        "host": "api.example.com",
        "url": "https://api.example.com",
        "status_code": 200,
        "title": "API",
        "tech": "nginx,cloudflare",
        "content_length": 1234,
        "final_url": "https://api.example.com/",
    }


def test_extract_missing_optional_fields() -> None:
    entry = {"input": "example.com", "url": "http://example.com"}
    svc = _extract_service(entry)
    assert svc is not None
    assert svc["host"] == "example.com"
    assert svc["status_code"] is None
    assert svc["title"] is None
    assert svc["tech"] is None


def test_extract_returns_none_when_url_missing() -> None:
    assert _extract_service({"input": "example.com"}) is None


def test_extract_falls_back_to_url_when_input_missing() -> None:
    svc = _extract_service({"url": "https://example.com"})
    assert svc is not None
    assert svc["host"] == "https://example.com"


def test_extract_drops_non_string_tech_entries() -> None:
    entry = {"url": "http://x", "tech": ["nginx", 42, None, "php"]}
    svc = _extract_service(entry)
    assert svc is not None
    assert svc["tech"] == "nginx,php"
