from wotd.scope import RuleType, Scope


def test_exact_match() -> None:
    scope = Scope()
    scope.add_include("example.com")
    assert scope.is_in_scope("example.com")
    assert not scope.is_in_scope("sub.example.com")
    assert not scope.is_in_scope("other.com")


def test_wildcard_match() -> None:
    scope = Scope()
    scope.add_include("*.example.com", RuleType.WILDCARD)
    assert scope.is_in_scope("sub.example.com")
    assert scope.is_in_scope("deep.sub.example.com")
    assert not scope.is_in_scope("example.com")
    assert not scope.is_in_scope("other.com")


def test_regex_match() -> None:
    scope = Scope()
    scope.add_include(r".*\.example\.(com|org)$", RuleType.REGEX)
    assert scope.is_in_scope("sub.example.com")
    assert scope.is_in_scope("sub.example.org")
    assert not scope.is_in_scope("sub.example.net")


def test_exclude_takes_precedence() -> None:
    scope = Scope()
    scope.add_include("*.example.com", RuleType.WILDCARD)
    scope.add_exclude("internal.example.com")
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("internal.example.com")


def test_no_includes_means_nothing_in_scope() -> None:
    scope = Scope()
    assert not scope.is_in_scope("anything.com")


def test_case_insensitive() -> None:
    scope = Scope()
    scope.add_include("Example.COM")
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("EXAMPLE.COM")


def test_trailing_dot_normalized() -> None:
    scope = Scope()
    scope.add_include("example.com.")
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("example.com.")


def test_from_dict() -> None:
    scope = Scope.from_dict(
        {
            "includes": [
                {"pattern": "*.example.com", "type": "wildcard"},
                {"pattern": "target.org", "type": "exact"},
            ],
            "excludes": [
                {"pattern": "admin.example.com", "type": "exact"},
            ],
        }
    )
    assert scope.is_in_scope("api.example.com")
    assert scope.is_in_scope("target.org")
    assert not scope.is_in_scope("admin.example.com")
    assert not scope.is_in_scope("random.org")
