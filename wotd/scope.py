from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Self


class RuleType(Enum):
    EXACT = "exact"
    WILDCARD = "wildcard"
    REGEX = "regex"


@dataclass
class ScopeRule:
    pattern: str
    rule_type: RuleType
    _compiled_regex: re.Pattern[str] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.rule_type == RuleType.REGEX:
            self._compiled_regex = re.compile(self.pattern, re.IGNORECASE)

    def matches(self, value: str) -> bool:
        value = value.lower().strip().rstrip(".")
        if self.rule_type == RuleType.EXACT:
            return value == self.pattern.lower().strip().rstrip(".")
        elif self.rule_type == RuleType.WILDCARD:
            return fnmatch.fnmatch(value, self.pattern.lower().strip().rstrip("."))
        elif self.rule_type == RuleType.REGEX:
            assert self._compiled_regex is not None
            return self._compiled_regex.search(value) is not None
        return False


@dataclass
class Scope:
    """Determines whether an asset is in scope for scanning.

    Exclude rules always take precedence over include rules.
    If no include rules are defined, nothing is in scope.
    """

    includes: list[ScopeRule] = field(default_factory=list)
    excludes: list[ScopeRule] = field(default_factory=list)

    def is_in_scope(self, value: str) -> bool:
        for rule in self.excludes:
            if rule.matches(value):
                return False
        for rule in self.includes:
            if rule.matches(value):
                return True
        return False

    def add_include(self, pattern: str, rule_type: RuleType = RuleType.EXACT) -> None:
        self.includes.append(ScopeRule(pattern=pattern, rule_type=rule_type))

    def add_exclude(self, pattern: str, rule_type: RuleType = RuleType.EXACT) -> None:
        self.excludes.append(ScopeRule(pattern=pattern, rule_type=rule_type))

    @classmethod
    def from_dict(cls, data: dict[str, list[dict[str, str]]]) -> Self:
        """Build a Scope from a dict like:
        {
            "includes": [{"pattern": "*.example.com", "type": "wildcard"}],
            "excludes": [{"pattern": "internal.example.com", "type": "exact"}],
        }
        """
        scope = cls()
        for entry in data.get("includes", []):
            scope.add_include(entry["pattern"], RuleType(entry.get("type", "exact")))
        for entry in data.get("excludes", []):
            scope.add_exclude(entry["pattern"], RuleType(entry.get("type", "exact")))
        return scope
