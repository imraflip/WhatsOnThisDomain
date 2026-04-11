"""Import scope definitions from bug bounty platforms."""

from __future__ import annotations

import json
from pathlib import Path

from wotd.scope import RuleType, Scope


def import_hackerone(source: str | Path) -> Scope:
    """Import scope from a HackerOne JSON export.

    Expects the structured_scope format from HackerOne's API or export,
    which looks like:
    {
        "relationships": {
            "structured_scopes": {
                "data": [
                    {
                        "attributes": {
                            "asset_identifier": "*.example.com",
                            "asset_type": "URL",
                            "eligible_for_bounty": true,
                            "eligible_for_submission": true
                        }
                    }
                ]
            }
        }
    }
    """
    data = _load_json(source)
    scope = Scope()

    scopes_data = (
        data.get("relationships", {}).get("structured_scopes", {}).get("data", [])
    )

    for item in scopes_data:
        attrs = item.get("attributes", {})
        identifier = attrs.get("asset_identifier", "")
        asset_type = attrs.get("asset_type", "").upper()

        if asset_type not in ("URL", "DOMAIN", "WILDCARD"):
            continue

        if not attrs.get("eligible_for_submission", False):
            continue

        rule_type = RuleType.WILDCARD if "*" in identifier else RuleType.EXACT
        if attrs.get("eligible_for_bounty", False):
            scope.add_include(identifier, rule_type)
        else:
            scope.add_exclude(identifier, rule_type)

    return scope


def import_bugcrowd(source: str | Path) -> Scope:
    """Import scope from a Bugcrowd JSON export.

    Expects the target format from Bugcrowd's API or export:
    {
        "target_groups": [
            {
                "in_scope": true,
                "targets": [
                    {
                        "name": "*.example.com",
                        "category": "website"
                    }
                ]
            }
        ]
    }
    """
    data = _load_json(source)
    scope = Scope()

    for group in data.get("target_groups", []):
        in_scope = group.get("in_scope", False)

        for target in group.get("targets", []):
            name = target.get("name", "")
            category = target.get("category", "").lower()

            if category not in ("website", "domain", "api"):
                continue

            rule_type = RuleType.WILDCARD if "*" in name else RuleType.EXACT
            if in_scope:
                scope.add_include(name, rule_type)
            else:
                scope.add_exclude(name, rule_type)

    return scope


def _load_json(source: str | Path) -> dict:  # type: ignore[type-arg]
    path = Path(source)
    with open(path) as f:
        return json.load(f)  # type: ignore[no-any-return]
