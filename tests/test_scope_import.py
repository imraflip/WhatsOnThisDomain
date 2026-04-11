import json
from pathlib import Path

from wotd.scope_import import import_bugcrowd, import_hackerone


def test_hackerone_import(tmp_path: Path) -> None:
    h1_data = {
        "relationships": {
            "structured_scopes": {
                "data": [
                    {
                        "attributes": {
                            "asset_identifier": "*.example.com",
                            "asset_type": "URL",
                            "eligible_for_bounty": True,
                            "eligible_for_submission": True,
                        }
                    },
                    {
                        "attributes": {
                            "asset_identifier": "internal.example.com",
                            "asset_type": "URL",
                            "eligible_for_bounty": False,
                            "eligible_for_submission": True,
                        }
                    },
                    {
                        "attributes": {
                            "asset_identifier": "10.0.0.0/8",
                            "asset_type": "CIDR",
                            "eligible_for_bounty": True,
                            "eligible_for_submission": True,
                        }
                    },
                ]
            }
        }
    }
    scope_file = tmp_path / "h1.json"
    scope_file.write_text(json.dumps(h1_data))

    scope = import_hackerone(scope_file)
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("internal.example.com")
    # CIDR should be ignored (not a URL/DOMAIN/WILDCARD type)
    assert not scope.is_in_scope("10.0.0.0/8")


def test_hackerone_skips_non_submittable(tmp_path: Path) -> None:
    h1_data = {
        "relationships": {
            "structured_scopes": {
                "data": [
                    {
                        "attributes": {
                            "asset_identifier": "*.nope.com",
                            "asset_type": "URL",
                            "eligible_for_bounty": True,
                            "eligible_for_submission": False,
                        }
                    }
                ]
            }
        }
    }
    scope_file = tmp_path / "h1.json"
    scope_file.write_text(json.dumps(h1_data))

    scope = import_hackerone(scope_file)
    assert not scope.is_in_scope("anything.nope.com")


def test_bugcrowd_import(tmp_path: Path) -> None:
    bc_data = {
        "target_groups": [
            {
                "in_scope": True,
                "targets": [
                    {"name": "*.target.com", "category": "website"},
                    {"name": "api.target.com", "category": "api"},
                ],
            },
            {
                "in_scope": False,
                "targets": [
                    {"name": "staging.target.com", "category": "website"},
                ],
            },
            {
                "in_scope": True,
                "targets": [
                    {"name": "com.target.app", "category": "android"},
                ],
            },
        ]
    }
    scope_file = tmp_path / "bc.json"
    scope_file.write_text(json.dumps(bc_data))

    scope = import_bugcrowd(scope_file)
    assert scope.is_in_scope("www.target.com")
    assert scope.is_in_scope("api.target.com")
    assert not scope.is_in_scope("staging.target.com")
    # Android app should be ignored
    assert not scope.is_in_scope("com.target.app")
