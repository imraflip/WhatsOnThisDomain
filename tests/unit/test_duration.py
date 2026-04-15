from datetime import timedelta

import pytest

from wotd.utils.duration import parse_duration


def test_hours() -> None:
    assert parse_duration("24h") == timedelta(hours=24)


def test_days() -> None:
    assert parse_duration("7d") == timedelta(days=7)


def test_weeks() -> None:
    assert parse_duration("2w") == timedelta(weeks=2)


def test_trim_and_lowercase() -> None:
    assert parse_duration(" 12H ") == timedelta(hours=12)


def test_rejects_missing_unit() -> None:
    with pytest.raises(ValueError):
        parse_duration("24")


def test_rejects_unknown_unit() -> None:
    with pytest.raises(ValueError):
        parse_duration("1y")


def test_rejects_empty() -> None:
    with pytest.raises(ValueError):
        parse_duration("")
