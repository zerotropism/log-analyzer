"""The Report model is the output contract: its JSON shape is part of the API."""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from log_analyzer.models import Report, Summary, SuspiciousActivity


def make_report() -> Report:
    return Report(
        summary=Summary(total_entries=3, total_users=1, total_ips=1, malformed_entries=2),
        suspicious_activity=[
            SuspiciousActivity(
                ip="1.2.3.4",
                user="alice",
                error_count=7,
                time_range=(
                    datetime(2024, 1, 15, 10, 20),
                    datetime(2024, 1, 15, 10, 24, 30),
                ),
            )
        ],
        logins_per_user={"john": 5},
        ips_per_user={"john": ["192.168.1.100", "10.0.0.5"]},
    )


def test_json_keeps_the_documented_section_names() -> None:
    payload = json.loads(make_report().model_dump_json())
    assert list(payload) == [
        "summary",
        "suspicious_activity",
        "logins_per_user",
        "ips_per_user",
    ]


def test_timestamps_are_serialised_as_iso() -> None:
    activity = json.loads(make_report().model_dump_json())["suspicious_activity"][0]
    assert activity["time_range"] == ["2024-01-15T10:20:00", "2024-01-15T10:24:30"]


def test_time_range_needs_exactly_two_bounds() -> None:
    with pytest.raises(ValidationError):
        SuspiciousActivity(
            ip="1.2.3.4",
            user="alice",
            error_count=7,
            time_range=(datetime(2024, 1, 1),),
        )
