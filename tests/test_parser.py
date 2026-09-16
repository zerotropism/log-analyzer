from datetime import datetime

import pytest

from log_analyzer.models import LogEntry
from log_analyzer.parser import parse_line

TS = datetime(2024, 1, 1, 12, 0, 0)


@pytest.mark.parametrize(
    "line,expected",
    [
        (
            "[2024-01-01 12:00:00] [ERROR] [192.168.1.1] [alice] LOGIN: failed attempt",
            LogEntry(TS, "ERROR", "192.168.1.1", "alice", "LOGIN", "failed attempt"),
        ),
        (
            "[2024-01-01 12:00:00] [INFO] [10.0.0.1] [bob] LOGIN: success",
            LogEntry(TS, "INFO", "10.0.0.1", "bob", "LOGIN", "success"),
        ),
        (
            "[2024-01-01 12:00:00] [INFO] [10.0.0.1] [bob] LOGIN: msg: with colon",
            LogEntry(TS, "INFO", "10.0.0.1", "bob", "LOGIN", "msg: with colon"),
        ),
        ("", None),
        ("garbage", None),
        # well-formed shape, impossible date: counted as malformed rather than crashing later
        ("[2024-13-45 10:00:00] [INFO] [1.1.1.1] [x] LOGIN: bad date", None),
    ],
)
def test_parse_line(line, expected) -> None:
    assert parse_line(line) == expected


def test_timestamp_is_parsed_once_into_a_datetime() -> None:
    entry = parse_line("[2024-01-01 12:00:00] [INFO] [1.1.1.1] [x] LOGIN: ok")
    assert entry.timestamp == TS
