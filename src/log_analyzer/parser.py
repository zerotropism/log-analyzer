"""Line-level parsing. The pattern is the specification of the log format."""

import re
from datetime import datetime

from log_analyzer.models import LogEntry

# [2024-01-15 10:23:45] [INFO] [192.168.1.100] [john_doe] LOGIN: Successful login attempt
PATTERN = re.compile(
    r"\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] "
    r"\[(?P<level>[^]]+)\] \[(?P<ip>[^]]+)\] \[(?P<user>[^]]+)\] "
    r"(?P<action>[^:]+): (?P<message>.+)"
)


def parse_line(line: str) -> LogEntry | None:
    """Parse one log line. Returns None when the line does not match the format."""
    match = PATTERN.match(line)
    if match is None:
        return None

    fields = match.groupdict()
    try:
        timestamp = datetime.fromisoformat(fields.pop("timestamp"))
    except ValueError:
        return None  # syntactically well-formed but impossible date, e.g. 2024-13-45

    return LogEntry(timestamp=timestamp, **fields)
