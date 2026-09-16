"""Domain models. LogEntry stays a dataclass: it is built once per log line."""

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel


@dataclass(frozen=True, slots=True)
class LogEntry:
    timestamp: datetime
    level: str
    ip: str
    user: str
    action: str
    message: str


class Summary(BaseModel):
    total_entries: int
    total_users: int
    total_ips: int
    malformed_entries: int


class SuspiciousActivity(BaseModel):
    """One (ip, user) pair that exceeded the error threshold within the window."""

    ip: str
    user: str
    error_count: int
    time_range: tuple[datetime, datetime]


class Report(BaseModel):
    """The analysis output contract. Serialised as-is by the CLI and by the MCP server."""

    summary: Summary
    suspicious_activity: list[SuspiciousActivity]
    logins_per_user: dict[str, int]
    ips_per_user: dict[str, list[str]]
