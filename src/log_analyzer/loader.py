"""File-level reading. Yields one entry per line, None for malformed lines."""

from collections.abc import Iterator
from pathlib import Path

from log_analyzer.models import LogEntry
from log_analyzer.parser import parse_line


def stream_entries(path: str | Path) -> Iterator[LogEntry | None]:
    """Stream a log file line by line; memory stays bounded whatever the file size."""
    with Path(path).open() as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            yield parse_line(stripped)
