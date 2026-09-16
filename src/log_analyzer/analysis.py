"""Single-pass analysis. One traversal of the entries, bounded memory."""

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import datetime

from log_analyzer.models import LogEntry, Report, Summary, SuspiciousActivity

DEFAULT_WINDOW_SECONDS = 300
DEFAULT_THRESHOLD = 5


def has_burst(timestamps: list[datetime], window_seconds: int, threshold: int) -> bool:
    """True when more than `threshold` timestamps fall within any `window_seconds` interval."""
    window: deque[datetime] = deque()
    for moment in sorted(timestamps):
        window.append(moment)
        while (moment - window[0]).total_seconds() > window_seconds:
            window.popleft()
        if len(window) > threshold:
            return True
    return False


def detect_bursts(
    errors_by_source: dict[tuple[str, str], list[datetime]],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    threshold: int = DEFAULT_THRESHOLD,
) -> list[SuspiciousActivity]:
    """Report every (ip, user) pair whose errors form a burst."""
    suspicious = []
    for (ip, user), timestamps in errors_by_source.items():
        if not has_burst(timestamps, window_seconds, threshold):
            continue
        ordered = sorted(timestamps)
        suspicious.append(
            SuspiciousActivity(
                ip=ip,
                user=user,
                error_count=len(ordered),
                time_range=(ordered[0], ordered[-1]),
            )
        )
    return suspicious


def analyze(
    entries: Iterable[LogEntry | None],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    threshold: int = DEFAULT_THRESHOLD,
) -> Report:
    """Aggregate a stream of entries into a Report. None marks a malformed line."""
    malformed = 0
    total = 0
    users: dict[str, None] = {}
    ips: dict[str, None] = {}
    logins: defaultdict[str, int] = defaultdict(int)
    # dict-as-ordered-set: keeps first-seen order without the O(n) lookups of a list
    ips_by_user: defaultdict[str, dict[str, None]] = defaultdict(dict)
    errors_by_source: defaultdict[tuple[str, str], list[datetime]] = defaultdict(list)

    for entry in entries:
        if entry is None:
            malformed += 1
            continue

        total += 1
        users[entry.user] = None
        ips[entry.ip] = None
        ips_by_user[entry.user][entry.ip] = None

        if entry.action == "LOGIN" and entry.level == "INFO":
            logins[entry.user] += 1

        if entry.level == "ERROR":
            errors_by_source[(entry.ip, entry.user)].append(entry.timestamp)

    return Report(
        summary=Summary(
            total_entries=total,
            total_users=len(users),
            total_ips=len(ips),
            malformed_entries=malformed,
        ),
        suspicious_activity=detect_bursts(errors_by_source, window_seconds, threshold),
        # busiest users first, as the previous pandas implementation did
        logins_per_user=dict(sorted(logins.items(), key=lambda item: item[1], reverse=True)),
        ips_per_user={user: list(seen) for user, seen in ips_by_user.items()},
    )
