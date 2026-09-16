"""Analysis tests: burst detection in isolation, then the full single-pass aggregation."""

from datetime import datetime, timedelta

from log_analyzer.analysis import analyze, has_burst
from log_analyzer.models import LogEntry

BASE = datetime(2024, 1, 1, 12, 0, 0)


def moments(count: int, gap_seconds: int = 30) -> list[datetime]:
    return [BASE + timedelta(seconds=i * gap_seconds) for i in range(count)]


def entry(offset: int = 0, *, level="INFO", ip="1.2.3.4", user="alice", action="LOGIN"):
    return LogEntry(BASE + timedelta(seconds=offset), level, ip, user, action, "msg")


def test_burst_detected_above_threshold() -> None:
    assert has_burst(moments(8, 20), window_seconds=300, threshold=5)


def test_no_burst_below_threshold() -> None:
    assert not has_burst(moments(4, 20), window_seconds=300, threshold=5)


def test_no_burst_when_spread_beyond_the_window() -> None:
    assert not has_burst(moments(8, 120), window_seconds=300, threshold=5)


def test_threshold_is_strictly_exceeded() -> None:
    """Exactly `threshold` errors is not a burst; one more is."""
    assert not has_burst(moments(5, 10), window_seconds=300, threshold=5)
    assert has_burst(moments(6, 10), window_seconds=300, threshold=5)


def test_unsorted_timestamps_are_handled() -> None:
    assert has_burst(list(reversed(moments(8, 20))), window_seconds=300, threshold=5)


def test_malformed_lines_are_counted_not_analysed() -> None:
    report = analyze(iter([None, None, entry()]))
    assert report.summary.malformed_entries == 2
    assert report.summary.total_entries == 1


def test_only_info_logins_are_counted() -> None:
    entries = [
        entry(0),
        entry(60),
        entry(120, level="ERROR", action="REQUEST"),
        entry(180, level="ERROR"),  # failed login: not counted
    ]
    assert analyze(iter(entries)).logins_per_user["alice"] == 2


def test_logins_are_sorted_by_count_descending() -> None:
    entries = [entry(0, user="alice"), *(entry(i, user="bob") for i in range(3))]
    assert list(analyze(iter(entries)).logins_per_user) == ["bob", "alice"]


def test_ips_per_user_keeps_first_seen_order_without_duplicates() -> None:
    entries = [entry(0, ip="1.1.1.1"), entry(1, ip="2.2.2.2"), entry(2, ip="1.1.1.1")]
    assert analyze(iter(entries)).ips_per_user["alice"] == ["1.1.1.1", "2.2.2.2"]


def test_empty_input_produces_an_empty_report() -> None:
    """The former pandas path raised KeyError here."""
    report = analyze(iter([]))
    assert report.summary.total_entries == 0
    assert report.suspicious_activity == []


def test_suspicious_activity_reports_range_and_count(sample_entries) -> None:
    activity = analyze(iter(sample_entries)).suspicious_activity
    assert len(activity) == 1
    assert activity[0].user == "alice"
    assert activity[0].error_count == 8
    assert activity[0].time_range[0] == BASE
