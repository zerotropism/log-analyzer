"""The generator is a test fixture: it must be reproducible and actually trip the detector."""

from log_analyzer.analysis import analyze
from log_analyzer.loader import stream_entries
from log_analyzer.synthetic import generate, write


def test_same_seed_yields_the_same_file() -> None:
    assert list(generate(lines=50, seed=1)) == list(generate(lines=50, seed=1))


def test_different_seeds_yield_different_files() -> None:
    assert list(generate(lines=50, seed=1)) != list(generate(lines=50, seed=2))


def test_generated_bursts_are_detected(tmp_path) -> None:
    path = tmp_path / "synthetic.log"
    write(path, lines=200, seed=42, attackers=2, burst_size=8)

    report = analyze(stream_entries(path))

    assert [a.user for a in report.suspicious_activity] == ["attacker1", "attacker2"]
    assert all(a.error_count == 8 for a in report.suspicious_activity)


def test_malformed_lines_are_produced_and_counted(tmp_path) -> None:
    path = tmp_path / "synthetic.log"
    write(path, lines=200, seed=42, malformed_ratio=0.2)

    assert analyze(stream_entries(path)).summary.malformed_entries > 0
