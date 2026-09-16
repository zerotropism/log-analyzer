"""Deterministic synthetic log generation, for tests and demos."""

import random
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

LEVELS = ("INFO", "WARNING", "ERROR")
ACTIONS = ("LOGIN", "LOGOUT", "REQUEST", "ACCESS")
USERS = ("alice", "bob", "carol", "dave", "erin")
MALFORMED = (
    "not a log line at all",
    "[2024-01-15 10:00:00] missing brackets",
    "[2024-13-45 10:00:00] [INFO] [1.1.1.1] [alice] LOGIN: impossible date",
)

LINE = "[{timestamp:%Y-%m-%d %H:%M:%S}] [{level}] [{ip}] [{user}] {action}: {message}"


def _line(moment: datetime, level: str, ip: str, user: str, action: str, message: str) -> str:
    return LINE.format(
        timestamp=moment, level=level, ip=ip, user=user, action=action, message=message
    )


def generate(
    lines: int = 2000,
    seed: int = 0,
    attackers: int = 2,
    burst_size: int = 8,
    malformed_ratio: float = 0.05,
    start: datetime | None = None,
) -> Iterator[str]:
    """Yield log lines: background traffic, injected bursts, and malformed lines.

    The same seed always yields the same file, so tests can assert on exact counts.
    """
    rng = random.Random(seed)
    moment = start or datetime(2024, 1, 15, 8, 0, 0)

    for index in range(lines):
        moment += timedelta(seconds=rng.randint(1, 20))

        if rng.random() < malformed_ratio:
            yield rng.choice(MALFORMED)
            continue

        yield _line(
            moment,
            rng.choices(LEVELS, weights=(70, 20, 10))[0],
            f"192.168.{rng.randint(0, 4)}.{rng.randint(1, 254)}",
            rng.choice(USERS),
            rng.choice(ACTIONS),
            f"event {index}",
        )

    # Bursts are appended last so they are unambiguous: one attacker, one IP, one window.
    for attacker in range(attackers):
        ip = f"10.0.0.{attacker + 1}"
        user = f"attacker{attacker + 1}"
        moment += timedelta(minutes=30)
        for _ in range(burst_size):
            moment += timedelta(seconds=20)
            yield _line(moment, "ERROR", ip, user, "ACCESS", "permission denied")


def write(path: str | Path, **kwargs) -> int:
    """Write a synthetic log file and return the number of lines written."""
    lines = list(generate(**kwargs))
    Path(path).write_text("\n".join(lines) + "\n")
    return len(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Génère un fichier de logs synthétique")
    parser.add_argument("--output", required=True)
    parser.add_argument("--lines", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--attackers", type=int, default=2)
    args = parser.parse_args()

    count = write(args.output, lines=args.lines, seed=args.seed, attackers=args.attackers)
    print(f"{count} lignes écrites dans {args.output}")


if __name__ == "__main__":
    main()
