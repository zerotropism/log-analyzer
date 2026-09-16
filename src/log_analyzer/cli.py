"""Command-line entry point."""

import argparse
import os
import sys
from pathlib import Path

from log_analyzer.analysis import DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECONDS, analyze
from log_analyzer.loader import stream_entries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyse de sécurité des logs")
    parser.add_argument("--input", required=True, help="Chemin vers le fichier de logs")
    parser.add_argument("--output", default=None, help="Fichier JSON de sortie (stdout par défaut)")
    parser.add_argument(
        "--window", type=int, default=DEFAULT_WINDOW_SECONDS, help="Fenêtre en secondes"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Nombre d'erreurs déclenchant une alerte",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = analyze(stream_entries(args.input), args.window, args.threshold)
    output = report.model_dump_json(indent=2)

    if args.output:
        Path(args.output).write_text(output)
        return

    try:
        print(output)
        sys.stdout.flush()
    except BrokenPipeError:
        # downstream closed early (e.g. `| head`): silence the interpreter's own flush
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
