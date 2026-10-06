"""MCP adapter: the analysis the CLI runs, exposed as tools, a resource and a prompt.

The server reads only below one root directory, and every analysis runs in a worker thread
under a timeout, so a large file can neither block the event loop nor hold a client forever.
"""

import asyncio
import os
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from log_analyzer import analysis
from log_analyzer.analysis import DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECONDS
from log_analyzer.loader import stream_entries
from log_analyzer.models import Report, SuspiciousActivity

ROOT_ENV_VAR = "LOG_ANALYZER_ROOT"
TIMEOUT_ENV_VAR = "LOG_ANALYZER_TIMEOUT"
DEFAULT_TIMEOUT_SECONDS = 30.0
READ_ONLY = {"readOnlyHint": True, "openWorldHint": False}


def resolve_within(root: Path, path: str) -> Path:
    """The file `path` designates below `root`; anything resolving outside it is refused.

    Resolution follows symlinks, so a link inside the root that points out of it is refused too.
    """
    base = root.resolve()
    candidate = (base / path).resolve()
    if not candidate.is_relative_to(base):
        raise ToolError(f"{path!r} is outside the readable root")
    if not candidate.is_file():
        raise ToolError(f"{path!r} is not a file below the readable root")
    return candidate


def create_server(root: Path, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> FastMCP:
    """Build a server reading below `root`. Tests pass their own root and timeout."""
    mcp = FastMCP("log-analyzer")

    async def report_for(path: str, window_seconds: int, threshold: int) -> Report:
        log_file = resolve_within(root, path)

        def run() -> Report:
            return analysis.analyze(stream_entries(log_file), window_seconds, threshold)

        try:
            return await asyncio.wait_for(asyncio.to_thread(run), timeout)
        except TimeoutError:
            raise ToolError(f"analysis of {path!r} exceeded {timeout:g}s") from None

    @mcp.tool(name="analyze", annotations=READ_ONLY)
    async def analyze_log(
        path: str,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        threshold: int = DEFAULT_THRESHOLD,
    ) -> Report:
        """Full report for a log file below the root: summary, error bursts, logins, IPs.

        A burst is more than `threshold` errors from one (ip, user) pair within
        `window_seconds`.
        """
        return await report_for(path, window_seconds, threshold)

    @mcp.tool(annotations=READ_ONLY)
    async def logins_per_user(path: str) -> dict[str, int]:
        """Successful logins per user, busiest first."""
        report = await report_for(path, DEFAULT_WINDOW_SECONDS, DEFAULT_THRESHOLD)
        return report.logins_per_user

    @mcp.tool(annotations=READ_ONLY)
    async def ips_per_user(path: str) -> dict[str, list[str]]:
        """IP addresses each user connected from, in first-seen order."""
        report = await report_for(path, DEFAULT_WINDOW_SECONDS, DEFAULT_THRESHOLD)
        return report.ips_per_user

    @mcp.tool(annotations=READ_ONLY)
    async def suspicious_sources(
        path: str,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        threshold: int = DEFAULT_THRESHOLD,
    ) -> list[SuspiciousActivity]:
        """(ip, user) pairs with more than `threshold` errors within `window_seconds`."""
        report = await report_for(path, window_seconds, threshold)
        return report.suspicious_activity

    @mcp.resource("report://{path*}", mime_type="application/json")
    async def report(path: str) -> str:
        """The default report for a log file below the root, as JSON."""
        result = await report_for(path, DEFAULT_WINDOW_SECONDS, DEFAULT_THRESHOLD)
        return result.model_dump_json(indent=2)

    @mcp.prompt
    def investigate_source(ip_or_user: str, path: str) -> str:
        """Ask the model to investigate one IP address or user in a log file."""
        return (
            f"Investigate {ip_or_user} in the log file {path}, using the log-analyzer tools. "
            "Call suspicious_sources first, then ips_per_user and logins_per_user. Report its "
            "error bursts (count and time range), the IP addresses or users linked to it, and "
            "whether the pattern looks like a brute-force attempt. Quote figures from the tool "
            "results only."
        )

    return mcp


def main() -> None:
    """Console entry point: serve over stdio, reading only below LOG_ANALYZER_ROOT."""
    configured = os.environ.get(ROOT_ENV_VAR)
    if not configured:
        raise SystemExit(f"Set {ROOT_ENV_VAR} to the directory the server may read.")
    root = Path(configured).expanduser()
    if not root.is_dir():
        raise SystemExit(f"{ROOT_ENV_VAR}={configured} is not a directory.")
    timeout = float(os.environ.get(TIMEOUT_ENV_VAR, DEFAULT_TIMEOUT_SECONDS))
    create_server(root, timeout).run(show_banner=False)


if __name__ == "__main__":
    main()
