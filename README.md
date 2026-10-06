# Log Analyzer

A Python security log analysis tool. It parses server log files to detect suspicious behavior,
extract usage statistics, and generate JSON reports.

Analysis runs as a single streaming pass: memory stays bounded whatever the file size, and the
output is deterministic — the same input always produces byte-identical JSON.

## Features

- **Log parsing**: reads and validates the format `[TIMESTAMP] [LEVEL] [IP] [USER] ACTION: message`
- **Anomaly detection**: identifies sources (IP/user) generating more than 5 errors within a
  5-minute sliding window; both bounds are configurable
- **Queries**: successful logins per user, IP addresses per user
- **JSON report**: typed with pydantic — the model is the output contract
- **Robustness**: malformed lines are counted without interrupting the analysis
- **Synthetic logs**: a seeded generator produces reproducible files, including bursts
- **MCP server**: the same analysis exposed to MCP clients and LLM agents, confined to one
  directory

## Expected Log Format

```
[2024-01-15 10:23:45] [INFO] [192.168.1.100] [john_doe] LOGIN: Successful login attempt
[2024-01-15 10:23:47] [ERROR] [192.168.1.101] [jane_smith] ACCESS: Invalid permission for /admin/users
```

A line is counted as malformed when it does not match this shape, or when it matches but carries
an impossible date such as `2024-13-45`.

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Usage

```bash
# Standard analysis
uv run log-analyzer --input input/sample.log

# Save the report to a file
uv run log-analyzer --input input/sample.log --output report.json

# Tighter detection: more than 3 errors within 60 seconds
uv run log-analyzer --input input/sample.log --window 60 --threshold 3
```

The sample file in `input/` contains no burst at the default thresholds. To exercise detection,
generate a file that contains some:

```bash
uv run log-analyzer-gen --output /tmp/synthetic.log --lines 50000 --seed 42
uv run log-analyzer --input /tmp/synthetic.log
```

The same seed always yields the same file, which is what makes the tests reproducible.

## MCP Server

`log-analyzer-mcp` serves the same analysis over stdio, as a second adapter next to the CLI: both
call one function and return the same `Report`.

| Kind | Name | Returns |
|---|---|---|
| Tool | `analyze(path, window_seconds=300, threshold=5)` | the full report |
| Tool | `logins_per_user(path)` | successful logins per user |
| Tool | `ips_per_user(path)` | IP addresses per user |
| Tool | `suspicious_sources(path, window_seconds=300, threshold=5)` | error bursts per (ip, user) |
| Resource | `report://{path}` | the default report, as JSON |
| Prompt | `investigate_source(ip_or_user, path)` | instructions to investigate one source with the tools |

Every tool is read-only. The server reads only below `LOG_ANALYZER_ROOT` and refuses to start
without it; a path that resolves outside, through `..`, an absolute path or a symlink, is
refused. Each analysis runs in a worker thread and is cut off after `LOG_ANALYZER_TIMEOUT`
seconds (30 by default).

MCP clients forward only a short list of environment variables to a stdio server, so pass the
root explicitly. With [mcp-servers-cli](https://pypi.org/project/mcp-servers-cli/):

```bash
mkdir -p /tmp/logs && uv run log-analyzer-gen --output /tmp/logs/synthetic.log --lines 5000 --seed 42
uvx mcp-servers-cli call suspicious_sources '{"path": "synthetic.log"}' \
  --env LOG_ANALYZER_ROOT=/tmp/logs --stdio "uv run --directory $PWD log-analyzer-mcp"
uvx mcp-servers-cli agent "Which sources look suspicious in synthetic.log?" \
  --model qwen3.5:4b-mlx \
  --env LOG_ANALYZER_ROOT=/tmp/logs --stdio "uv run --directory $PWD log-analyzer-mcp"
```

## Output Report Structure

```json
{
  "summary": {
    "total_entries": 1500,
    "total_users": 12,
    "total_ips": 8,
    "malformed_entries": 3
  },
  "suspicious_activity": [
    {
      "ip": "192.168.1.101",
      "user": "jane_smith",
      "error_count": 7,
      "time_range": ["2024-01-15T10:20:00", "2024-01-15T10:24:30"]
    }
  ],
  "logins_per_user": {
    "john_doe": 5
  },
  "ips_per_user": {
    "john_doe": ["192.168.1.100", "10.0.0.5"]
  }
}
```

Timestamps are ISO 8601. `logins_per_user` is sorted by count, busiest first;
`ips_per_user` keeps first-seen order.

## Project Structure

```
src/log_analyzer/
├── models.py      # LogEntry (dataclass) and the Report contract (pydantic)
├── parser.py      # Line pattern and parsing
├── loader.py      # File streaming
├── analysis.py    # Single-pass aggregation and sliding-window burst detection
├── synthetic.py   # Seeded log generator
├── cli.py         # Command-line adapter
└── server.py      # MCP adapter: tools, resource, prompt; root confinement and timeout
input/             # Sample log file
tests/             # pytest suite
```

`LogEntry` is a frozen dataclass because one is built per log line; `Report` is a pydantic model
because it is built once per run and defines the public output contract.

## Tests

```bash
uv run pytest
```

## Dependencies

| Package    | Role                          |
|------------|-------------------------------|
| `pydantic` | Report model and serialization |
| `fastmcp`  | MCP server                     |

`pytest`, `pytest-asyncio` and `ruff` live in the `dev` dependency group.

## Detection semantics

A source is flagged when strictly more than `threshold` errors fall within any `window` window,
for a given `(ip, user)` pair. Grouping on the pair means an attacker rotating IP addresses
between attempts will not be flagged; grouping by user alone would catch that case at the cost
of more false positives on shared accounts.
