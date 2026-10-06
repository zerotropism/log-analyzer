"""The MCP adapter through the in-memory FastMCP client: same results as the CLI, confined
to its root, bounded in time."""

import json
import time
from pathlib import Path

import pytest
from fastmcp import Client

from log_analyzer import analysis, server, synthetic
from log_analyzer.loader import stream_entries
from log_analyzer.server import create_server

TOOLS = {"analyze", "logins_per_user", "ips_per_user", "suspicious_sources"}


@pytest.fixture
def root(tmp_path) -> Path:
    """A readable root holding a seeded 200-line log with two attackers, and a file outside it."""
    logs = tmp_path / "logs"
    logs.mkdir()
    synthetic.write(logs / "sample.log", lines=200, seed=0, attackers=2)
    (tmp_path / "secret.log").write_text("not for the server\n")
    return logs


@pytest.fixture
def client(root) -> Client:
    return Client(create_server(root, timeout=5))


def expected_report(root: Path) -> dict:
    report = analysis.analyze(stream_entries(root / "sample.log"))
    return report.model_dump(mode="json")


async def test_every_tool_is_listed_and_read_only(client) -> None:
    async with client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} == TOOLS
    assert all(tool.annotations.read_only_hint for tool in tools)


async def test_analyze_returns_the_report_the_cli_prints(client, root) -> None:
    async with client:
        result = await client.call_tool("analyze", {"path": "sample.log"})
    assert result.structured_content == expected_report(root)


async def test_partial_tools_agree_with_the_full_report(client, root) -> None:
    report = expected_report(root)
    async with client:
        logins = await client.call_tool("logins_per_user", {"path": "sample.log"})
        ips = await client.call_tool("ips_per_user", {"path": "sample.log"})
        sources = await client.call_tool("suspicious_sources", {"path": "sample.log"})
    # objects are returned as they are; MCP wraps a list in {"result": ...}
    assert logins.structured_content == report["logins_per_user"]
    assert ips.structured_content == report["ips_per_user"]
    assert sources.structured_content["result"] == report["suspicious_activity"]
    assert len(report["suspicious_activity"]) == 2  # the two seeded attackers


@pytest.mark.parametrize("path", ["../secret.log", "logs/../../secret.log"])
async def test_paths_leaving_the_root_are_refused(client, path) -> None:
    async with client:
        result = await client.call_tool("analyze", {"path": path}, raise_on_error=False)
    assert result.is_error
    assert "outside the readable root" in result.content[0].text


async def test_absolute_paths_outside_the_root_are_refused(client, root) -> None:
    outside = str(root.parent / "secret.log")
    async with client:
        result = await client.call_tool("analyze", {"path": outside}, raise_on_error=False)
    assert result.is_error
    assert "outside the readable root" in result.content[0].text


async def test_symlinks_out_of_the_root_are_refused(client, root) -> None:
    (root / "link.log").symlink_to(root.parent / "secret.log")
    async with client:
        result = await client.call_tool("analyze", {"path": "link.log"}, raise_on_error=False)
    assert result.is_error
    assert "outside the readable root" in result.content[0].text


async def test_a_missing_file_is_reported(client) -> None:
    async with client:
        result = await client.call_tool("analyze", {"path": "nope.log"}, raise_on_error=False)
    assert result.is_error
    assert "not a file" in result.content[0].text


async def test_a_slow_analysis_is_cut_off(root, monkeypatch) -> None:
    def slow(*args, **kwargs):
        time.sleep(1)

    monkeypatch.setattr(server.analysis, "analyze", slow)
    async with Client(create_server(root, timeout=0.1)) as client:
        result = await client.call_tool("analyze", {"path": "sample.log"}, raise_on_error=False)
    assert result.is_error
    assert "exceeded 0.1s" in result.content[0].text


async def test_report_resource_matches_the_tool(client, root) -> None:
    async with client:
        contents = await client.read_resource("report://sample.log")
    assert json.loads(contents[0].text) == expected_report(root)


async def test_prompt_names_the_source_and_the_file(client) -> None:
    arguments = {"ip_or_user": "192.168.1.3", "path": "sample.log"}
    async with client:
        result = await client.get_prompt("investigate_source", arguments)
    text = result.messages[0].content.text
    assert "192.168.1.3" in text
    assert "sample.log" in text


def test_main_requires_a_root(monkeypatch) -> None:
    monkeypatch.delenv("LOG_ANALYZER_ROOT", raising=False)
    with pytest.raises(SystemExit, match="LOG_ANALYZER_ROOT"):
        server.main()
