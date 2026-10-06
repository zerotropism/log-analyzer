"""Every declared console script must resolve: a typo would only fail at run time."""

from importlib.metadata import entry_points

EXPECTED = {"log-analyzer", "log-analyzer-gen", "log-analyzer-mcp"}


def test_console_scripts_resolve() -> None:
    scripts = [ep for ep in entry_points(group="console_scripts") if ep.name in EXPECTED]
    assert {ep.name for ep in scripts} == EXPECTED
    for ep in scripts:
        assert callable(ep.load())
