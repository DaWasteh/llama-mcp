"""Regression tests for runtime dependency compatibility."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_REQUIREMENT = "mcp[cli]==1.29.0"
REQUIREMENTS_FILES = (
    PROJECT_ROOT / "requirements-dateisystem.txt",
    PROJECT_ROOT / "requirements-recherche.txt",
)
WINDOWS_LAUNCHERS = (
    PROJECT_ROOT / "server_dateisystem.bat",
    PROJECT_ROOT / "server_recherche.bat",
)


def _mcp_requirements(path: Path) -> list[str]:
    """Return active MCP requirement lines from a requirements file."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().lower().startswith("mcp[")
    ]


def test_mcp_sdk_is_exactly_pinned_for_both_servers() -> None:
    """Keep MCP 2.x from silently removing the FastMCP import contract."""
    for path in REQUIREMENTS_FILES:
        assert _mcp_requirements(path) == [MCP_REQUIREMENT], path.name


def test_windows_launcher_fallbacks_use_the_same_mcp_pin() -> None:
    """Prevent fallback installs from silently upgrading to incompatible MCP 2.x."""
    for path in WINDOWS_LAUNCHERS:
        content = path.read_text(encoding="utf-8")
        assert f'"{MCP_REQUIREMENT}"' in content, path.name


def test_pinned_mcp_exposes_fastmcp_import() -> None:
    """Verify the import path used by both server entry points remains available."""
    from mcp.server.fastmcp import FastMCP

    assert FastMCP.__name__ == "FastMCP"
