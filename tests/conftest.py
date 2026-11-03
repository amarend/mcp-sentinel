import pytest
from pathlib import Path

from mcp_sentinel.repository import Repository


@pytest.fixture
def example_repository(tmp_path: Path):
    """Create a minimal repository containing a FastMCP server."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
from fastmcp import FastMCP

mcp = FastMCP("Example Server")


@mcp.tool()
def hello(name: str) -> str:
    return f"Hello {name}"
"""
    )

    return Repository(
        root=tmp_path,
        files=[server_file],
    )