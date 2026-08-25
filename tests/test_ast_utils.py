from pathlib import Path

from mcp_sentinel.analysis.ast_utils import (
    get_function_parameters,
    get_mcp_tools,
    parse_file,
)


def test_parse_file(tmp_path: Path):
    """AST parser should parse valid Python."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
x = 10
"""
    )

    tree = parse_file(server_file)

    assert tree is not None


def test_parse_file_handles_invalid_python(tmp_path: Path):
    """AST parser should gracefully handle invalid Python."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
this is not valid python !!!
"""
    )

    tree = parse_file(server_file)

    assert tree is None


def test_get_mcp_tools(tmp_path: Path):
    """AST utilities should identify MCP tools."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Test")


@mcp.tool()
def hello(name: str):
    return f"Hello {name}"


def normal_function():
    return "normal"
"""
    )

    tree = parse_file(server_file)

    tools = get_mcp_tools(tree, server_file)

    assert len(tools) == 1

    tool = tools[0]

    assert tool.name == "hello"
    assert tool.parameters == {"name"}
    assert tool.file == server_file

def test_get_function_parameters(tmp_path: Path):
    """AST utilities should return function parameters."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
def example(url: str, timeout: int):
    pass
"""
    )

    tree = parse_file(server_file)

    function = tree.body[0]

    parameters = get_function_parameters(function)

    assert parameters == {"url", "timeout"}