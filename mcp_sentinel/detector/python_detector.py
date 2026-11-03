import ast
from pathlib import Path

from ..analysis.ast_utils import get_mcp_tools, parse_file
from .models import MCPDetectionResult


# Root module names that identify an MCP SDK / framework import.
FASTMCP_MODULES = {"fastmcp"}
OFFICIAL_SDK_MODULE = "mcp"


def _imports(tree: ast.AST) -> set[str]:
    """Return every dotted module name imported by the file."""

    modules: set[str] = set()

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)

        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)

    return modules


def _classify_imports(modules: set[str]) -> str | None:
    """
    Map imported modules to a framework name, or None if the file
    imports no MCP SDK. Matches whole module components, so
    ``mcp_utils`` or ``mcpx`` do not count as MCP.
    """

    framework = None

    for module in modules:

        parts = module.split(".")
        root = parts[0]

        if root in FASTMCP_MODULES:
            return "FastMCP"

        if root == OFFICIAL_SDK_MODULE:

            if "fastmcp" in parts:
                return "FastMCP"

            # e.g. mcp.server, mcp.types, mcp.client
            framework = framework or "MCP Python SDK"

    return framework


def detect_python_mcp(files: list[Path]) -> MCPDetectionResult:

    best: MCPDetectionResult | None = None

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        framework = _classify_imports(_imports(tree))

        if framework is None:
            continue

        tools = get_mcp_tools(tree, file)

        # Imports + registered tools is a strong signal;
        # imports alone is a weaker one.
        confidence = "High" if tools else "Medium"

        result = MCPDetectionResult(
            detected=True,
            language="Python",
            framework=framework,
            confidence=confidence,
            tools=[tool.name for tool in tools],
        )

        if confidence == "High":
            # Aggregate tool names across the whole repository.
            if best is not None and best.confidence == "High":
                best.tools.extend(result.tools)
                continue

            best = result
            continue

        if best is None:
            best = result

    return best or MCPDetectionResult(detected=False)
