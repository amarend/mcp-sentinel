import re
from pathlib import Path

from ..ts.rules import is_ts_file, load_source
from ..ts.tools import discover_tools, is_mcp_source
from .models import MCPDetectionResult


_FRAMEWORKS = [
    (re.compile(r"@modelcontextprotocol/sdk"), "MCP TypeScript SDK"),
    (re.compile(r"['\"]fastmcp['\"]"), "FastMCP (TypeScript)"),
    (re.compile(r"mcp-framework"), "mcp-framework"),
]


def detect_typescript_mcp(files: list[Path]) -> MCPDetectionResult:
    """Detect MCP servers written in TypeScript or JavaScript."""

    framework = None
    tools: list[str] = []
    has_ts = False
    found = False

    for file in files:

        if not is_ts_file(file):
            continue

        src = load_source(file)

        if src is None or not is_mcp_source(src.text):
            continue

        found = True
        has_ts = has_ts or file.suffix in {".ts", ".mts", ".cts"}

        if framework is None:
            for pattern, name in _FRAMEWORKS:
                if pattern.search(src.text):
                    framework = name
                    break

        tools.extend(t.name for t in discover_tools(src, file))

    if not found:
        return MCPDetectionResult(detected=False)

    return MCPDetectionResult(
        detected=True,
        language="TypeScript" if has_ts else "JavaScript",
        framework=framework or "Unknown",
        confidence="High" if tools else "Medium",
        tools=tools,
    )
