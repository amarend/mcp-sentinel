from pathlib import Path

from .models import MCPDetectionResult


PYTHON_MCP_INDICATORS = [
    "FastMCP",
    "@mcp.tool",
    "mcp.run(",
    "from mcp",
    "import mcp",
]


def detect_python_mcp(files: list[Path]) -> MCPDetectionResult:

    for file in files:

        try:
            source = file.read_text(errors="ignore")

        except Exception:
            continue

        for indicator in PYTHON_MCP_INDICATORS:

            if indicator in source:

                return MCPDetectionResult(
                    detected=True,
                    language="Python",
                    framework="FastMCP",
                    confidence="High",
                )

    return MCPDetectionResult(detected=False)