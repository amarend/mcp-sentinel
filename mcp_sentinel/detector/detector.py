from mcp_sentinel.repository import Repository

from .models import MCPDetectionResult
from .python_detector import detect_python_mcp
from .typescript_detector import detect_typescript_mcp


def detect_mcp(repository: Repository) -> MCPDetectionResult:
    """
    Detect MCP servers in a repository.

    If the repository contains both Python and TypeScript/JavaScript
    servers the results are merged.
    """

    python = detect_python_mcp(repository.python_files)

    typescript = detect_typescript_mcp(
        repository.typescript_files + repository.javascript_files
    )

    if python.detected and typescript.detected:

        return MCPDetectionResult(
            detected=True,
            language=f"{python.language}, {typescript.language}",
            framework=f"{python.framework}, {typescript.framework}",
            confidence=(
                "High"
                if "High" in (python.confidence, typescript.confidence)
                else "Medium"
            ),
            tools=python.tools + typescript.tools,
        )

    if python.detected:
        return python

    if typescript.detected:
        return typescript

    return MCPDetectionResult(detected=False)
