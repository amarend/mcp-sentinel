from mcp_sentinel.repository import Repository

from .models import MCPDetectionResult
from .python_detector import detect_python_mcp


def detect_mcp(repository: Repository) -> MCPDetectionResult:

    result = detect_python_mcp(repository.python_files)

    if result.detected:
        return result

    return MCPDetectionResult(detected=False)