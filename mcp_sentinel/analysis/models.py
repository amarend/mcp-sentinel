from dataclasses import dataclass
import ast
from pathlib import Path


@dataclass
class MCPTool:
    """
    Represents an MCP tool discovered in a source file.
    """

    name: str
    parameters: set[str]
    description: str | None
    file: Path
    line: int
    node: ast.FunctionDef | ast.AsyncFunctionDef