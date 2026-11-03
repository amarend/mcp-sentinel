from dataclasses import dataclass, field
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

    # Names inside the tool that derive from tool parameters
    # (parameters plus anything assigned from them).
    tainted: set[str] = field(default_factory=set)

    # Description passed to the decorator, e.g.
    # @mcp.tool(description="...")
    decorator_description: str | None = None

    @property
    def descriptions(self) -> list[str]:
        """All description texts attached to this tool."""

        return [
            text
            for text in (self.description, self.decorator_description)
            if text
        ]
