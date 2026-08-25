from dataclasses import dataclass


@dataclass
class SecurityFinding:
    """
    Represents a security issue discovered by MCP Sentinel.
    """

    rule_id: str
    title: str
    severity: str
    file: str
    description: str
    recommendation: str
    line: int | None = None
    tool: str | None = None