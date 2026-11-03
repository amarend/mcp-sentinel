from dataclasses import dataclass


# Higher number = more severe.
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def severity_rank(severity: str) -> int:
    """Numeric rank of a severity string (unknown values rank 0)."""

    return SEVERITY_ORDER.get(severity.upper(), 0)


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
