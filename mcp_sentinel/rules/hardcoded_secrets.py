from pathlib import Path
import re

from ..analysis.ast_utils import get_mcp_tools, parse_file
from ..findings.models import SecurityFinding


SECRET_PATTERNS = [
    r"^api[_-]?key$",
    r"^secret[_-]?key$",
    r"^access[_-]?key$",
    r"^auth[_-]?token$",
    r"^password$",
    r"^passwd$",
    r"^token$",
    r"^aws[_-]?access[_-]?key[_-]?id$",
    r"^aws[_-]?secret[_-]?access[_-]?key$",
]


def _find_tool_for_line(
    tools,
    line_number: int,
):
    """
    Return the MCP tool containing the given line, if any.
    """

    for tool in tools:

        if not hasattr(tool.node, "end_lineno"):
            continue

        if (
            tool.node.lineno
            <= line_number
            <= tool.node.end_lineno
        ):
            return tool

    return None


def detect_hardcoded_secrets(
    files: list[Path],
) -> list[SecurityFinding]:
    """
    MCP-002: Detect potential hardcoded secrets.

    Secrets can exist at module level or inside an MCP tool.
    """

    findings: list[SecurityFinding] = []

    for file in files:

        try:
            source = file.read_text(errors="ignore")
        except OSError:
            continue

        # Parse the file so we can determine whether a secret
        # exists inside an MCP tool.
        tree = parse_file(file)

        tools = []

        if tree is not None:
            tools = get_mcp_tools(tree, file)

        for line_number, line in enumerate(
            source.splitlines(),
            start=1,
        ):

            match = re.search(
                r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']([^\"']+)[\"']",
                line,
            )

            if not match:
                continue

            variable_name = match.group(1)
            secret_value = match.group(2)

            # Ignore empty values
            if not secret_value.strip():
                continue

            # Only flag exact credential-like variable names.
            is_secret_variable = any(
                re.match(
                    pattern,
                    variable_name,
                    re.IGNORECASE,
                )
                for pattern in SECRET_PATTERNS
            )

            if not is_secret_variable:
                continue

            # Determine whether the secret belongs to an MCP tool.
            tool = _find_tool_for_line(
                tools,
                line_number,
            )

            findings.append(
                SecurityFinding(
                    rule_id="MCP-002",
                    title="Hardcoded Secret",
                    severity="HIGH",
                    file=str(file),
                    line=line_number,
                    tool=tool.name if tool else None,
                    description=(
                        f"Potential hardcoded secret found in "
                        f"variable '{variable_name}'."
                    ),
                    recommendation=(
                        "Remove the secret from source code and "
                        "load it from a secure secret manager or "
                        "environment variable."
                    ),
                )
            )

    return findings