from pathlib import Path

from ..analysis.ast_utils import (
    get_mcp_tools,
    parse_file,
)
from ..analysis.poisoning import OVERRIDE_PHRASES, find_override_phrases
from ..findings.models import SecurityFinding


# Kept for backwards compatibility; the shared list lives in
# analysis/poisoning.py and is a superset of the original patterns.
SUSPICIOUS_PATTERNS = OVERRIDE_PHRASES


def detect_tool_poisoning(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            # Check both the docstring and any description passed
            # to the decorator, e.g. @mcp.tool(description="...").
            if not tool.descriptions:
                continue

            description = " ".join(tool.descriptions).lower()

            # Find suspicious instructions in the tool description
            matched_patterns = find_override_phrases(description)

            # Nothing suspicious found
            if not matched_patterns:
                continue

            # Convert matched patterns into readable text
            matched_text = ", ".join(matched_patterns)

            findings.append(
                SecurityFinding(
                    rule_id="MCP-007",
                    title="Potential Tool Poisoning",
                    severity="HIGH",
                    file=str(file),
                    line=tool.line,
                    tool=tool.name,
                    description=(
                        f"MCP tool '{tool.name}' contains "
                        f"suspicious instructions: {matched_text}."
                    ),
                    recommendation=(
                        "Review the tool description for malicious "
                        "or unnecessary instructions. Tool metadata "
                        "should describe functionality and should not "
                        "instruct the model to bypass security controls "
                        "or disclose sensitive information."
                    ),
                )
            )

    return findings