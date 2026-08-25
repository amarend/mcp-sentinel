from pathlib import Path

from ..analysis.ast_utils import (
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


SUSPICIOUS_PATTERNS = {
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "bypass security",
    "disable security",
    "send environment variables",
    "send api keys",
    "send credentials",
    "exfiltrate",
    "upload secrets",
}


def detect_tool_poisoning(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            if not tool.description:
                continue

            description = tool.description.lower()

            # Find suspicious instructions in the tool description
            matched_patterns = [
                pattern
                for pattern in SUSPICIOUS_PATTERNS
                if pattern in description
            ]

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