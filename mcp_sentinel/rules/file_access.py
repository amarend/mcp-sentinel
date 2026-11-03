from pathlib import Path
import ast

from ..analysis.ast_utils import (
    get_mcp_tools,
    get_name_calls,
    parse_file,
)
from ..findings.models import SecurityFinding


def detect_unsafe_file_access(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            for call in get_name_calls(tool.node):

                if call.func.id != "open":
                    continue

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-003",
                        title="Unsafe File Access",
                        severity="HIGH",
                        file=str(file),
                        line=call.lineno,
                        tool=tool.name,
                        description=(
                            f"MCP tool '{tool.name}' directly "
                            "accesses the filesystem using open()."
                        ),
                        recommendation=(
                            "Restrict file access to an explicit "
                            "allowlist of directories or files. "
                            "Validate and normalize user-provided "
                            "paths before accessing the filesystem."
                        ),
                    )
                )

    return findings