from pathlib import Path

from ..analysis.ast_utils import (
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


DANGEROUS_TOOL_NAMES = {
    "create_user",
    "delete_user",
    "modify_user",
    "change_permissions",
    "set_permissions",
    "change_password",
    "restart_service",
    "stop_service",
    "start_service",
    "shutdown",
    "reboot",
    "mount_disk",
    "unmount_disk",
}


def detect_dangerous_capabilities(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            if tool.name.lower() not in DANGEROUS_TOOL_NAMES:
                continue

            findings.append(
                SecurityFinding(
                    rule_id="MCP-006",
                    title="Dangerous Tool Capability",
                    severity="HIGH",
                    file=str(file),
                    line=tool.line,
                    tool=tool.name,
                    description=(
                        f"MCP tool '{tool.name}' exposes a "
                        "potentially privileged system capability."
                    ),
                    recommendation=(
                        "Apply least privilege to MCP tools. "
                        "Restrict privileged operations to explicitly "
                        "approved use cases and validate all inputs."
                    ),
                )
            )

    return findings