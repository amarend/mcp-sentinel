from pathlib import Path

from ..analysis.ast_utils import (
    get_attribute_calls,
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


NETWORK_FUNCTIONS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "request",
}


NETWORK_MODULES = {
    "requests",
    "httpx",
}


def detect_unrestricted_network_access(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            for call in get_attribute_calls(tool.node):

                if call.func.attr not in NETWORK_FUNCTIONS:
                    continue

                if not hasattr(call.func.value, "id"):
                    continue

                module_name = call.func.value.id

                if module_name not in NETWORK_MODULES:
                    continue

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-004",
                        title="Unrestricted Network Access",
                        severity="MEDIUM",
                        file=str(file),
                        description=(
                            f"MCP tool '{tool.name}' performs "
                            "outbound network access."
                        ),
                        recommendation=(
                            "Restrict outbound network access to "
                            "approved destinations and protocols. "
                            "Validate external destinations before "
                            "making network requests."
                        ),
                    )
                )

    return findings