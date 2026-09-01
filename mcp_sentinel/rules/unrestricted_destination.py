import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_function_parameters,
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


NETWORK_CALLS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "request",
    "head",
}


NETWORK_MODULES = {
    "requests",
    "httpx",
    "urllib",
}


def detect_unrestricted_destination(
    files: list[Path],
) -> list[SecurityFinding]:

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            parameters = get_function_parameters(tool.node)

            if not parameters:
                continue

            for node in ast.walk(tool.node):

                if not isinstance(node, ast.Call):
                    continue

                if not isinstance(node.func, ast.Attribute):
                    continue

                if node.func.attr not in NETWORK_CALLS:
                    continue

                # Check whether this is requests/httpx/urllib
                if not isinstance(node.func.value, ast.Name):
                    continue

                if node.func.value.id not in NETWORK_MODULES:
                    continue

                if not node.args:
                    continue

                destination = node.args[0]

                if (
                    isinstance(destination, ast.Name)
                    and destination.id in parameters
                ):

                    findings.append(
                        SecurityFinding(
                            rule_id="MCP-012",
                            title="Unrestricted URL/Destination",
                            severity="HIGH",
                            file=str(file),
                            description=(
                                f"MCP tool '{tool.name}' uses the "
                                f"user-controlled parameter "
                                f"'{destination.id}' as a network "
                                f"destination without an apparent "
                                f"destination restriction."
                            ),
                            recommendation=(
                                "Restrict network destinations using "
                                "an explicit allowlist. Validate the "
                                "scheme, hostname, port, and destination "
                                "before making outbound requests."
                            ),
                        )
                    )

    return findings