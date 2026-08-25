from pathlib import Path
import ast

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


def detect_ssrf(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            parameters = tool.parameters

            for call in get_attribute_calls(tool.node):

                if call.func.attr not in NETWORK_FUNCTIONS:
                    continue

                if not isinstance(call.func.value, ast.Name):
                    continue

                if call.func.value.id not in NETWORK_MODULES:
                    continue

                user_controlled = False

                # Positional arguments
                for argument in call.args:

                    if (
                        isinstance(argument, ast.Name)
                        and argument.id in parameters
                    ):
                        user_controlled = True

                # Keyword arguments
                for keyword in call.keywords:

                    if (
                        isinstance(keyword.value, ast.Name)
                        and keyword.value.id in parameters
                    ):
                        user_controlled = True

                if not user_controlled:
                    continue

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-005",
                        title="Potential SSRF",
                        severity="HIGH",
                        file=str(file),
                        description=(
                            f"MCP tool '{tool.name}' passes "
                            "user-controlled input to an outbound "
                            "network request."
                        ),
                        recommendation=(
                            "Validate and restrict user-controlled "
                            "URLs and hosts. Block access to private, "
                            "loopback, link-local, and cloud metadata "
                            "addresses."
                        ),
                    )
                )

    return findings