import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_function_parameters,
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


DANGEROUS_FUNCTIONS = {
    "open",
    "eval",
    "exec",
}

DANGEROUS_ATTRIBUTES = {
    "run",
    "Popen",
    "call",
    "check_output",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "request",
}


def detect_missing_input_validation(
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

                dangerous_call = False

                # open(path), eval(value), exec(value)
                if isinstance(node.func, ast.Name):

                    if node.func.id in DANGEROUS_FUNCTIONS:
                        dangerous_call = True

                # requests.get(url), subprocess.run(command), etc.
                elif isinstance(node.func, ast.Attribute):

                    if node.func.attr in DANGEROUS_ATTRIBUTES:
                        dangerous_call = True

                if not dangerous_call:
                    continue

                # Check whether an MCP tool parameter is passed
                # directly into the dangerous call.
                for argument in node.args:

                    if (
                        isinstance(argument, ast.Name)
                        and argument.id in parameters
                    ):

                        findings.append(
                            SecurityFinding(
                                rule_id="MCP-015",
                                title="Missing Input Validation",
                                severity="HIGH",
                                file=str(file),
                                description=(
                                    f"MCP tool '{tool.name}' passes "
                                    f"user-controlled parameter "
                                    f"'{argument.id}' directly into "
                                    f"a potentially dangerous operation "
                                    f"without apparent validation."
                                ),
                                recommendation=(
                                    "Validate and constrain all "
                                    "user-controlled input before "
                                    "using it in filesystem, network, "
                                    "command execution, or other "
                                    "security-sensitive operations."
                                ),
                            )
                        )

    return findings