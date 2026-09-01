import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_function_parameters,
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


FILE_OPERATIONS = {
    "open",
}

PATH_MODULES = {
    "os.path",
    "pathlib",
}


def detect_path_traversal(
    files: list[Path],
) -> list[SecurityFinding]:
    """
    Detect potential path traversal vulnerabilities
    in MCP tools.

    MCP-011 focuses on filesystem operations where
    an MCP tool parameter is directly used as a path.
    """

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

                # open(user_controlled_path)
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in FILE_OPERATIONS
                ):
                    for argument in node.args:

                        if (
                            isinstance(argument, ast.Name)
                            and argument.id in parameters
                        ):
                            findings.append(
                                SecurityFinding(
                                    rule_id="MCP-011",
                                    title="Potential Path Traversal",
                                    severity="HIGH",
                                    file=str(file),
                                    description=(
                                        f"MCP tool '{tool.name}' uses "
                                        f"the user-controlled parameter "
                                        f"'{argument.id}' directly in "
                                        f"file access at line "
                                        f"{node.lineno}."
                                    ),
                                    recommendation=(
                                        "Validate and normalize file "
                                        "paths before accessing the "
                                        "filesystem. Restrict access "
                                        "to an approved directory and "
                                        "prevent '../' traversal."
                                    ),
                                )
                            )

                # os.path.*(user_input)
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {
                        "join",
                        "abspath",
                        "realpath",
                    }
                    and isinstance(node.func.value, ast.Attribute)
                ):
                    for argument in node.args:

                        if (
                            isinstance(argument, ast.Name)
                            and argument.id in parameters
                        ):
                            findings.append(
                                SecurityFinding(
                                    rule_id="MCP-011",
                                    title="Potential Path Traversal",
                                    severity="HIGH",
                                    file=str(file),
                                    description=(
                                        f"MCP tool '{tool.name}' uses "
                                        f"user-controlled parameter "
                                        f"'{argument.id}' in path "
                                        f"construction at line "
                                        f"{node.lineno}."
                                    ),
                                    recommendation=(
                                        "Validate and normalize user "
                                        "supplied paths and restrict "
                                        "filesystem access to an "
                                        "approved directory."
                                    ),
                                )
                            )

    return findings