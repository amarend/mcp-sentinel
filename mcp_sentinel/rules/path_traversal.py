import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_mcp_tools,
    parse_file,
)
from ..analysis.taint import expr_is_tainted
from ..findings.models import SecurityFinding


FILE_OPERATIONS = {
    "open",
}

PATH_JOIN_FUNCTIONS = {
    "join",
    "abspath",
    "realpath",
}


def _finding(file, tool, node, description, recommendation):

    return SecurityFinding(
        rule_id="MCP-011",
        title="Potential Path Traversal",
        severity="HIGH",
        file=str(file),
        line=node.lineno,
        tool=tool.name,
        description=description,
        recommendation=recommendation,
    )


def detect_path_traversal(
    files: list[Path],
) -> list[SecurityFinding]:
    """
    Detect potential path traversal vulnerabilities
    in MCP tools.

    MCP-011 focuses on filesystem operations where
    an MCP tool parameter (or a value derived from one)
    is used as a path.
    """

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            if not tool.parameters:
                continue

            for node in ast.walk(tool.node):

                if not isinstance(node, ast.Call):
                    continue

                # open(user_controlled_path)
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in FILE_OPERATIONS
                ):
                    for argument in node.args[:1]:

                        if (
                            isinstance(argument, ast.Name)
                            and argument.id in tool.tainted
                        ):
                            findings.append(
                                _finding(
                                    file,
                                    tool,
                                    node,
                                    (
                                        f"MCP tool '{tool.name}' uses "
                                        f"the user-controlled value "
                                        f"'{argument.id}' directly in "
                                        f"file access at line "
                                        f"{node.lineno}."
                                    ),
                                    (
                                        "Validate and normalize file "
                                        "paths before accessing the "
                                        "filesystem. Restrict access "
                                        "to an approved directory and "
                                        "prevent '../' traversal."
                                    ),
                                )
                            )

                # os.path.join / abspath / realpath (user_input)
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in PATH_JOIN_FUNCTIONS
                    and isinstance(node.func.value, ast.Attribute)
                ):
                    for argument in node.args:

                        if expr_is_tainted(argument, tool.tainted):
                            findings.append(
                                _finding(
                                    file,
                                    tool,
                                    node,
                                    (
                                        f"MCP tool '{tool.name}' uses "
                                        f"user-controlled input in path "
                                        f"construction at line "
                                        f"{node.lineno}."
                                    ),
                                    (
                                        "Validate and normalize user "
                                        "supplied paths and restrict "
                                        "filesystem access to an "
                                        "approved directory."
                                    ),
                                )
                            )
                            break

    return findings
