import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_attribute_calls,
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


SUBPROCESS_FUNCTIONS = {
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
}


def _has_shell_true(call: ast.Call) -> bool:
    """
    Determine whether a subprocess call contains shell=True.
    """

    for keyword in call.keywords:

        if keyword.arg != "shell":
            continue

        return (
            isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        )

    return False


def _is_dangerous_subprocess_call(
    call: ast.Call,
) -> bool:
    """
    Determine whether an AST call represents dangerous
    subprocess execution.
    """

    if not isinstance(call.func, ast.Attribute):
        return False

    if call.func.attr not in SUBPROCESS_FUNCTIONS:
        return False

    return _has_shell_true(call)


def detect_command_execution(
    files: list[Path],
) -> list[SecurityFinding]:
    """
    MCP-001: Detect dangerous command execution.

    Detects subprocess calls using shell=True.

    The finding is associated with an MCP tool when the
    dangerous call occurs inside an MCP tool.
    """

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        # Discover MCP tools in this file.
        mcp_tools = get_mcp_tools(tree, file)

        # --------------------------------------------------
        # Check MCP tools first
        # --------------------------------------------------

        detected_nodes: set[int] = set()

        for tool in mcp_tools:

            calls = get_attribute_calls(tool.node)

            for call in calls:

                if not _is_dangerous_subprocess_call(call):
                    continue

                detected_nodes.add(id(call))

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-001",
                        title="Dangerous Command Execution",
                        severity="CRITICAL",
                        file=str(file),
                        line=call.lineno,
                        tool=tool.name,
                        description=(
                            f"MCP tool '{tool.name}' executes "
                            "a subprocess with shell=True."
                        ),
                        recommendation=(
                            "Avoid shell execution. If command "
                            "execution is required, use a strict "
                            "allowlist and avoid shell=True."
                        ),
                    )
                )

        # --------------------------------------------------
        # Check the rest of the file
        # --------------------------------------------------

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            if id(node) in detected_nodes:
                continue

            if not _is_dangerous_subprocess_call(node):
                continue

            findings.append(
                SecurityFinding(
                    rule_id="MCP-001",
                    title="Dangerous Command Execution",
                    severity="CRITICAL",
                    file=str(file),
                    line=node.lineno,
                    tool=None,
                    description=(
                        "The application executes a subprocess "
                        "with shell=True."
                    ),
                    recommendation=(
                        "Avoid shell execution. If command "
                        "execution is required, use a strict "
                        "allowlist and avoid shell=True."
                    ),
                )
            )

    return findings