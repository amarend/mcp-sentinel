import ast
from pathlib import Path

from ..analysis.ast_utils import parse_file
from ..findings.models import SecurityFinding


DANGEROUS_FUNCTIONS = {
    "eval",
    "exec",
    "compile",
}


def detect_dynamic_execution(
    files: list[Path],
) -> list[SecurityFinding]:
    """
    Detect potentially dangerous dynamic code execution.

    MCP-010 detects:
        eval(...)
        exec(...)
        compile(...)
    """

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Name):
                continue

            function_name = node.func.id

            if function_name not in DANGEROUS_FUNCTIONS:
                continue

            findings.append(
                SecurityFinding(
                    rule_id="MCP-010",
                    title="Dynamic Code Execution",
                    severity="CRITICAL",
                    file=str(file),
                    description=(
                        f"Potentially dangerous dynamic code "
                        f"execution using {function_name}() "
                        f"at line {node.lineno}."
                    ),
                    recommendation=(
                        "Avoid eval(), exec(), and compile() "
                        "with untrusted or dynamically controlled "
                        "input. Use safer, explicit functionality "
                        "instead."
                    ),
                )
            )

    return findings