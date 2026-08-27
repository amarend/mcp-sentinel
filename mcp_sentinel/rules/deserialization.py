import ast
from pathlib import Path

from ..analysis.ast_utils import parse_file
from ..findings.models import SecurityFinding


UNSAFE_DESERIALIZATION_FUNCTIONS = {
    "pickle": {
        "load",
        "loads",
    },
    "yaml": {
        "load",
    },
}


def detect_unsafe_deserialization(
    files: list[Path],
) -> list[SecurityFinding]:
    """
    Detect potentially unsafe deserialization operations.

    MCP-009 detects:
        pickle.load(...)
        pickle.loads(...)
        yaml.load(...)

    yaml.safe_load(...) is intentionally not flagged.
    """

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Attribute):
                continue

            module = node.func.value
            function_name = node.func.attr

            if not isinstance(module, ast.Name):
                continue

            module_name = module.id

            allowed_functions = (
                UNSAFE_DESERIALIZATION_FUNCTIONS.get(
                    module_name
                )
            )

            if not allowed_functions:
                continue

            if function_name not in allowed_functions:
                continue

            findings.append(
                SecurityFinding(
                    rule_id="MCP-009",
                    title="Unsafe Deserialization",
                    severity="CRITICAL",
                    file=str(file),
                    description=(
                        f"Potentially unsafe deserialization "
                        f"using {module_name}.{function_name}() "
                        f"at line {node.lineno}."
                    ),
                    recommendation=(
                        "Avoid deserializing untrusted data. "
                        "Use safe serialization formats and "
                        "safe loaders such as yaml.safe_load() "
                        "where applicable."
                    ),
                )
            )

    return findings