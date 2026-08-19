from pathlib import Path
import ast

from ..findings.models import SecurityFinding


def detect_unsafe_file_access(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        try:
            source = file.read_text(errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):

            if not isinstance(node, ast.FunctionDef):
                continue

            # Check whether this function is an MCP tool
            is_mcp_tool = any(
                (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "tool"
                )
                or (
                    isinstance(decorator, ast.Attribute)
                    and decorator.attr == "tool"
                )
                for decorator in node.decorator_list
            )

            if not is_mcp_tool:
                continue

            # Look for open(...)
            for child in ast.walk(node):

                if not isinstance(child, ast.Call):
                    continue

                if not isinstance(child.func, ast.Name):
                    continue

                if child.func.id != "open":
                    continue

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-003",
                        title="Unsafe File Access",
                        severity="HIGH",
                        file=str(file),
                        description=(
                            f"MCP tool '{node.name}' directly accesses "
                            "the filesystem using open()."
                        ),
                        recommendation=(
                            "Restrict file access to an explicit "
                            "allowlist of directories or files. "
                            "Validate and normalize user-provided paths "
                            "before accessing the filesystem."
                        ),
                    )
                )

    return findings