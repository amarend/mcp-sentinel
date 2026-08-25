import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_function_parameters,
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


PROMPT_VARIABLE_NAMES = {
    "prompt",
    "system_prompt",
    "user_prompt",
    "instruction",
    "message",
}


def detect_prompt_injection(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            parameters = get_function_parameters(tool.node)

            if not parameters:
                continue

            for node in ast.walk(tool.node):

                if not isinstance(node, ast.Assign):
                    continue

                # Check whether this assignment creates
                # something that looks like a prompt.
                target_names = {
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name)
                }

                if not target_names.intersection(
                    PROMPT_VARIABLE_NAMES
                ):
                    continue

                # Look for an f-string.
                if not isinstance(
                    node.value,
                    ast.JoinedStr,
                ):
                    continue

                # Find MCP tool parameters referenced
                # inside the f-string.
                referenced_parameters = set()

                for value in node.value.values:

                    if not isinstance(
                        value,
                        ast.FormattedValue,
                    ):
                        continue

                    if isinstance(
                        value.value,
                        ast.Name,
                    ):
                        if value.value.id in parameters:
                            referenced_parameters.add(
                                value.value.id
                            )

                if not referenced_parameters:
                    continue

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-008",
                        title="Potential Prompt Injection",
                        severity="HIGH",
                        file=str(file),
                        description=(
                            f"MCP tool '{tool.name}' directly "
                            f"places user-controlled parameter(s) "
                            f"{', '.join(referenced_parameters)} "
                            "into a prompt."
                        ),
                        recommendation=(
                            "Treat MCP tool parameters as untrusted "
                            "input. Validate and constrain input "
                            "before incorporating it into prompts, "
                            "and avoid allowing user-controlled "
                            "content to override system instructions."
                        ),
                    )
                )

    return findings