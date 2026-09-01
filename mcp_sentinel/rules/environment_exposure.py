import ast
from pathlib import Path

from ..analysis.ast_utils import (
    get_mcp_tools,
    parse_file,
)
from ..findings.models import SecurityFinding


SENSITIVE_ENV_NAMES = {
    "API_KEY",
    "SECRET_KEY",
    "ACCESS_KEY",
    "AUTH_TOKEN",
    "AUTHORIZATION",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "PRIVATE_KEY",
}


def detect_sensitive_environment_exposure(
    files: list[Path],
) -> list[SecurityFinding]:

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            for node in ast.walk(tool.node):

                if not isinstance(node, ast.Call):
                    continue

                if not isinstance(node.func, ast.Attribute):
                    continue

                if not isinstance(node.func.value, ast.Name):
                    continue

                if node.func.value.id != "os":
                    continue

                if node.func.attr not in {
                    "getenv",
                    "environ",
                }:
                    continue

                # os.getenv("API_KEY")
                if node.func.attr == "getenv":

                    if not node.args:
                        continue

                    argument = node.args[0]

                    if not isinstance(argument, ast.Constant):
                        continue

                    env_name = argument.value

                # os.environ(...)
                else:
                    continue

                if not isinstance(env_name, str):
                    continue

                if env_name.upper() not in SENSITIVE_ENV_NAMES:
                    continue

                findings.append(
                    SecurityFinding(
                        rule_id="MCP-013",
                        title="Sensitive Environment Exposure",
                        severity="CRITICAL",
                        file=str(file),
                        description=(
                            f"MCP tool '{tool.name}' accesses the "
                            f"sensitive environment variable "
                            f"'{env_name}'. The value may be exposed "
                            f"through the tool response."
                        ),
                        recommendation=(
                            "Do not expose secrets or sensitive "
                            "environment variables through MCP tool "
                            "responses. Keep credentials server-side "
                            "and return only the minimum required data."
                        ),
                    )
                )

    return findings