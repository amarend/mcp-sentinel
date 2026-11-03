import ast
from pathlib import Path

from ..analysis.ast_utils import get_mcp_tools, parse_file
from ..findings.models import SecurityFinding


CAPABILITY_PATTERNS = {
    "filesystem": {
        "names": {"open"},
        "attributes": {"read_text", "write_text"},
    },
    "command_execution": {
        "names": {"eval", "exec"},
        "attributes": {"run", "Popen", "call", "check_output"},
    },
    "network": {
        "names": {"urlopen"},
        "attributes": {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "request",
        },
    },
}


def _get_tool_capabilities(
    tool_node: ast.AST,
) -> set[str]:

    capabilities: set[str] = set()

    for node in ast.walk(tool_node):

        if not isinstance(node, ast.Call):
            continue

        # Example:
        # open(...)
        # eval(...)
        # exec(...)
        if isinstance(node.func, ast.Name):

            for capability, patterns in CAPABILITY_PATTERNS.items():

                if node.func.id in patterns["names"]:
                    capabilities.add(capability)

        # Example:
        # requests.get(...)
        # subprocess.run(...)
        # pathlib.Path.read_text(...)
        if isinstance(node.func, ast.Attribute):

            for capability, patterns in CAPABILITY_PATTERNS.items():

                if node.func.attr in patterns["attributes"]:
                    capabilities.add(capability)

    return capabilities


def detect_excessive_tool_capability(
    files: list[Path],
) -> list[SecurityFinding]:

    findings: list[SecurityFinding] = []

    for file in files:

        tree = parse_file(file)

        if tree is None:
            continue

        for tool in get_mcp_tools(tree, file):

            capabilities = _get_tool_capabilities(
                tool.node
            )

            # Two or more high-risk capabilities in a
            # single MCP tool indicates excessive capability.
            if len(capabilities) < 2:
                continue

            capability_list = ", ".join(
                sorted(capabilities)
            )

            findings.append(
                SecurityFinding(
                    rule_id="MCP-014",
                    title="Excessive Tool Capability",
                    severity="HIGH",
                    file=str(file),
                    line=tool.line,
                    tool=tool.name,
                    description=(
                        f"MCP tool '{tool.name}' combines multiple "
                        f"high-risk capabilities: {capability_list}."
                    ),
                    recommendation=(
                        "Apply the principle of least privilege. "
                        "Split broad tools into narrowly scoped tools "
                        "and restrict each tool to only the capabilities "
                        "required for its intended purpose."
                    ),
                )
            )

    return findings