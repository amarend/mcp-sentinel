import ast
from pathlib import Path

from .models import MCPTool


def parse_file(file: Path) -> ast.AST | None:
    """
    Parse a Python file and return its AST.

    Returns None if the file cannot be read or parsed.
    """

    try:
        source = file.read_text(errors="ignore")
        return ast.parse(source)

    except (OSError, SyntaxError):
        return None


def is_mcp_tool(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """
    Determine whether a function is decorated as an MCP tool.

    Supports:

        @mcp.tool
        def example():
            ...

    and:

        @mcp.tool()
        def example():
            ...
    """

    for decorator in node.decorator_list:

        # @mcp.tool
        if (
            isinstance(decorator, ast.Attribute)
            and decorator.attr == "tool"
        ):
            return True

        # @mcp.tool()
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "tool"
        ):
            return True

    return False


def get_function_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """
    Return all parameter names of a function.
    """

    parameters = set()

    # Positional-only arguments
    parameters.update(
        arg.arg
        for arg in node.args.posonlyargs
    )

    # Normal positional arguments
    parameters.update(
        arg.arg
        for arg in node.args.args
    )

    # Keyword-only arguments
    parameters.update(
        arg.arg
        for arg in node.args.kwonlyargs
    )

    # *args
    if node.args.vararg:
        parameters.add(node.args.vararg.arg)

    # **kwargs
    if node.args.kwarg:
        parameters.add(node.args.kwarg.arg)

    return parameters


def get_mcp_tools(
    tree: ast.AST,
    file: Path,
) -> list[MCPTool]:
    """
    Discover MCP tools in a Python AST.

    Each MCPTool contains:

    - name
    - parameters
    - description
    - source file
    - AST node
    """

    tools: list[MCPTool] = []

    for node in ast.walk(tree):

        if not isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            continue

        if not is_mcp_tool(node):
            continue

        # Extract function parameters
        parameters = get_function_parameters(node)

        # Extract the MCP tool description/docstring
        description = ast.get_docstring(node)

        tools.append(
            MCPTool(
                name=node.name,
                parameters=parameters,
                description=description,
                file=file,
                line=node.lineno,
                node=node,
)
        )

    return tools


def get_attribute_calls(
    node: ast.AST,
) -> list[ast.Call]:
    """
    Return function calls using attribute syntax.

    Examples:

        requests.get(...)
        httpx.post(...)
        subprocess.run(...)
    """

    return [
        child
        for child in ast.walk(node)
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
        )
    ]


def get_name_calls(
    node: ast.AST,
) -> list[ast.Call]:
    """
    Return function calls using simple function names.

    Examples:

        open(...)
        eval(...)
        exec(...)
    """

    return [
        child
        for child in ast.walk(node)
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
        )
    ]