import ast
from functools import lru_cache
from pathlib import Path

from .models import MCPTool
from .taint import compute_tainted_names


# Decorator attribute names that register an MCP tool.
#
#   @mcp.tool / @mcp.tool()            FastMCP / official SDK (FastMCP)
#   @server.call_tool()                official SDK low-level Server
MCP_TOOL_DECORATORS = {
    "tool",
    "call_tool",
}


@lru_cache(maxsize=4096)
def _parse_cached(
    path: str,
    mtime_ns: int,
    size: int,
) -> ast.AST | None:
    """Parse a file once per (path, mtime, size)."""

    try:
        source = Path(path).read_text(errors="ignore")
        return ast.parse(source)

    except (OSError, SyntaxError, ValueError, RecursionError):
        return None


def parse_file(file: Path) -> ast.AST | None:
    """
    Parse a Python file and return its AST.

    Results are cached, so the 15 security rules share a single parse
    of each file. Returns None if the file is not Python, cannot be read,
    or cannot be parsed.
    """

    file = Path(file)

    if file.suffix != ".py":
        return None

    try:
        stat = file.stat()
    except OSError:
        return None

    return _parse_cached(
        str(file),
        stat.st_mtime_ns,
        stat.st_size,
    )


def clear_parse_cache() -> None:
    """Drop all cached ASTs (useful in long-running processes)."""

    _parse_cached.cache_clear()


def _decorator_target(decorator: ast.expr) -> ast.expr:
    """Return the decorator expression without a trailing call."""

    if isinstance(decorator, ast.Call):
        return decorator.func

    return decorator


def _decorator_name(decorator: ast.expr) -> str | None:
    """Return the last attribute/name of a decorator, if any."""

    target = _decorator_target(decorator)

    if isinstance(target, ast.Attribute):
        return target.attr

    if isinstance(target, ast.Name):
        return target.id

    return None


def is_mcp_tool(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """
    Determine whether a function is registered as an MCP tool.

    Supports:

        @mcp.tool
        @mcp.tool()
        @mcp.tool(name="x", description="...")
        @server.call_tool()
        @tool                    (when imported directly from an MCP SDK)
    """

    for decorator in node.decorator_list:

        target = _decorator_target(decorator)

        # @something.tool / @something.call_tool
        if (
            isinstance(target, ast.Attribute)
            and target.attr in MCP_TOOL_DECORATORS
        ):
            return True

        # @tool (bare name)
        if isinstance(target, ast.Name) and target.id == "tool":
            return True

    return False


def _decorator_description(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Return description="..." passed to the tool decorator, if any."""

    for decorator in node.decorator_list:

        if not isinstance(decorator, ast.Call):
            continue

        if _decorator_name(decorator) not in MCP_TOOL_DECORATORS | {
            "tool"
        }:
            continue

        for keyword in decorator.keywords:

            if (
                keyword.arg == "description"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                return keyword.value.value

    return None


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

    # Methods: self/cls are not user-controlled.
    parameters.discard("self")
    parameters.discard("cls")

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
    - tainted names (parameters plus values derived from them)
    - description (docstring) and decorator description
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

        tools.append(
            MCPTool(
                name=node.name,
                parameters=parameters,
                description=ast.get_docstring(node),
                file=file,
                line=node.lineno,
                node=node,
                tainted=compute_tainted_names(node, parameters),
                decorator_description=_decorator_description(node),
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
