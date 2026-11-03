"""
Lightweight, intra-function taint tracking.

A name is "tainted" if it is a tool parameter, or if it is assigned from an
expression that references an already-tainted name. This is deliberately
simple (flow-insensitive, no inter-procedural analysis) but catches the very
common pattern::

    @mcp.tool()
    def fetch(url: str):
        target = f"https://{url}/api"      # tainted via f-string
        return requests.get(target)         # flagged

and the low-level SDK pattern::

    @server.call_tool()
    async def handle(name: str, arguments: dict):
        path = arguments["path"]            # tainted via subscript
        return open(path).read()            # flagged
"""

from __future__ import annotations

import ast


def expr_is_tainted(expr: ast.AST | None, tainted: set[str]) -> bool:
    """Return True if ``expr`` references any tainted name."""

    if expr is None:
        return False

    return any(
        isinstance(node, ast.Name) and node.id in tainted
        for node in ast.walk(expr)
    )


def _target_names(target: ast.AST) -> set[str]:
    """Collect every simple name bound by an assignment target."""

    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name)
    }


def compute_tainted_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parameters: set[str],
) -> set[str]:
    """
    Compute the names inside ``function`` that derive from ``parameters``.

    Propagates through assignments, annotated/augmented assignments, ``for``
    targets, ``with ... as`` targets and walrus expressions until a fixed
    point is reached.
    """

    tainted = set(parameters)

    changed = True

    while changed:

        changed = False

        for node in ast.walk(function):

            sources: list[tuple[ast.AST | None, set[str]]] = []

            if isinstance(node, ast.Assign):
                names: set[str] = set()
                for target in node.targets:
                    names |= _target_names(target)
                sources.append((node.value, names))

            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                sources.append(
                    (node.value, _target_names(node.target))
                )

            elif isinstance(node, (ast.For, ast.AsyncFor)):
                sources.append(
                    (node.iter, _target_names(node.target))
                )

            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        sources.append(
                            (
                                item.context_expr,
                                _target_names(item.optional_vars),
                            )
                        )

            elif isinstance(node, ast.NamedExpr):
                sources.append(
                    (node.value, _target_names(node.target))
                )

            for value, names in sources:

                if not names - tainted:
                    continue

                if expr_is_tainted(value, tainted):
                    tainted |= names
                    changed = True

    return tainted
