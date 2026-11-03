"""
MCP tool discovery in JavaScript/TypeScript source.

Recognised registration styles:

    server.registerTool("name", { description, inputSchema }, async (args) => {})
    server.tool("name", "description", schema, async (args) => {})
    server.addTool({ name, description, parameters, execute: async (args) => {} })   // fastmcp
    server.setRequestHandler(CallToolRequestSchema, async (request) => {})          // low-level SDK
    class MyTool extends MCPTool { name = "x"; description = "..."; execute(input) {} }  // mcp-framework
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .lexer import (
    Source,
    find_closing,
    lex,
    read_string_literal,
    split_top_level,
)
from .taint import compute_tainted, expression_end, parameter_names


# A file is only analysed as an MCP server if it looks like one.
MCP_MARKERS = re.compile(
    r"@modelcontextprotocol/sdk|from\s+['\"]fastmcp['\"]|"
    r"require\(\s*['\"]fastmcp['\"]|mcp-framework|"
    r"\bMcpServer\b|\bFastMCP\b|CallToolRequestSchema"
)

_REGISTER = re.compile(r"\.\s*(registerTool|tool|addTool)\s*\(")
_SET_HANDLER = re.compile(
    r"\.\s*setRequestHandler\s*\(\s*CallToolRequestSchema\s*,"
)
_MCP_CLASS = re.compile(r"\bclass\s+[\w$]+\s+extends\s+MCPTool\b[^{]*\{")


@dataclass
class TSTool:
    name: str
    file: Path
    line: int
    kind: str
    description: str | None
    body_start: int
    body_end: int
    parameters: set[str] = field(default_factory=set)
    tainted: set[str] = field(default_factory=set)
    validated: set[str] = field(default_factory=set)

    def contains(self, offset: int) -> bool:
        return self.body_start <= offset < self.body_end


def is_mcp_source(text: str) -> bool:
    return bool(MCP_MARKERS.search(text))


# ----------------------------------------------------------------
# helpers
# ----------------------------------------------------------------

def _object_value(src: Source, start: int, end: int, key: str):
    """
    Return (value_start, value_end) of a top-level ``key: value`` entry in
    the object literal spanning ``src.code[start:end]`` (braces included).
    """

    if src.code[start:end].strip()[:1] != "{":
        return None

    open_index = src.code.index("{", start)
    close_index = find_closing(src.code, open_index)

    if close_index == -1:
        return None

    pattern = re.compile(
        rf"^\s*(?:['\"`]{re.escape(key)}['\"`]|{re.escape(key)})\s*:\s*"
    )

    for a, b in split_top_level(src.code, open_index + 1, close_index):

        match = pattern.match(src.clean[a:b])

        if match:
            return a + match.end(), b

    return None


def _resolve_identifier(src: Source, a: int, b: int):
    """
    If ``src.code[a:b]`` is a bare identifier, return the span of its
    ``const name = <initializer>`` in the same file (else None).
    """

    ident = src.code[a:b].strip()

    if not re.fullmatch(r"[A-Za-z_$][\w$]*", ident):
        return None

    match = re.search(
        rf"(?<![\w$.])(?:const|let|var)\s+{re.escape(ident)}\s*"
        r"(?::[^=;]+?)?=(?![=>])\s*",
        src.code,
    )

    if not match:
        return None

    end = expression_end(src.code, match.end(), len(src.code))

    return match.end(), end


def _string_value(src: Source, start: int, end: int, key: str):
    span = _object_value(src, start, end, key)

    if span is None:
        return None

    literal = read_string_literal(src.clean, span[0])

    return literal[0] if literal else None


def _function_after(src: Source, a: int, b: int):
    """
    Parse a function expression in ``src.code[a:b]``.
    Returns (params_names, body_start, body_end) or None.
    """

    code = src.code
    seg = code[a:b]

    # arrow function:  [async] (params) [: T] => body   |   x => body
    depth = 0
    arrow = -1

    for k, ch in enumerate(seg):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "=" and seg[k + 1:k + 2] == ">" and depth == 0:
            arrow = k
            break

    if arrow != -1:

        head = seg[:arrow]
        paren = head.find("(")

        if paren != -1:
            close = find_closing(code, a + paren)
            params = code[a + paren + 1:close]
        else:
            params = re.sub(r"^\s*async\s+", "", head)

        body_a = a + arrow + 2

        while body_a < b and code[body_a] in " \t\r\n":
            body_a += 1

        if body_a < b and code[body_a] == "{":
            body_close = find_closing(code, body_a)
            return (
                parameter_names(params),
                body_a + 1,
                body_close if body_close != -1 else b,
            )

        return parameter_names(params), body_a, b

    # function expression:  [async] function [name](params) { body }
    match = re.search(r"\bfunction\b[^(]*\(", seg)

    if match:
        open_paren = a + match.end() - 1
        return _method_at(src, open_paren, b)

    return None


def _method_at(src: Source, open_paren: int, limit: int):
    """Parse ``(params) [: T] { body }`` starting at an open paren."""

    code = src.code

    close = find_closing(code, open_paren)

    if close == -1:
        return None

    brace = code.find("{", close, limit)

    if brace == -1:
        return None

    body_close = find_closing(code, brace)

    return (
        parameter_names(code[open_paren + 1:close]),
        brace + 1,
        body_close if body_close != -1 else limit,
    )


def _make_tool(
    src: Source,
    file: Path,
    name: str | None,
    offset: int,
    kind: str,
    description: str | None,
    handler,
    fallback_name: str,
) -> TSTool | None:

    if handler is None:
        return None

    params, body_start, body_end = handler

    tainted, validated = compute_tainted(src, body_start, body_end, params)

    return TSTool(
        name=name or fallback_name,
        file=file,
        line=src.line_of(offset),
        kind=kind,
        description=description,
        body_start=body_start,
        body_end=body_end,
        parameters=params,
        tainted=tainted,
        validated=validated,
    )


# ----------------------------------------------------------------
# discovery
# ----------------------------------------------------------------

def discover_tools(src: Source, file: Path) -> list[TSTool]:

    tools: list[TSTool] = []

    code = src.code

    # --- server.registerTool / server.tool / server.addTool ---
    for match in _REGISTER.finditer(code):

        method = match.group(1)
        open_paren = match.end() - 1
        close = find_closing(code, open_paren)

        if close == -1:
            continue

        args = split_top_level(code, open_paren + 1, close)

        if not args:
            continue

        name = None
        description = None
        handler = None

        if method == "addTool":

            a, b = args[0]

            name = _string_value(src, a, b, "name")
            description = _string_value(src, a, b, "description")

            execute = _object_value(src, a, b, "execute")

            if execute:
                handler = _function_after(src, execute[0], execute[1])

            if handler is None:
                # execute(args) { ... } shorthand
                short = re.search(
                    r"(?<![\w$.])(?:async\s+)?execute\s*\(", src.code[a:b]
                )
                if short:
                    handler = _method_at(src, a + short.end() - 1, b)

        else:

            literal = read_string_literal(src.clean, args[0][0])

            if literal is None:
                # registerTool(name, ...) where `const name = "x"`.
                resolved = _resolve_identifier(src, *args[0])

                if resolved:
                    literal = read_string_literal(src.clean, resolved[0])

            # Skip things like `schema.tool(x)` that are not registrations.
            if literal is None:
                continue

            name = literal[0]

            if method == "registerTool" and len(args) > 1:
                config = _resolve_identifier(src, *args[1]) or args[1]

                description = _string_value(
                    src, config[0], config[1], "description"
                )

            elif method == "tool" and len(args) > 2:
                described = read_string_literal(src.clean, args[1][0])
                if described:
                    description = described[0]

            a, b = args[-1]
            handler = _function_after(src, a, b)

        tool = _make_tool(
            src, file, name, match.start(), "registered",
            description, handler, f"<{method}>",
        )

        if tool:
            tools.append(tool)

    # --- low-level setRequestHandler(CallToolRequestSchema, handler) ---
    for match in _SET_HANDLER.finditer(code):

        open_paren = code.rfind("(", match.start(), match.end())
        close = find_closing(code, open_paren)

        if close == -1:
            continue

        handler = _function_after(src, match.end(), close)

        tool = _make_tool(
            src, file, "call_tool handler", match.start(),
            "request-handler", None, handler, "call_tool handler",
        )

        if tool:
            tools.append(tool)

    # --- mcp-framework: class X extends MCPTool { ... } ---
    for match in _MCP_CLASS.finditer(code):

        open_brace = match.end() - 1
        close = find_closing(code, open_brace)

        if close == -1:
            continue

        body = src.clean[open_brace:close]

        name_match = re.search(
            r"(?<![\w$.])name\s*[:=]\s*['\"`]([^'\"`]+)['\"`]", body
        )
        desc_match = re.search(
            r"(?<![\w$.])description\s*[:=]\s*['\"`]([^'\"`]+)['\"`]", body
        )

        execute = re.search(
            r"(?<![\w$.])(?:async\s+)?execute\s*\(", code[open_brace:close]
        )

        handler = (
            _method_at(src, open_brace + execute.end() - 1, close)
            if execute
            else None
        )

        tool = _make_tool(
            src, file,
            name_match.group(1) if name_match else None,
            match.start(), "class",
            desc_match.group(1) if desc_match else None,
            handler, "MCPTool",
        )

        if tool:
            tools.append(tool)

    return tools
