"""
Lightweight taint tracking for JavaScript/TypeScript tool handlers.

Mirrors ``analysis/taint.py`` for Python: a name is tainted if it is a
handler parameter or is assigned from an expression referencing a tainted
name. Expressions that pass through a validation/sanitising helper
(``validatePath(...)``, ``sanitize(...)``, ``normalize(...)`` ...) are
treated as clean, since flagging those would be noise.
"""

from __future__ import annotations

import re

from .lexer import Source, split_top_level


_IDENT = r"[A-Za-z_$][\w$]*"

SANITIZER_CALL = re.compile(
    r"(?<![\w$])[\w$.]*(valid|sanitiz|normaliz|escape|allowlist|"
    r"whitelist|issafe|assert|authoriz)[\w$]*\s*\(",
    re.IGNORECASE,
)

_DECL = re.compile(
    r"(?<![\w$.])(?:const|let|var)\s+"
    rf"(?P<target>{_IDENT}|\{{[^=;]*?\}}|\[[^=;]*?\])"
    r"\s*(?::[^=;]+?)?=(?![=>])\s*"
)

_ASSIGN = re.compile(
    rf"(?<![\w$.])(?P<target>{_IDENT})\s*(?:\+|\|\||\?\?)?=(?![=>])\s*"
)

_CONTINUATION_START = set(".+?:&|,)]}*/%<>=")
_CONTINUATION_END = set("+-*/%&|?:,(=<>[{!")


def identifiers(code: str) -> set[str]:
    """Identifiers that are not property accesses (``a`` in ``a.b``)."""

    return set(re.findall(rf"(?<![\w$.]){_IDENT}", code))


def names_from_pattern(pattern: str) -> set[str]:
    """
    Binding names introduced by a parameter / destructuring pattern.

        "args: Foo"               -> {"args"}
        "{ a, b: c = 1, ...r }"   -> {"a", "c", "r"}
        "[x, y]"                  -> {"x", "y"}
    """

    pattern = pattern.strip()

    if not pattern:
        return set()

    if pattern[0] in "{[":

        inner = pattern[1:pattern.rfind("}" if pattern[0] == "{" else "]")]

        names: set[str] = set()

        for start, end in split_top_level(inner, 0, len(inner)):

            part = inner[start:end].strip()

            if part.startswith("..."):
                part = part[3:]

            # strip default value
            depth = 0
            cut = len(part)

            for k, ch in enumerate(part):
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                elif ch == "=" and depth == 0:
                    cut = k
                    break

            part = part[:cut].strip()

            # "key: binding" -> binding
            depth = 0
            for k, ch in enumerate(part):
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                elif ch == ":" and depth == 0:
                    part = part[k + 1:].strip()
                    break

            names |= names_from_pattern(part)

        return names

    match = re.match(_IDENT, pattern)

    return {match.group(0)} if match else set()


def parameter_names(params_code: str) -> set[str]:
    """Names bound by a function's parameter list (without parens)."""

    names: set[str] = set()

    for start, end in split_top_level(params_code, 0, len(params_code)):

        part = params_code[start:end].strip()

        if part.startswith("..."):
            part = part[3:]

        names |= names_from_pattern(part)

    names.discard("this")

    return names


def expression_end(code: str, start: int, limit: int) -> int:
    """End offset of the expression beginning at ``start``."""

    depth = 0
    k = start

    while k < limit:

        ch = code[k]

        if ch in "([{":
            depth += 1

        elif ch in ")]}":
            if depth == 0:
                return k
            depth -= 1

        elif ch == ";" and depth == 0:
            return k

        elif ch == "\n" and depth == 0:

            before = code[start:k].rstrip()
            after = code[k:limit].lstrip()

            if (
                before
                and before[-1] not in _CONTINUATION_END
                and (not after or after[0] not in _CONTINUATION_START)
            ):
                return k

        k += 1

    return limit


def expr_is_tainted(expr_code: str, tainted: set[str]) -> bool:
    """True if the expression uses a tainted name outside a sanitiser."""

    if SANITIZER_CALL.search(expr_code):
        return False

    return bool(identifiers(expr_code) & tainted)


def compute_tainted(
    src: Source,
    start: int,
    end: int,
    parameters: set[str],
) -> tuple[set[str], set[str]]:
    """
    Names inside ``src.code[start:end]`` derived from ``parameters``.

    Returns ``(tainted, validated)``. ``validated`` holds names assigned
    from a sanitising call over tainted input (``const p = await
    validatePath(args.path)``): they are not tainted, but they are known
    to be user-derived and checked.
    """

    code = src.code

    tainted = set(parameters)

    assignments: list[tuple[set[str], str]] = []

    for regex in (_DECL, _ASSIGN):

        for match in regex.finditer(code, start, end):

            expr_start = match.end()
            expr_stop = expression_end(code, expr_start, end)

            assignments.append(
                (
                    names_from_pattern(match.group("target")),
                    code[expr_start:expr_stop],
                )
            )

    validated: set[str] = set()

    changed = True

    while changed:

        changed = False

        for names, expr in assignments:

            if names <= tainted:
                continue

            if expr_is_tainted(expr, tainted):
                tainted |= names
                changed = True

            elif (
                SANITIZER_CALL.search(expr)
                and (identifiers(expr) & (tainted | validated))
                and not names <= validated
            ):
                validated |= names
                changed = True

    return tainted, validated
