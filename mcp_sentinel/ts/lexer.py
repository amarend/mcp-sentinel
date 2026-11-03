"""
A small, dependency-free JavaScript/TypeScript lexer.

It does not build an AST. It produces two same-length views of the source
so that character offsets (and therefore line numbers) line up everywhere:

``clean``
    The source with comments blanked out. String contents are preserved so
    values such as tool names and descriptions can be read.

``code``
    ``clean`` with the *contents* of string literals (and the literal text
    of template strings) also blanked. Only structure remains: identifiers,
    punctuation, ``${...}`` interpolations. Brace matching, argument
    splitting and sink detection run on this view, so a "}" or "exec(" inside
    a string or comment can never confuse them.
"""

from __future__ import annotations

from dataclasses import dataclass


# A "/" after one of these starts a regex literal rather than a division.
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = ("return", "typeof", "case", "in", "of", "void", "delete")


@dataclass
class Source:
    text: str       # original
    clean: str      # comments blanked
    code: str       # comments + string contents blanked

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


def _blank(chunk: str) -> str:
    """Replace a chunk with spaces, keeping newlines."""

    return "".join("\n" if ch == "\n" else " " for ch in chunk)


def _previous_significant(code: list[str], index: int) -> str:
    """Last non-space character before ``index`` in the code view."""

    j = index - 1

    while j >= 0 and code[j] in " \t\r\n":
        j -= 1

    return code[j] if j >= 0 else ""


def _previous_word(code: list[str], index: int) -> str:
    j = index - 1

    while j >= 0 and code[j] in " \t\r\n":
        j -= 1

    end = j + 1

    while j >= 0 and (code[j].isalnum() or code[j] in "_$"):
        j -= 1

    return "".join(code[j + 1:end])


def lex(text: str) -> Source:
    """Produce the ``clean`` and ``code`` views of ``text``."""

    n = len(text)

    clean = list(text)
    code = list(text)

    # Stack of template-literal brace depths, for nested ${ ... }.
    template_stack: list[int] = []
    brace_depth = 0

    i = 0

    def blank_range(start: int, end: int, *, both: bool):
        for k in range(start, end):
            if text[k] != "\n":
                code[k] = " "
                if both:
                    clean[k] = " "

    def skip_template(start: int) -> int:
        """
        Consume template-literal text from ``start`` (just after the opening
        backtick or after a closing ``}`` of an interpolation).
        Returns the index to resume normal scanning at.
        """

        k = start

        while k < n:

            ch = text[k]

            if ch == "\\":
                blank_range(k, min(k + 2, n), both=False)
                k += 2
                continue

            if ch == "`":
                return k + 1

            if ch == "$" and k + 1 < n and text[k + 1] == "{":
                template_stack.append(brace_depth)
                return k + 2

            if ch != "\n":
                code[k] = " "

            k += 1

        return k

    while i < n:

        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # ---------------- comments ----------------
        if ch == "/" and nxt == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            blank_range(i, end, both=True)
            i = end
            continue

        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            blank_range(i, end, both=True)
            i = end
            continue

        # ---------------- strings ----------------
        if ch in "\"'":
            k = i + 1

            while k < n and text[k] != ch and text[k] != "\n":
                k += 2 if text[k] == "\\" else 1

            k = min(k, n)
            blank_range(i + 1, k, both=False)
            i = k + 1
            continue

        # ---------------- templates ----------------
        if ch == "`":
            i = skip_template(i + 1)
            continue

        # ---------------- braces (for ${ } nesting) ----------------
        if ch == "{":
            brace_depth += 1
            i += 1
            continue

        if ch == "}":

            if template_stack and template_stack[-1] == brace_depth:
                template_stack.pop()
                i = skip_template(i + 1)
                continue

            brace_depth = max(0, brace_depth - 1)
            i += 1
            continue

        # ---------------- regex literals ----------------
        if ch == "/":

            prev = _previous_significant(code, i)
            word = _previous_word(code, i)

            if prev == "" or prev in _REGEX_PRECEDERS or word in _REGEX_KEYWORDS:

                k = i + 1
                in_class = False

                while k < n and text[k] != "\n":

                    if text[k] == "\\":
                        k += 2
                        continue

                    if text[k] == "[":
                        in_class = True
                    elif text[k] == "]":
                        in_class = False
                    elif text[k] == "/" and not in_class:
                        break

                    k += 1

                if k < n and text[k] == "/":
                    blank_range(i + 1, k, both=False)
                    i = k + 1
                    continue

        i += 1

    return Source(
        text=text,
        clean="".join(clean),
        code="".join(code),
    )


# ---------------------------------------------------------------
# Structure helpers (operate on the ``code`` view)
# ---------------------------------------------------------------

_OPENERS = {"(": ")", "[": "]", "{": "}"}


def find_closing(code: str, open_index: int) -> int:
    """
    Index of the bracket matching ``code[open_index]``, or -1.
    ``code`` must be the blanked view.
    """

    opener = code[open_index]
    closer = _OPENERS[opener]

    depth = 0

    for k in range(open_index, len(code)):

        ch = code[k]

        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return k

    return -1


def split_top_level(code: str, start: int, end: int) -> list[tuple[int, int]]:
    """
    Split ``code[start:end]`` on commas that are not nested inside
    brackets. Returns (start, end) offset pairs.
    """

    parts = []
    depth = 0
    seg = start

    for k in range(start, end):

        ch = code[k]

        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append((seg, k))
            seg = k + 1

    if code[seg:end].strip():
        parts.append((seg, end))

    return parts


def read_string_literal(clean: str, index: int) -> tuple[str, int] | None:
    """
    If ``clean[index:]`` (after whitespace) starts with a plain string
    literal, return (value, end_index). Template literals with
    interpolation are not plain strings.
    """

    k = index

    while k < len(clean) and clean[k] in " \t\r\n":
        k += 1

    if k >= len(clean) or clean[k] not in "\"'`":
        return None

    quote = clean[k]
    k += 1
    value = []

    while k < len(clean):

        ch = clean[k]

        if ch == "\\" and k + 1 < len(clean):
            value.append(clean[k + 1])
            k += 2
            continue

        if ch == quote:
            return "".join(value), k + 1

        if quote == "`" and ch == "$" and clean[k + 1:k + 2] == "{":
            return None

        if ch == "\n" and quote != "`":
            return None

        value.append(ch)
        k += 1

    return None
