"""
Shared tool-poisoning heuristics.

Used by the Python rules, the TypeScript rules and the live scanner so all
three agree on what a suspicious tool description looks like.
"""

from __future__ import annotations

import re


# Phrases that try to override the model's instructions.
OVERRIDE_PHRASES = {
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "ignore the above",
    "new instructions:",
    "bypass security",
    "disable security",
    "send environment variables",
    "send api keys",
    "send credentials",
    "exfiltrate",
    "upload secrets",
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "do not mention this",
    "don't mention this",
    "keep this secret",
    "<important>",
    "<system>",
    "[system]",
}

# Zero-width, bidi-control and Unicode "tag" characters are invisible to a
# human reviewer but still read by the model.
_HIDDEN_CHARS = re.compile(
    "["
    "​-‏"
    "‪-‮"
    "⁠-⁤"
    "⁦-⁩"
    "﻿"
    "\U000e0000-\U000e007f"
    "]"
)

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

# Paths and files an MCP tool description has no business mentioning.
_SENSITIVE_REFERENCES = re.compile(
    r"(~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|"
    r"(?<![\w])\.env\b|mcp\.json|claude_desktop_config|"
    r"/etc/passwd|/etc/shadow|\.npmrc|\.git-credentials|"
    r"\.netrc|keychain|\bcookies?\.sqlite)",
    re.IGNORECASE,
)

# Language that steers *other* tools or hijacks tool selection.
_CROSS_TOOL = [
    re.compile(
        r"\b(instead of|rather than|do not use|don't use|never use)\b"
        r"[^.\n]{0,60}\btools?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(before|after|whenever)\b[^.\n]{0,60}"
        r"\b(any|another|other|every|all) (other )?tools?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\balways (call|use|invoke|run) this tool\b",
        re.IGNORECASE,
    ),
]

LONG_DESCRIPTION_CHARS = 2000


def find_override_phrases(text: str) -> list[str]:
    lowered = text.lower()
    return sorted(p for p in OVERRIDE_PHRASES if p in lowered)


def find_hidden_content(text: str) -> list[str]:
    labels = []

    if _HIDDEN_CHARS.search(text):
        labels.append("invisible/bidi Unicode characters")

    if _HTML_COMMENT.search(text):
        labels.append("HTML comment")

    if _BASE64_BLOB.search(text):
        labels.append("long base64-like blob")

    if len(text) > LONG_DESCRIPTION_CHARS:
        labels.append(f"unusually long text ({len(text)} chars)")

    return labels


def find_sensitive_references(text: str) -> list[str]:
    return sorted(
        {m.group(0).lower() for m in _SENSITIVE_REFERENCES.finditer(text)}
    )


def find_cross_tool_manipulation(text: str) -> list[str]:
    return [
        match.group(0).strip()
        for pattern in _CROSS_TOOL
        for match in [pattern.search(text)]
        if match
    ]
