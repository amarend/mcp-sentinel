"""
Analysis of what a *running* MCP server advertises.

Catches problems that are invisible in source code: poisoned or hidden
metadata, name collisions, dangerous parameters, and transport weaknesses.

Rule IDs (MCP-1xx are live-only; MCP-006/007 are shared with static rules):

    MCP-006  Dangerous tool capability (by name)
    MCP-007  Tool poisoning / instruction manipulation in metadata
    MCP-101  Hidden or obfuscated content in metadata
    MCP-103  Sensitive file/secret reference in metadata
    MCP-104  Unconstrained dangerous parameter in a tool's input schema
    MCP-105  Tool name collision / lookalike / non-ASCII name
    MCP-106  Definition changed since baseline (rug pull)   [baseline.py]
    MCP-108  Transport weakness (plaintext HTTP, no authentication)
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

from ..analysis.poisoning import (
    find_cross_tool_manipulation,
    find_hidden_content,
    find_override_phrases,
    find_sensitive_references,
)
from ..findings.models import SecurityFinding
from ..rules.dangerous_capability import DANGEROUS_TOOL_NAMES
from .client import ServerSnapshot


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

# Parameter-name categories for MCP-104.
RISKY_PARAMETERS = {
    "command execution": {
        "command", "cmd", "shell", "script", "bash", "powershell",
    },
    "code execution": {
        "code", "expression", "eval", "javascript", "python",
    },
    "SQL": {"sql", "sql_query", "raw_query"},
    "filesystem path": {
        "path", "file", "filepath", "file_path", "filename",
        "directory", "dir", "folder", "dest", "destination",
    },
    "network destination": {
        "url", "uri", "endpoint", "webhook", "host", "hostname",
    },
}

_RISK_SEVERITY = {
    "command execution": "HIGH",
    "code execution": "HIGH",
    "SQL": "HIGH",
    "filesystem path": "MEDIUM",
    "network destination": "MEDIUM",
}

_CONSTRAINING_KEYS = {"enum", "const", "pattern"}


def _snake(name: str) -> str:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[-\s]+", "_", name).lower()


def _label(snapshot: ServerSnapshot) -> str:
    return f"live://{snapshot.transport}/{snapshot.target}"


def schema_texts(schema, path: str = "") -> list[tuple[str, str]]:
    """
    Every human/model-readable string in a JSON schema, with its
    location: descriptions, titles, defaults, enums, examples and
    property names.
    """

    found: list[tuple[str, str]] = []

    if isinstance(schema, dict):

        for key, value in schema.items():

            location = f"{path}.{key}" if path else key

            if key in {"description", "title"} and isinstance(value, str):
                found.append((location, value))

            elif key == "default" and isinstance(value, str):
                found.append((location, value))

            elif key in {"enum", "examples"} and isinstance(value, list):
                found.extend(
                    (location, item)
                    for item in value
                    if isinstance(item, str)
                )

            elif key == "properties" and isinstance(value, dict):

                for prop, sub in value.items():
                    found.append((f"{location}.{prop} (name)", prop))
                    found.extend(
                        schema_texts(sub, f"{location}.{prop}")
                    )

            else:
                found.extend(schema_texts(value, location))

    elif isinstance(schema, list):

        for index, item in enumerate(schema):
            found.extend(schema_texts(item, f"{path}[{index}]"))

    return found


def _item_texts(item: dict) -> list[tuple[str, str]]:
    """All scannable text in a tool / prompt / resource definition."""

    texts = []

    for key in ("title", "description"):
        if isinstance(item.get(key), str):
            texts.append((key, item[key]))

    for key in ("inputSchema", "outputSchema"):
        if key in item:
            texts.extend(
                (f"{key}.{where}", text)
                for where, text in schema_texts(item[key])
            )

    for argument in item.get("arguments", []) or []:     # prompts
        if isinstance(argument, dict) and isinstance(
            argument.get("description"), str
        ):
            texts.append(
                (f"arguments.{argument.get('name')}", argument["description"])
            )

    return texts


def _finding(
    snapshot, rule_id, title, severity, description, recommendation,
    tool=None,
) -> SecurityFinding:

    return SecurityFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        file=_label(snapshot),
        line=None,
        tool=tool,
        description=description,
        recommendation=recommendation,
    )


def _scan_metadata(snapshot, subject, texts) -> list[SecurityFinding]:
    """Poisoning / hidden / sensitive-reference checks on text blobs."""

    findings = []

    for where, text in texts:

        phrases = find_override_phrases(text)

        if phrases:
            findings.append(
                _finding(
                    snapshot, "MCP-007", "Potential Tool Poisoning",
                    "HIGH",
                    f"'{subject}' ({where}) contains suspicious "
                    f"instructions: {', '.join(phrases)}.",
                    "Review this metadata. Descriptions should explain "
                    "functionality, not instruct the model to hide "
                    "actions, bypass controls or disclose data.",
                    subject,
                )
            )

        manipulation = find_cross_tool_manipulation(text)

        if manipulation:
            findings.append(
                _finding(
                    snapshot, "MCP-007", "Cross-Tool Manipulation",
                    "MEDIUM",
                    f"'{subject}' ({where}) tries to steer tool "
                    f"selection: \"{manipulation[0]}\".",
                    "A tool description should not control how other "
                    "tools are chosen or used.",
                    subject,
                )
            )

        hidden = find_hidden_content(text)

        if hidden:
            only_length = all(h.startswith("unusually long") for h in hidden)

            findings.append(
                _finding(
                    snapshot, "MCP-101",
                    "Hidden or Obfuscated Content",
                    "MEDIUM" if only_length else "HIGH",
                    f"'{subject}' ({where}) contains: "
                    f"{', '.join(hidden)}.",
                    "Remove invisible characters, comments and encoded "
                    "blobs from tool metadata; what a reviewer sees "
                    "should be exactly what the model reads.",
                    subject,
                )
            )

        sensitive = find_sensitive_references(text)

        if sensitive:
            findings.append(
                _finding(
                    snapshot, "MCP-103",
                    "Sensitive Resource Referenced in Metadata", "HIGH",
                    f"'{subject}' ({where}) references sensitive "
                    f"locations: {', '.join(sensitive)}.",
                    "Tool metadata has no reason to mention credentials "
                    "or configuration files. This is a common "
                    "exfiltration instruction.",
                    subject,
                )
            )

    return findings


def _constrained(schema: dict) -> bool:
    return bool(_CONSTRAINING_KEYS & set(schema))


def _scan_parameters(snapshot, tool) -> list[SecurityFinding]:

    name = tool.get("name", "?")
    schema = tool.get("inputSchema") or {}
    properties = schema.get("properties") or {}

    grouped: dict[str, list[str]] = {}

    for prop, definition in properties.items():

        if not isinstance(definition, dict):
            continue

        if definition.get("type") not in (None, "string"):
            continue

        if _constrained(definition):
            continue

        normalized = _snake(prop)

        for category, names in RISKY_PARAMETERS.items():
            if normalized in names:
                grouped.setdefault(category, []).append(prop)

    findings = []

    for category, params in grouped.items():

        findings.append(
            _finding(
                snapshot, "MCP-104",
                "Unconstrained Dangerous Parameter",
                _RISK_SEVERITY[category],
                f"Tool '{name}' accepts free-form {category} input via "
                f"{', '.join(repr(p) for p in params)} with no enum or "
                "pattern in its schema.",
                "Constrain the parameter with an enum or pattern, and "
                "validate it server-side. Schema constraints are not a "
                "substitute for server-side checks.",
                name,
            )
        )

    return findings


def _scan_names(snapshot) -> list[SecurityFinding]:

    findings = []
    seen: dict[str, str] = {}

    for tool in snapshot.tools:

        name = tool.get("name")

        if not isinstance(name, str):
            continue

        if not name.isascii():
            findings.append(
                _finding(
                    snapshot, "MCP-105", "Non-ASCII Tool Name", "MEDIUM",
                    f"Tool name {name!r} contains non-ASCII characters "
                    "and can imitate another tool.",
                    "Use plain ASCII tool names.",
                    name,
                )
            )

        canonical = re.sub(
            r"[\s_\-]+", "",
            unicodedata.normalize("NFKC", name).casefold(),
        )

        if canonical in seen:

            exact = seen[canonical] == name

            findings.append(
                _finding(
                    snapshot, "MCP-105",
                    "Duplicate Tool Name" if exact
                    else "Lookalike Tool Name",
                    "HIGH",
                    f"Tool '{name}' "
                    + (
                        "is registered more than once."
                        if exact
                        else f"is easily confused with '{seen[canonical]}'."
                    ),
                    "Tool names must be unique and clearly distinct; "
                    "collisions let one tool shadow another.",
                    name,
                )
            )

        else:
            seen[canonical] = name

        if _snake(name) in DANGEROUS_TOOL_NAMES:
            findings.append(
                _finding(
                    snapshot, "MCP-006", "Dangerous Tool Capability",
                    "HIGH",
                    f"Tool '{name}' exposes a potentially privileged "
                    "system capability.",
                    "Apply least privilege and require explicit user "
                    "confirmation for privileged operations.",
                    name,
                )
            )

    return findings


def _scan_transport(snapshot) -> list[SecurityFinding]:

    if snapshot.transport != "http":
        return []

    parsed = urlparse(snapshot.target)
    host = (parsed.hostname or "").lower()
    local = host in LOOPBACK_HOSTS

    findings = []

    if parsed.scheme == "http" and not local:
        findings.append(
            _finding(
                snapshot, "MCP-108", "Plaintext Transport", "HIGH",
                f"The server at {snapshot.target} is reached over "
                "unencrypted HTTP. Tool calls and results (and any "
                "credentials) can be read or modified in transit.",
                "Serve MCP over HTTPS.",
            )
        )

    if not local and snapshot.tools and not snapshot.auth_supplied:
        findings.append(
            _finding(
                snapshot, "MCP-108", "No Authentication", "MEDIUM",
                f"The remote server answered initialize and tools/list "
                f"({len(snapshot.tools)} tools) without any "
                "credentials.",
                "Require authentication (e.g. OAuth bearer tokens) on "
                "remote MCP endpoints.",
            )
        )

    return findings


def analyze_snapshot(snapshot: ServerSnapshot) -> list[SecurityFinding]:
    """Run every live check over a server snapshot."""

    findings: list[SecurityFinding] = []

    if snapshot.instructions:
        findings.extend(
            _scan_metadata(
                snapshot, "server instructions",
                [("instructions", snapshot.instructions)],
            )
        )

    for tool in snapshot.tools:

        name = tool.get("name", "?")

        findings.extend(
            _scan_metadata(snapshot, name, _item_texts(tool))
        )
        findings.extend(_scan_parameters(snapshot, tool))

    for kind, items in (
        ("prompt", snapshot.prompts),
        ("resource", snapshot.resources),
    ):
        for item in items:
            subject = f"{kind}:{item.get('name') or item.get('uri')}"
            findings.extend(
                _scan_metadata(snapshot, subject, _item_texts(item))
            )

    findings.extend(_scan_names(snapshot))
    findings.extend(_scan_transport(snapshot))

    return findings
