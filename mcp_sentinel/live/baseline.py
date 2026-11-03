"""
Baselines for detecting "rug pulls": a server that behaves when first
approved and later changes a tool's description or schema.

``fingerprint()`` reduces a snapshot to stable hashes; ``compare()`` turns
the difference between two fingerprints into findings (MCP-106).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ..findings.models import SecurityFinding
from .client import ServerSnapshot


BASELINE_FORMAT = 1


def _hash(value) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _item_fingerprint(item: dict) -> dict:
    """Hash a definition and the parts a reviewer cares about."""

    parts = {
        "description": item.get("description"),
        "title": item.get("title"),
        "inputSchema": item.get("inputSchema", item.get("arguments")),
        "outputSchema": item.get("outputSchema"),
        "annotations": item.get("annotations"),
    }

    return {
        "hash": _hash(item),
        "parts": {key: _hash(value) for key, value in parts.items()},
    }


def fingerprint(snapshot: ServerSnapshot) -> dict:

    return {
        "format": BASELINE_FORMAT,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": snapshot.target,
        "server": snapshot.server_info,
        "instructions": _hash(snapshot.instructions),
        "tools": {
            tool.get("name", "?"): _item_fingerprint(tool)
            for tool in snapshot.tools
        },
        "prompts": {
            prompt.get("name", "?"): _item_fingerprint(prompt)
            for prompt in snapshot.prompts
        },
        "resources": {
            resource.get("uri") or resource.get("name", "?"):
                _item_fingerprint(resource)
            for resource in snapshot.resources
        },
    }


def save_baseline(path: Path, snapshot: ServerSnapshot) -> dict:

    data = fingerprint(snapshot)
    path.write_text(json.dumps(data, indent=2, sort_keys=True))

    return data


def load_baseline(path: Path) -> dict:

    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot read baseline {path}: {error}") from error

    if data.get("format") != BASELINE_FORMAT:
        raise ValueError(
            f"Unsupported baseline format in {path} "
            f"(expected {BASELINE_FORMAT})."
        )

    return data


def _finding(label, severity, title, description, subject):

    return SecurityFinding(
        rule_id="MCP-106",
        title=title,
        severity=severity,
        file=label,
        line=None,
        tool=subject,
        description=description,
        recommendation=(
            "Re-review this definition before trusting the server. "
            "If the change is expected, regenerate the baseline with "
            "--save-baseline."
        ),
    )


def compare(
    old: dict,
    new: dict,
    label: str,
) -> list[SecurityFinding]:
    """Findings describing how ``new`` differs from the baseline ``old``."""

    findings: list[SecurityFinding] = []

    for kind in ("tools", "prompts", "resources"):

        before = old.get(kind, {})
        after = new.get(kind, {})

        singular = kind[:-1]

        for name, current in after.items():

            if name not in before:
                findings.append(
                    _finding(
                        label, "MEDIUM", f"New {singular}",
                        f"{singular.capitalize()} '{name}' was not in "
                        "the baseline.",
                        name,
                    )
                )
                continue

            if current["hash"] == before[name]["hash"]:
                continue

            changed = [
                part
                for part, digest in current["parts"].items()
                if digest != before[name]["parts"].get(part)
            ]

            findings.append(
                _finding(
                    label, "CRITICAL",
                    f"{singular.capitalize()} definition changed",
                    f"{singular.capitalize()} '{name}' changed since the "
                    f"baseline ({', '.join(changed) or 'metadata'}). A "
                    "server that alters a tool after approval can "
                    "introduce malicious behaviour (a 'rug pull').",
                    name,
                )
            )

        for name in before:

            if name not in after:
                findings.append(
                    _finding(
                        label, "LOW", f"{singular.capitalize()} removed",
                        f"{singular.capitalize()} '{name}' is no longer "
                        "advertised.",
                        name,
                    )
                )

    if old.get("instructions") != new.get("instructions"):
        findings.append(
            _finding(
                label, "HIGH", "Server instructions changed",
                "The server's initialize instructions differ from the "
                "baseline.",
                "server instructions",
            )
        )

    return findings
