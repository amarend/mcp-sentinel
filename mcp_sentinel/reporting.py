"""
Machine-readable reports: JSON and SARIF 2.1.0.

SARIF output can be uploaded to GitHub code scanning
(``github/codeql-action/upload-sarif``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .findings.models import SecurityFinding, SEVERITY_ORDER, severity_rank
from .version import __version__


SARIF_SCHEMA = (
    "https://json.schemastore.org/sarif-2.1.0.json"
)

# SARIF only knows error / warning / note.
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# Approximate GitHub "security-severity" scores (0-10).
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
}


def severity_counts(
    findings: list[SecurityFinding],
) -> dict[str, int]:

    counts = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in findings:

        severity = finding.severity.upper()

        if severity in counts:
            counts[severity] += 1

    return counts


def should_fail(
    findings: list[SecurityFinding],
    fail_on: str | None,
) -> bool:
    """True if any finding is at or above the ``fail_on`` severity."""

    if not fail_on:
        return False

    threshold = severity_rank(fail_on)

    if threshold == 0:
        raise ValueError(
            f"Unknown severity '{fail_on}'. "
            f"Use one of: {', '.join(SEVERITY_ORDER)}."
        )

    return any(
        severity_rank(finding.severity) >= threshold
        for finding in findings
    )


def _relative(path: str, root: Path | None) -> str:
    """Return ``path`` relative to ``root`` using forward slashes."""

    # Live-scan targets (live://...) are not file paths.
    if "://" in path:
        return path

    if root is not None:
        try:
            path = os.path.relpath(path, root)
        except ValueError:
            pass

    return Path(path).as_posix()


def to_json(
    findings: list[SecurityFinding],
    root: Path | None = None,
    rules_run: int | None = None,
) -> str:

    document = {
        "tool": "mcp-sentinel",
        "version": __version__,
        "summary": {
            "total": len(findings),
            "rules_run": rules_run,
            "by_severity": severity_counts(findings),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.upper(),
                "file": _relative(f.file, root),
                "line": f.line,
                "tool": f.tool,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }

    return json.dumps(document, indent=2)


def to_sarif(
    findings: list[SecurityFinding],
    root: Path | None = None,
) -> str:

    rules: dict[str, dict] = {}

    for f in findings:

        severity = f.severity.upper()

        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "help": {"text": f.recommendation},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(severity, "warning"),
                },
                "properties": {
                    "security-severity": _SECURITY_SEVERITY.get(
                        severity, "5.0"
                    ),
                    "tags": ["security", "mcp"],
                },
            },
        )

    results = []

    for f in findings:

        location: dict = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _relative(f.file, root),
                },
            }
        }

        if f.line:
            location["physicalLocation"]["region"] = {
                "startLine": f.line,
            }

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(
                    f.severity.upper(), "warning"
                ),
                "message": {
                    "text": f"{f.description} {f.recommendation}"
                },
                "locations": [location],
            }
        )

    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Sentinel",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/amarend/mcp-sentinel"
                        ),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(document, indent=2)
