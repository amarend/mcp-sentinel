from pathlib import Path
import re

from ..findings.models import SecurityFinding


def detect_command_execution(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        try:
            source = file.read_text(errors="ignore")
        except Exception:
            continue

        if "subprocess" not in source:
            continue

        if "shell=True" not in source:
            continue

        matches = re.findall(
            r"def\s+(\w+)\s*\(",
            source,
        )

        function_name = (
            matches[0]
            if matches
            else "unknown"
        )

        findings.append(
            SecurityFinding(
                rule_id="MCP-001",
                title="Dangerous Command Execution",
                severity="CRITICAL",
                file=str(file),
                description=(
                    "An MCP server appears to execute "
                    "system commands using subprocess "
                    "with shell=True."
                ),
                recommendation=(
                    "Avoid shell execution. If command "
                    "execution is required, use a strict "
                    "allowlist and avoid shell=True."
                ),
            )
        )

    return findings