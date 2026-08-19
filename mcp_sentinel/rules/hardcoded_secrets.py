from pathlib import Path
import re

from ..findings.models import SecurityFinding


SECRET_PATTERNS = [
    r"^api[_-]?key$",
    r"^secret[_-]?key$",
    r"^access[_-]?key$",
    r"^auth[_-]?token$",
    r"^password$",
    r"^passwd$",
    r"^token$",
    r"^aws[_-]?access[_-]?key[_-]?id$",
    r"^aws[_-]?secret[_-]?access[_-]?key$",
]


def detect_hardcoded_secrets(
    files: list[Path],
) -> list[SecurityFinding]:

    findings = []

    for file in files:

        try:
            source = file.read_text(errors="ignore")
        except Exception:
            continue

        for line_number, line in enumerate(
            source.splitlines(),
            start=1,
        ):

            match = re.search(
                r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']([^\"']+)[\"']",
                line,
            )

            if not match:
                continue

            variable_name = match.group(1)
            secret_value = match.group(2)

            # Ignore empty values
            if not secret_value.strip():
                continue

            # Only flag exact credential-like variable names.
            # This prevents false positives such as:
            # API_KEY_NAME = "my-api-key"
            is_secret_variable = any(
                re.match(
                    pattern,
                    variable_name,
                    re.IGNORECASE,
                )
                for pattern in SECRET_PATTERNS
            )

            if not is_secret_variable:
                continue

            findings.append(
                SecurityFinding(
                    rule_id="MCP-002",
                    title="Hardcoded Secret",
                    severity="HIGH",
                    file=str(file),
                    description=(
                        f"Potential hardcoded secret found in "
                        f"variable '{variable_name}' "
                        f"at line {line_number}."
                    ),
                    recommendation=(
                        "Remove the secret from source code and "
                        "load it from a secure secret manager or "
                        "environment variable."
                    ),
                )
            )

    return findings