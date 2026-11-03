from pathlib import Path

from ..findings.models import severity_rank
from .command_execution import detect_command_execution
from .hardcoded_secrets import detect_hardcoded_secrets
from .file_access import detect_unsafe_file_access
from .network_access import detect_unrestricted_network_access
from .ssrf import detect_ssrf
from .dangerous_capability import detect_dangerous_capabilities
from .tool_poisoning import detect_tool_poisoning
from .prompt_injection import detect_prompt_injection
from .deserialization import detect_unsafe_deserialization
from .dynamic_execution import detect_dynamic_execution
from .path_traversal import detect_path_traversal
from .unrestricted_destination import (
    detect_unrestricted_destination,
)
from .environment_exposure import (
    detect_sensitive_environment_exposure,
)
from .excessive_capability import (
    detect_excessive_tool_capability,
)
from .input_validation import (
    detect_missing_input_validation,
)

RULES = [
    detect_command_execution,
    detect_hardcoded_secrets,
    detect_unsafe_file_access,
    detect_unrestricted_network_access,
    detect_ssrf,
    detect_dangerous_capabilities,
    detect_tool_poisoning,
    detect_prompt_injection,
    detect_unsafe_deserialization,
    detect_dynamic_execution,
    detect_path_traversal,
    detect_unrestricted_destination,
    detect_sensitive_environment_exposure,
    detect_excessive_tool_capability,
    detect_missing_input_validation,
]


# When two rules fire on the same file and line, the more specific rule
# (key) makes the weaker, overlapping rules (values) redundant.
SUPERSEDES = {
    "MCP-001": {"MCP-015"},
    "MCP-010": {"MCP-015"},
    "MCP-011": {"MCP-003", "MCP-015"},
    "MCP-005": {"MCP-012", "MCP-015"},
    "MCP-012": {"MCP-015"},
    "MCP-003": {"MCP-015"},
}


def dedupe_findings(findings):
    """
    Remove exact duplicates and findings made redundant by a more
    specific rule reporting the same root cause on the same line.
    """

    unique = []
    seen = set()

    for finding in findings:

        key = (
            finding.rule_id,
            finding.file,
            finding.line,
            finding.tool,
            finding.description,
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    # (file, line) -> rule ids reported there
    rules_at = {}

    for finding in unique:

        if finding.line is None:
            continue

        rules_at.setdefault(
            (finding.file, finding.line), set()
        ).add(finding.rule_id)

    result = []

    for finding in unique:

        if finding.line is not None:

            present = rules_at[(finding.file, finding.line)]

            if any(
                finding.rule_id in SUPERSEDES.get(other, ())
                for other in present
            ):
                continue

        result.append(finding)

    return result


def sort_findings(findings):
    """Order findings by severity (desc), then file, then line."""

    return sorted(
        findings,
        key=lambda f: (
            -severity_rank(f.severity),
            f.file,
            f.line or 0,
            f.rule_id,
        ),
    )


def run_security_rules(files):
    # Imported lazily: the TypeScript rules import from this package.
    from ..ts.rules import run_typescript_rules

    files = [Path(file) for file in files]

    python_files = [file for file in files if file.suffix == ".py"]

    findings = []

    for rule in RULES:
        findings.extend(rule(python_files))

    findings.extend(run_typescript_rules(files))

    return sort_findings(dedupe_findings(findings))