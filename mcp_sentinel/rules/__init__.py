from .command_execution import detect_command_execution
from .hardcoded_secrets import detect_hardcoded_secrets
from .file_access import detect_unsafe_file_access


RULES = [
    detect_command_execution,
    detect_hardcoded_secrets,
    detect_unsafe_file_access,
]


def run_security_rules(files):
    findings = []

    for rule in RULES:
        findings.extend(rule(files))

    return findings