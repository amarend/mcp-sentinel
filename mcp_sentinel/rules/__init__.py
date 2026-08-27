from .command_execution import detect_command_execution
from .hardcoded_secrets import detect_hardcoded_secrets
from .file_access import detect_unsafe_file_access
from .network_access import detect_unrestricted_network_access
from .ssrf import detect_ssrf
from .dangerous_capability import detect_dangerous_capabilities
from .tool_poisoning import detect_tool_poisoning
from .prompt_intection import detect_prompt_injection
from .deserialization import detect_unsafe_deserialization

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
]


def run_security_rules(files):
    findings = []

    for rule in RULES:
        findings.extend(rule(files))

    return findings