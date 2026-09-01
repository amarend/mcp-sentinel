from .command_execution import detect_command_execution
from .hardcoded_secrets import detect_hardcoded_secrets
from .file_access import detect_unsafe_file_access
from .network_access import detect_unrestricted_network_access
from .ssrf import detect_ssrf
from .dangerous_capability import detect_dangerous_capabilities
from .tool_poisoning import detect_tool_poisoning
from .prompt_intection import detect_prompt_injection
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


def run_security_rules(files):
    findings = []

    for rule in RULES:
        findings.extend(rule(files))

    return findings