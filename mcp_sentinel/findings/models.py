from dataclasses import dataclass


@dataclass
class SecurityFinding:
    rule_id: str
    title: str
    severity: str
    file: str
    description: str
    recommendation: str