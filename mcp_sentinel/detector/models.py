from dataclasses import dataclass, field


@dataclass
class MCPDetectionResult:
    detected: bool
    language: str | None = None
    framework: str | None = None
    confidence: str = "Low"

    tools: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)