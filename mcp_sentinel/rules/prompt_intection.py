"""Deprecated alias kept for backwards compatibility.

The module was renamed to ``prompt_injection`` (fixing a typo).
"""

from .prompt_injection import detect_prompt_injection  # noqa: F401

__all__ = ["detect_prompt_injection"]
