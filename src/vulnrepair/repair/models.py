"""Repair request and response objects."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RepairRequest:
    vulnerable_code: str
    prompt_template: str = "zero_shot"
    guidance: str | None = None
    examples: list[str] = field(default_factory=list)


@dataclass
class RepairResult:
    response: str
    repaired_code: str
    prompt: str
    metadata: dict[str, Any] = field(default_factory=dict)

