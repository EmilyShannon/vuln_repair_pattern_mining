"""Evaluation result structures."""

from dataclasses import dataclass
from typing import Any


@dataclass
class RepairEvaluation:
    reference_patch: str
    candidate_patch: str


@dataclass
class EvaluationResult:
    overall: dict[str, Any]
    by_prompt: Any
    by_guidance: Any
    by_prompt_and_guidance: Any
    patches: Any

