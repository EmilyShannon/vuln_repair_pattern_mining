"""Request and result types for vulnerability summary generation."""

from dataclasses import dataclass


@dataclass
class SummaryGenerationRequest:
    patch: str
    cwe_id: str
    commit_message: str
    num_variants: int = 3
    prompt_mode: str = "orig"


@dataclass
class SummaryGenerationResult:
    variant_id: int
    summary: str
    input_prompt: str
    input_tokens: int | None = None
    output_tokens: int | None = None
