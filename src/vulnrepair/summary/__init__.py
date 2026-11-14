"""Generation of natural-language vulnerability and repair summaries."""

from .generator import SummaryGenerator
from .models import SummaryGenerationRequest, SummaryGenerationResult

__all__ = [
    "SummaryGenerationRequest",
    "SummaryGenerationResult",
    "SummaryGenerator",
]
