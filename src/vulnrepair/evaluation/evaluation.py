"""Evaluation adapter around the established result aggregation."""

import pandas as pd

from eval.evaluate_results import analyze_patch_match

from .models import EvaluationResult


class Evaluator:
    def evaluate(self, results: pd.DataFrame) -> EvaluationResult:
        values = analyze_patch_match(results)
        return EvaluationResult(**values)

