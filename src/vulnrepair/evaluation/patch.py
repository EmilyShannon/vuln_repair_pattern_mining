"""Patch comparison adapter around the existing evaluation metrics."""

from eval.evaluate_results import (
    compute_bleu,
    compute_codebleu,
    compute_diff,
    compute_fuzzy_match,
    normalize_patch,
)

from .models import RepairEvaluation


class PatchComparator:
    def compare(self, evaluation: RepairEvaluation) -> dict:
        reference = evaluation.reference_patch
        candidate = evaluation.candidate_patch
        return {
            "patch_match": normalize_patch(reference) == normalize_patch(candidate),
            "fuzzy_match": compute_fuzzy_match(reference, candidate),
            "bleu": compute_bleu(reference, candidate),
            "codebleu": compute_codebleu(reference, candidate),
            "diff": compute_diff(reference, candidate),
        }

