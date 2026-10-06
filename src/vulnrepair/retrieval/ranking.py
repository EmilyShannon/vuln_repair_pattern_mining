"""Ranking helpers for retrieval implementations."""

from difflib import SequenceMatcher


def rank_text_similarity(query: str, candidates: list[str]) -> list[int]:
    """Return candidate indexes ordered by descending lexical similarity."""
    return sorted(
        range(len(candidates)),
        key=lambda index: SequenceMatcher(None, query, candidates[index]).ratio(),
        reverse=True,
    )

