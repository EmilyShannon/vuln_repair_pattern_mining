"""Embedding model interface for future pluggable retrieval implementations."""

from typing import Protocol, Sequence


class EmbeddingModel(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one embedding vector for each input string."""

