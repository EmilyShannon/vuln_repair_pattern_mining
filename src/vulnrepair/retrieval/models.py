"""Retrieval request and response objects."""

from dataclasses import dataclass


@dataclass
class RetrievalQuery:
    vulnerable_code: str
    cwe_id: str
    tree: dict
    description: str | None = None
    cache_path: str | None = None


@dataclass
class RetrievalResult:
    guidance: str
    vulnerability_summary: str
    matched_summary: str | None
    matched_node_id: str | None
    explanation: str | None

