"""Compatibility adapter around the current LLM-based guidance retriever."""

from .models import RetrievalQuery, RetrievalResult


class GuidanceRetriever:
    def __init__(self, client, provider: str, model: str):
        self.client = client
        self.provider = provider
        self.model = model

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        if query.cache_path is None:
            raise ValueError("cache_path is required by the current guidance retriever")
        from retrieval.retrieve_guidance import retrieve_guidance

        guidance, summary, matched, node_id, explanation = retrieve_guidance(
            client=self.client,
            provider=self.provider,
            model=self.model,
            vul_code=query.vulnerable_code,
            cwe_id=query.cwe_id,
            description=query.description,
            tree_json=query.tree,
            cache_path=query.cache_path,
        )
        return RetrievalResult(guidance, summary, matched, node_id, explanation)

