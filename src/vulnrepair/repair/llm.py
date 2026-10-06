"""Adapter to the existing OpenAI/Ollama repair request implementation."""

from .models import RepairRequest, RepairResult
from .prompts import load_prompt_templates


class LLMClient:
    def __init__(self, provider: str, model: str | None = None, client=None):
        self.provider = provider
        self.model = model
        if client is None:
            from eval.llm_basic_repair import load_client

            client = load_client(provider, model)
        self.client = client

    def generate(self, prompt: str) -> str:
        from eval.llm_basic_repair import get_response

        if not self.model:
            raise ValueError("A model name is required to generate a response")
        return get_response(self.provider, self.client, self.model, prompt)


class Repairer:
    def __init__(self, client: LLMClient):
        self.client = client

    def repair(self, request: RepairRequest) -> RepairResult:
        from eval.llm_basic_repair import (
            extract_patch_from_response,
            formulate_prompt,
            load_prompt_template,
        )

        templates = load_prompt_templates()
        template = load_prompt_template(request.prompt_template, templates)
        prompt = formulate_prompt(
            template,
            request.vulnerable_code,
            examples=request.examples or None,
            guidance=request.guidance,
        )
        response = self.client.generate(prompt)
        return RepairResult(
            response=response,
            repaired_code=extract_patch_from_response(response),
            prompt=prompt,
        )
