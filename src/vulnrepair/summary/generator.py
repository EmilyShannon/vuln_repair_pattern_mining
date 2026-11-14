"""Generate vulnerability and repair-strategy summaries for patches."""

from typing import Any

from .models import SummaryGenerationRequest, SummaryGenerationResult

_PROMPT_BASES = {
    "orig": (
        "Given the following information from a vulnerability-fixing commit, "
        "generate 1) a concise, detailed 1 to 2 sentence-long summary of the "
        "vulnerability being fixed, and 2) a concise, detailed 1 to 2 "
        "sentence-long summary of the strategy being used to repair the "
        "vulnerability. Do NOT include the patch content in your summaries. "
        "Focus on describing the vulnerability itself, and the repair strategy, "
        'respectively. Output the summaries like this: "VUL_SUMMARY: '
        '<vul_summary>" and "STRATEGY_SUMMARY: <strat_summary>".'
    ),
    "hybrid": (
        "Given the following information from a vulnerability-fixing commit, "
        "generate 1) a concise, detailed 1 to 2 sentence-long summary of the "
        "vulnerability being fixed, and 2) a concise, detailed 1 to 2 "
        "sentence-long summary of the strategy being used to repair the "
        "vulnerability. Do NOT include the patch content in your summaries. "
        "Focus on describing the vulnerability itself, and the repair strategy, "
        "respectively. Omit implementation-specific details unless they are "
        "critical to the vulnerability or repair, such as a critical function "
        "call, library usage, or security-library call. Output the summaries "
        'like this: "VUL_SUMMARY: <vul_summary>" and "STRATEGY_SUMMARY: '
        '<strat_summary>".'
    ),
    "semantic": (
        "Given the following information from a vulnerability-fixing commit, "
        "generate 1) a concise, detailed 1 to 2 sentence-long summary of the "
        "vulnerability being fixed, and 2) a concise, detailed 1 to 2 "
        "sentence-long summary of the repair strategy being used to repair the "
        "vulnerability.\n\n"
        "Do NOT include the patch content in your summary. Do NOT include "
        "implementation details, library or parser names, or code-specific "
        "content.\n\n"
        "For the vulnerability summary, focus on describing the nature of the "
        "vulnerability, such as improper input validation leading to remote "
        "code execution, unsafe deserialization, or a buffer overflow due to "
        "unchecked array access. Emphasize the underlying issue rather than "
        "specific code constructs.\n\n"
        "For the repair summary, focus on the general approach or high-level "
        "strategy, such as disabling unsafe features, replacing an unsafe "
        "parser, or validating input before processing. Emphasize how the "
        "vulnerability is addressed rather than the exact code change. Make "
        "summaries generalizable so that semantically similar vulnerabilities "
        "and repair strategies can be phrased similarly.\n\n"
        'Output the summaries like this: "VUL_SUMMARY: <vul_summary>" and '
        '"STRATEGY_SUMMARY: <strat_summary>".'
    ),
}


class SummaryGenerator:
    """Generate one or more vulnerability and repair-strategy summaries."""

    _DEFAULT_MODELS = {
        "openai": "gpt-5.1",
        "ollama": "qwen3-coder:30b-cloud",
    }

    def __init__(
        self, provider: str = "ollama", model: str | None = None, client: Any = None
    ):
        provider = provider.lower()
        if provider not in self._DEFAULT_MODELS:
            raise ValueError(
                f"Unsupported provider: {provider}. Supported providers are "
                "'openai' and 'ollama'."
            )

        self.provider = provider
        self.model = model or self._DEFAULT_MODELS[provider]
        if client is None:
            from eval.llm_basic_repair import load_client

            client = load_client(provider, self.model)
        self.client = client

    def generate(
        self, request: SummaryGenerationRequest
    ) -> list[SummaryGenerationResult]:
        if request.num_variants < 1:
            raise ValueError("num_variants must be at least 1")

        prompt_mode = request.prompt_mode.lower()
        try:
            prompt_base = _PROMPT_BASES[prompt_mode]
        except KeyError as exc:
            modes = ", ".join(sorted(_PROMPT_BASES))
            raise ValueError(
                f"Unsupported prompt_mode: {request.prompt_mode}. "
                f"Supported modes are: {modes}."
            ) from exc

        prompt = (
            f"{prompt_base}\n"
            f"CWE ID:\n{request.cwe_id}\n"
            f"COMMIT MESSAGE:\n{request.commit_message}\n"
            f"Patch:\n{request.patch}"
        )
        return [
            self._generate_variant(prompt, variant_id)
            for variant_id in range(request.num_variants)
        ]

    def _generate_variant(
        self, prompt: str, variant_id: int
    ) -> SummaryGenerationResult:
        if self.provider == "openai":
            response = self.client.responses.create(
                model=self.model,
                input=[{"role": "user", "content": prompt}],
            )
            summary = response.output_text.strip()
            usage = getattr(response, "usage", None)
            input_tokens = getattr(usage, "input_tokens", None)
            output_tokens = getattr(usage, "output_tokens", None)
        else:
            response = self.client.generate(model=self.model, prompt=prompt)
            summary = self._ollama_text(response).strip()
            input_tokens = self._ollama_token_count(response, "prompt_eval_count")
            output_tokens = self._ollama_token_count(response, "eval_count")

        return SummaryGenerationResult(
            variant_id=variant_id,
            summary=summary,
            input_prompt=prompt,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    @staticmethod
    def _ollama_text(response: Any) -> str:
        if isinstance(response, dict):
            text = response.get("response")
        else:
            text = getattr(response, "response", None)
        if not isinstance(text, str):
            raise TypeError(
                "Ollama generation response must contain text in 'response'"
            )
        return text

    @staticmethod
    def _ollama_token_count(response: Any, field: str) -> int | None:
        if isinstance(response, dict):
            count = response.get(field)
        else:
            count = getattr(response, field, None)
        return count if isinstance(count, int) else None
