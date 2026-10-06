"""Prompt helpers that preserve the existing repair prompt templates."""

from pathlib import Path
import json


def load_prompt_templates() -> list[dict]:
    template_path = next(
        (
            parent / "eval" / "llm_based_repair_prompt_templates.json"
            for parent in Path(__file__).resolve().parents[2:4]
            if (parent / "eval" / "llm_based_repair_prompt_templates.json").is_file()
        ),
        None,
    )
    if template_path is None:
        raise FileNotFoundError("Could not locate the repair prompt templates")
    with template_path.open(encoding="utf-8") as handle:
        return json.load(handle).get("prompt_templates", [])
