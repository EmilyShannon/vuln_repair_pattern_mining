"""Prompt-related types for guidance generation."""

from dataclasses import dataclass


@dataclass
class GuidancePrompt:
    text: str
    detail_level: str | None = None

