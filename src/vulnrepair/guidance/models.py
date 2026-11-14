"""Typed representations for guidance trees and generation requests."""

from dataclasses import dataclass, field
from typing import Any

from ..data.models import VulnerabilityDataset


@dataclass
class TreeConfig:
    """Configuration options for building a guidance tree."""

    min_group_size: int = 1
    max_group_size: int = 6
    min_nodes_to_continue: int = 1
    max_depth: int = 10
    force_merge_threshold: int = 2
    temperature: float = 0.0
    model: str = "gpt-4o"
    provider: str = "openai"
    tree_type: str = "combined"
    max_tokens: int = 100000


@dataclass
class RepairGuidance:
    text: str
    cwe_id: str | None = None
    source_node_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuidanceNode:
    node_id: str
    depth: int
    summary: str = ""
    guidance: str | None = None
    children: list[str] = field(default_factory=list)
    patches: list[str] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuidanceTree:
    nodes: dict[str, GuidanceNode] = field(default_factory=dict)
    root_id: str | None = None


@dataclass
class GuidanceGenerationRequest:
    patches: VulnerabilityDataset | None = None
    config: TreeConfig | None = None
    cwe_id: str | None = None
    output_path: str | None = None
