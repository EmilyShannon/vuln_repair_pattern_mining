"""Typed representations for guidance trees and generation requests."""

from dataclasses import dataclass, field
from typing import Any


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
    patches: Any
    config: Any = None
    cwe_id: str | None = None
    output_path: str | None = None

