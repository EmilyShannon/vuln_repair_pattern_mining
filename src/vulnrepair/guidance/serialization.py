"""Serialization helpers for the public guidance dataclasses."""

from dataclasses import asdict
from typing import Any

from .models import GuidanceTree


def tree_to_dict(tree: GuidanceTree) -> dict[str, Any]:
    """Serialize a typed guidance tree into JSON-compatible dictionaries."""
    return {
        "root_id": tree.root_id,
        "nodes": {node_id: asdict(node) for node_id, node in tree.nodes.items()},
    }

