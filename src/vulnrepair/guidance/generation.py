"""Adapters to the repository's existing dynamic guidance-tree generator."""

import pandas as pd

from ..data.models import VulnerabilityDataset
from .models import GuidanceGenerationRequest


class GuidanceGenerator:
    """Run the existing tree builder without changing its generation behavior."""

    def generate(self, request: GuidanceGenerationRequest):
        from mining.trees.utils.build_tree import build_tree

        patches = request.patches
        if isinstance(patches, VulnerabilityDataset):
            patches = pd.DataFrame(
                [
                    {
                        "patch_id": example.cve_id or f"patch_{index}",
                        "cwe_id": example.cwe_id,
                        "summary": example.message
                        or example.metadata.get("cve_description", ""),
                        "patch": example.patch or "",
                    }
                    for index, example in enumerate(patches.examples)
                ],
                columns=["patch_id", "cwe_id", "summary", "patch"],
            )

        return build_tree(patches, request.config)
