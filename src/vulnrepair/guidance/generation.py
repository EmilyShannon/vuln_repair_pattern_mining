"""Adapters to the repository's existing dynamic guidance-tree generator."""

from .models import GuidanceGenerationRequest


class GuidanceGenerator:
    """Run the existing tree builder without changing its generation behavior."""

    def generate(self, request: GuidanceGenerationRequest):
        from mining.trees.utils.build_tree import build_tree

        return build_tree(request.patches, request.config)

