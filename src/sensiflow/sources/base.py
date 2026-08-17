"""The LineageSource protocol every connector implements."""

from __future__ import annotations

from typing import Protocol

from sensiflow.model import LineageGraph


class LineageSource(Protocol):
    """Anything that can produce an abstract lineage graph."""

    def build_graph(self, root: str | None = None) -> LineageGraph:
        """Build the graph, optionally scoped to the lineage of ``root``."""
        ...
