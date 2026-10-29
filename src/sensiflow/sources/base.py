"""The LineageSource protocol every connector implements."""

from __future__ import annotations

from typing import Protocol

from sensiflow.model import LineageGraph
from sensiflow.root_selectors import GraphSelection


class LineageSource(Protocol):
    """Anything that can produce an abstract lineage graph.

    ``selection`` scopes the graph (ADR-0002 amendment A4): exact roots,
    fnmatch patterns, or seed-derived roots, plus per-direction depth
    limits. ``None`` — like an all-defaults ``GraphSelection()`` — means a
    full scan. Sources that have no notion of walking (e.g. fixed fixtures)
    may ignore the selection.

    This signature is shape-stable: future scoping extensions add optional
    fields to ``GraphSelection``, never parameters to ``build_graph``.
    """

    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
        """Build the graph, optionally scoped by ``selection``."""
        ...
