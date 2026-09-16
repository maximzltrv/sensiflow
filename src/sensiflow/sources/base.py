"""The LineageSource protocol every connector implements."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from sensiflow.model import LineageGraph


class LineageSource(Protocol):
    """Anything that can produce an abstract lineage graph.

    ``roots`` scopes the graph to the lineage closure of the given node ids
    (``None`` = the whole catalog). ``upstream_depth`` / ``downstream_depth``
    cap the walk per direction: ``None`` = unlimited, ``0`` = that direction
    disabled. Sources that have no notion of walking (e.g. fixed fixtures)
    may ignore all three.
    """

    def build_graph(
        self,
        roots: Sequence[str] | None = None,
        *,
        upstream_depth: int | None = None,
        downstream_depth: int | None = None,
    ) -> LineageGraph:
        """Build the graph, optionally scoped and depth-limited."""
        ...
