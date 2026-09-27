"""In-memory scoping of a LineageGraph to the lineage closure of roots.

Shared by connectors whose whole graph is already local (dbt manifest, future
file-based sources): build everything, then keep the union of per-direction
closures from the roots. Semantics match ADR-0002 §3: ``None`` depth =
unlimited, ``0`` disables a direction, and truncation produces the same
warnings (a hard one when the upstream cut leaves no PII seeds in scope, a
mild note for a downstream cut).

Connectors that fetch remotely (OpenMetadata) must NOT use this: their walk
exists to limit fetching, not to filter a graph they already paid for.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence

from sensiflow.model import LineageGraph


def scope_graph(
    graph: LineageGraph,
    roots: Sequence[str],
    *,
    upstream_depth: int | None = None,
    downstream_depth: int | None = None,
) -> LineageGraph:
    """Return a new graph containing roots plus their bounded closures.

    Every root must be a node id present in ``graph`` (connectors resolve
    user input to ids before calling). Kept nodes are shared, not copied;
    upstream references to dropped nodes are left dangling — the engine
    ignores edges pointing outside the graph.
    """
    downstream_map: dict[str, list[str]] = {node_id: [] for node_id in graph.nodes}
    for node_id, node in graph.nodes.items():
        for up in node.upstream:
            if up in graph.nodes:
                downstream_map[up].append(node_id)

    def ups(node_id: str) -> list[str]:
        return [u for u in graph.nodes[node_id].upstream if u in graph.nodes]

    def downs(node_id: str) -> list[str]:
        return downstream_map[node_id]

    def expand(
        neighbors: Callable[[str], list[str]], limit: int | None
    ) -> tuple[set[str], bool]:
        reached: set[str] = set()
        truncated = False
        seen: set[str] = set(roots)
        frontier: deque[tuple[str, int]] = deque((root, 0) for root in roots)
        while frontier:
            node_id, dist = frontier.popleft()
            adjacent = neighbors(node_id)
            if limit is not None and dist >= limit:
                if any(n not in seen for n in adjacent):
                    truncated = True
                continue
            for neighbor in adjacent:
                if neighbor not in seen:
                    seen.add(neighbor)
                    reached.add(neighbor)
                    frontier.append((neighbor, dist + 1))
        return reached, truncated

    ancestors, truncated_up = expand(ups, upstream_depth)
    descendants, truncated_down = expand(downs, downstream_depth)
    keep = set(roots) | ancestors | descendants

    nodes = {node_id: node for node_id, node in graph.nodes.items() if node_id in keep}
    warnings = list(graph.warnings)
    has_seeds = any(node.declared_pii for node in nodes.values())
    if truncated_up and not has_seeds:
        warnings.append(
            f"upstream truncated at depth {upstream_depth}; no PII sources within "
            "horizon — findings may be incomplete"
        )
    if truncated_down:
        warnings.append(
            f"downstream truncated at depth {downstream_depth}; consumers below "
            "this horizon were not analyzed"
        )
    return LineageGraph(nodes=nodes, warnings=warnings)
