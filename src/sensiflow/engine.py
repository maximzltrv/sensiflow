"""Propagation engine: seed declared PII, walk the graph, classify exposure.

Implements ADR-0001. The engine consumes an abstract
:class:`~sensiflow.model.LineageGraph` and never talks to a catalog. SQL, when
present, refines classification (HIGH/MEDIUM); when absent or unparseable the
node degrades to presence-based classification (LOW).
"""

from __future__ import annotations

from dataclasses import dataclass

from sensiflow.model import Finding, LineageGraph, NodeResult, PiiTag, TraceResult
from sensiflow.sql_analysis import analyze_sql

#: Column names too generic to trust a name-based PII match on.
DEFAULT_GENERIC_COLUMNS: frozenset[str] = frozenset(
    {"id", "name", "date", "status", "value", "type", "code", "key", "created_at", "updated_at"}
)

# Confidence multipliers per matching mechanism (heuristics are not exact and
# the numbers say so; see ADR-0001 §4).
_CONF_PROJECTION_SAME_NAME = 0.9
_CONF_PROJECTION_ALIASED = 0.8
_CONF_SELECT_STAR = 0.7
_CONF_PRESENCE_ONLY = 0.6
_CONF_JOIN_WHERE = 0.9


@dataclass(frozen=True)
class _Propagated:
    """A PII column flowing along an edge: its tag, origin, and belief."""

    tag: PiiTag
    origin: str
    confidence: float


def _topological_order(graph: LineageGraph) -> list[str]:
    """Kahn's algorithm over upstream edges; raises on cycles."""
    remaining_deps = {
        node_id: {up for up in node.upstream if up in graph.nodes}
        for node_id, node in graph.nodes.items()
    }
    downstream: dict[str, list[str]] = {node_id: [] for node_id in graph.nodes}
    for node_id, deps in remaining_deps.items():
        for up in deps:
            downstream[up].append(node_id)

    ready = sorted(node_id for node_id, deps in remaining_deps.items() if not deps)
    order: list[str] = []
    while ready:
        node_id = ready.pop(0)
        order.append(node_id)
        for down in downstream[node_id]:
            remaining_deps[down].discard(node_id)
            if not remaining_deps[down]:
                ready.append(down)
    if len(order) != len(graph.nodes):
        raise ValueError("lineage graph contains a cycle")
    return order


def trace(
    graph: LineageGraph,
    *,
    dialect: str = "bigquery",
    generic_columns: set[str] | None = None,
) -> TraceResult:
    """Propagate declared PII down the graph and classify every node."""
    generic = frozenset(generic_columns) if generic_columns is not None else DEFAULT_GENERIC_COLUMNS
    outputs: dict[str, dict[str, _Propagated]] = {}
    results: dict[str, NodeResult] = {}

    for node_id in _topological_order(graph):
        node = graph.nodes[node_id]

        # Merge upstream outputs; on a name collision keep the higher confidence.
        inherited: dict[str, _Propagated] = {}
        for up in node.upstream:
            for column, prop in outputs.get(up, {}).items():
                current = inherited.get(column)
                if current is None or prop.confidence > current.confidence:
                    inherited[column] = prop

        findings: dict[str, Finding] = {}
        node_out: dict[str, _Propagated] = {}

        # Declared PII seeds this node as an ORIGIN and always propagates.
        for column, tag in node.declared_pii.items():
            column = column.lower()
            findings[column] = Finding(
                column=column,
                tag=tag,
                risk="ORIGIN",
                reason="declared PII source",
                confidence=1.0,
                origin_node=node.id,
            )
            node_out[column] = _Propagated(tag=tag, origin=node.id, confidence=1.0)

        analysis = analyze_sql(node.sql, dialect) if node.sql is not None else None

        if analysis is None:
            # Presence-based fallback: no SQL, or SQL failed to parse. We know
            # PII arrives here via lineage but not how it is used.
            for column, prop in inherited.items():
                if column in generic or column in findings:
                    continue
                confidence = prop.confidence * _CONF_PRESENCE_ONLY
                findings[column] = Finding(
                    column=column,
                    tag=prop.tag,
                    risk="LOW",
                    reason="present via lineage (no SQL available)",
                    confidence=confidence,
                    origin_node=prop.origin,
                )
                node_out.setdefault(
                    column, _Propagated(tag=prop.tag, origin=prop.origin, confidence=confidence)
                )
        else:
            # HIGH: inherited PII used in a JOIN condition or WHERE clause.
            # Flagged on this node; propagates only if it is also in the output.
            for column in analysis.join_or_where:
                hit = inherited.get(column)
                if hit is None or column in generic:
                    continue
                findings[column] = Finding(
                    column=column,
                    tag=hit.tag,
                    risk="HIGH",
                    reason="used in JOIN/WHERE",
                    confidence=hit.confidence * _CONF_JOIN_WHERE,
                    origin_node=hit.origin,
                )

            # MEDIUM: inherited PII explicitly projected (possibly renamed).
            for out_name, src_name in analysis.projected.items():
                hit = inherited.get(src_name)
                if hit is None or src_name in generic:
                    continue
                same_name = out_name == src_name
                factor = _CONF_PROJECTION_SAME_NAME if same_name else _CONF_PROJECTION_ALIASED
                confidence = hit.confidence * factor
                if out_name not in findings:
                    findings[out_name] = Finding(
                        column=out_name,
                        tag=hit.tag,
                        risk="MEDIUM",
                        reason="selected in projection",
                        confidence=confidence,
                        origin_node=hit.origin,
                    )
                node_out[out_name] = _Propagated(
                    tag=hit.tag, origin=hit.origin, confidence=confidence
                )

            # LOW: everything inherited arrives implicitly via SELECT *.
            if analysis.select_star:
                for column, prop in inherited.items():
                    if column in generic:
                        continue
                    confidence = prop.confidence * _CONF_SELECT_STAR
                    if column not in findings:
                        findings[column] = Finding(
                            column=column,
                            tag=prop.tag,
                            risk="LOW",
                            reason="inherited via SELECT *",
                            confidence=confidence,
                            origin_node=prop.origin,
                        )
                    node_out.setdefault(
                        column,
                        _Propagated(tag=prop.tag, origin=prop.origin, confidence=confidence),
                    )
            # Inherited columns that are neither projected, nor in JOIN/WHERE,
            # nor swept up by SELECT * are read-and-dropped: no finding, no
            # propagation.

        outputs[node_id] = node_out
        results[node_id] = NodeResult(
            node_id=node.id,
            name=node.name,
            owners=list(node.owners),
            is_source=bool(node.declared_pii),
            findings=findings,
        )

    warnings = list(graph.warnings)
    if graph.nodes and not any(node.declared_pii for node in graph.nodes.values()):
        warnings.append(
            "no PII seeds declared anywhere in the graph — nothing to propagate "
            "(see applicability preconditions, ADR-0001)"
        )
    return TraceResult(nodes=results, warnings=warnings)
