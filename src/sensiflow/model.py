"""Core dataclasses: the abstract lineage graph and trace results.

These types are the public contract of sensiflow. The engine consumes a
:class:`LineageGraph` and returns a :class:`TraceResult`; connectors produce
graphs, renderers consume results. Nothing here knows about catalogs or SQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Risk = Literal["ORIGIN", "LOW", "MEDIUM", "HIGH", "NONE"]

#: Precedence used for max_risk and report ordering (higher = more exposed).
RISK_RANK: dict[Risk, int] = {"NONE": 0, "ORIGIN": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}


@dataclass(frozen=True)
class PiiTag:
    """A PII marker on a column, e.g. category="email"."""

    category: str
    sensitive: bool = True


@dataclass
class Node:
    """One node of the lineage graph (a table, view, or model)."""

    id: str
    name: str
    owners: list[str] = field(default_factory=list)
    upstream: list[str] = field(default_factory=list)
    sql: str | None = None
    declared_pii: dict[str, PiiTag] = field(default_factory=dict)


@dataclass
class LineageGraph:
    """An abstract lineage graph keyed by node id."""

    nodes: dict[str, Node]


@dataclass(frozen=True)
class Finding:
    """One PII exposure finding: a column on a node, with risk and provenance."""

    column: str
    tag: PiiTag
    risk: Risk
    reason: str
    confidence: float
    origin_node: str


@dataclass
class NodeResult:
    """Classification of a single node after propagation."""

    node_id: str
    name: str
    owners: list[str]
    is_source: bool
    findings: dict[str, Finding]

    @property
    def max_risk(self) -> Risk:
        if not self.findings:
            return "NONE"
        return max((f.risk for f in self.findings.values()), key=lambda r: RISK_RANK[r])


@dataclass
class TraceResult:
    """The full result of a trace over a lineage graph."""

    nodes: dict[str, NodeResult]

    def by_risk(self, minimum: Risk = "LOW") -> list[NodeResult]:
        """Nodes at or above ``minimum`` risk, most exposed first."""
        selected = [n for n in self.nodes.values() if RISK_RANK[n.max_risk] >= RISK_RANK[minimum]]
        return sorted(selected, key=lambda n: (-RISK_RANK[n.max_risk], n.name))

    def summary(self) -> dict[Risk, int]:
        """Node count per risk level (all five levels always present)."""
        counts: dict[Risk, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "ORIGIN": 0, "NONE": 0}
        for node in self.nodes.values():
            counts[node.max_risk] += 1
        return counts
