"""sensiflow — propagate PII tags along data lineage and classify exposure risk."""

from sensiflow.engine import DEFAULT_GENERIC_COLUMNS, trace
from sensiflow.exceptions import (
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowError,
    SensiflowInputError,
)
from sensiflow.model import (
    Finding,
    LineageGraph,
    Node,
    NodeResult,
    PiiTag,
    Risk,
    TraceResult,
)
from sensiflow.root_selectors import GraphSelection

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_GENERIC_COLUMNS",
    "Finding",
    "GraphSelection",
    "LineageGraph",
    "Node",
    "NodeResult",
    "PiiTag",
    "Risk",
    "SensiflowConnectionError",
    "SensiflowDependencyError",
    "SensiflowError",
    "SensiflowInputError",
    "TraceResult",
    "__version__",
    "trace",
]
