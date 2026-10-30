"""The protocols connectors implement: LineageSource (read) and WritebackTarget (write)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from sensiflow.model import LineageGraph, Risk
from sensiflow.root_selectors import GraphSelection

if TYPE_CHECKING:
    from sensiflow.writeback import ApplyResult, TagChange


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


@dataclass(frozen=True)
class ExistingTag:
    """PII markup currently on a column, in the neutral shape the diff reasons about.

    ``sensitive`` and ``managed`` are always known; ``managed`` is True iff the
    tool owns the markup (OpenMetadata: marker plus an unconfirmed Automated
    label; dbt: the ``meta.sensiflow`` block). Every other field is ``None``
    when the target cannot store it, and a ``None`` never participates in
    drift. ``not_pii`` is an explicit human negative declaration ("this column
    is not PII"), which is not the same thing as non-sensitive PII.
    """

    sensitive: bool
    managed: bool
    category: str | None = None
    risk: Risk | None = None
    confidence: float | None = None
    origin: str | None = None
    not_pii: bool = False
@runtime_checkable
class WritebackTarget(Protocol):
    """A catalog or project that derived markup can be written to (ADR-0006 §3).

    Independent of :class:`LineageSource`, which stays read-only. Diff policy
    (add / update / manual / conflict ...) lives once in ``writeback.py``;
    implementations only translate their reality into :class:`ExistingTag`
    and execute writes. Confirm gating lives in ``apply_writeback``.
    """

    def read_markup(self, node_ids: Sequence[str]) -> dict[tuple[str, str], ExistingTag]:
        """Current PII markup on the given nodes, read-only.

        Key: ``(node_id, column)`` with the column lower-cased. Covers
        human-placed markup and sensiflow-managed markup (``managed=True``).
        """
        ...

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[tuple[str, str], str]:
        """Planned changes the target cannot place, with the reason (read-only).

        Key: ``(node_id, column)`` lower-cased column; value: human-readable
        reason (a dbt target embeds a ready-to-paste YAML snippet). The diff
        needs this because ``read_markup`` only lists columns that *have*
        markup and cannot tell "no markup" from "no such column".
        """
        ...

    def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
        """Execute the changes. Mutating; called only via ``apply_writeback``."""
        ...
