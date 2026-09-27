"""dbt connector: builds a LineageGraph from a dbt ``manifest.json``.

Implements ADR-0003: standard-library-only parsing (no dbt-core, no extra),
defensive across manifest schema versions — a missing field means the feature
is absent, never a crash. The user brings a manifest produced by their own
``dbt compile`` / ``dbt build``; sensiflow never runs dbt.

PII seeds come from column annotations, two conventions (ADR-0003 §4):
``meta: {pii: true, pii_category: ..., pii_sensitive: ...}`` (primary) and
column tags ``pii`` / ``pii:<category>`` (secondary).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sensiflow.exceptions import SensiflowInputError
from sensiflow.graph_scope import scope_graph
from sensiflow.model import LineageGraph, Node, PiiTag

#: resource kinds that become graph vertices; tests/macros/exposures are not data.
_INCLUDED_KINDS = frozenset({"model", "seed", "snapshot"})
_EDGE_PREFIXES = ("model.", "source.", "seed.", "snapshot.")


def _declared_pii(raw: dict[str, Any]) -> dict[str, PiiTag]:
    declared: dict[str, PiiTag] = {}
    for column_name, column in (raw.get("columns") or {}).items():
        meta = column.get("meta") or {}
        if meta.get("pii") is True:
            declared[column_name] = PiiTag(
                category=str(meta.get("pii_category") or "pii"),
                sensitive=bool(meta.get("pii_sensitive", True)),
            )
            continue
        for tag in column.get("tags") or []:
            if not isinstance(tag, str):
                continue
            if tag == "pii":
                declared[column_name] = PiiTag(category="pii")
                break
            if tag.startswith("pii:") and len(tag) > 4:
                declared[column_name] = PiiTag(category=tag[4:])
                break
    return declared


def _owners(raw: dict[str, Any]) -> list[str]:
    meta = {**(raw.get("meta") or {}), **((raw.get("config") or {}).get("meta") or {})}
    owner = meta.get("owner")
    if isinstance(owner, str) and owner.strip():
        return [owner]
    if isinstance(owner, list):
        return [item for item in owner if isinstance(item, str) and item]
    group = raw.get("group")
    if isinstance(group, str) and group:
        return [group]
    return []


def _sql(raw: dict[str, Any]) -> str | None:
    for key in ("compiled_code", "raw_code"):
        code = raw.get(key)
        if isinstance(code, str) and code.strip():
            return code
    return None


def _node_from_manifest_entry(unique_id: str, raw: dict[str, Any]) -> Node:
    upstream = [
        dep
        for dep in (raw.get("depends_on") or {}).get("nodes") or []
        if isinstance(dep, str) and dep.startswith(_EDGE_PREFIXES)
    ]
    return Node(
        id=unique_id,
        name=raw.get("name") or unique_id.rsplit(".", 1)[-1],
        owners=_owners(raw),
        upstream=upstream,
        sql=_sql(raw),
        declared_pii=_declared_pii(raw),
    )


class DbtSource:
    """LineageSource over a local dbt manifest.json (read-only, no network)."""

    def __init__(self, manifest_path: str | Path) -> None:
        self._path = Path(manifest_path)

    def __repr__(self) -> str:
        return f"DbtSource(manifest_path={str(self._path)!r})"

    def build_graph(
        self,
        roots: Sequence[str] | None = None,
        *,
        upstream_depth: int | None = None,
        downstream_depth: int | None = None,
    ) -> LineageGraph:
        manifest = self._load()
        graph = self._graph_from_manifest(manifest)
        if not roots:
            return graph
        resolved = [self._resolve_root(root, graph) for root in roots]
        return scope_graph(
            graph,
            resolved,
            upstream_depth=upstream_depth,
            downstream_depth=downstream_depth,
        )

    def _load(self) -> dict[str, Any]:
        try:
            text = self._path.read_text()
        except FileNotFoundError:
            raise SensiflowInputError(f"dbt manifest not found: {self._path}") from None
        except OSError as exc:
            raise SensiflowInputError(
                f"cannot read dbt manifest {self._path}: {exc.strerror}"
            ) from None
        try:
            manifest = json.loads(text)
        except ValueError:
            raise SensiflowInputError(
                f"{self._path} is not valid JSON — is it really a dbt manifest?"
            ) from None
        if not isinstance(manifest, dict) or (
            "nodes" not in manifest and "sources" not in manifest
        ):
            raise SensiflowInputError(
                f"{self._path} has neither 'nodes' nor 'sources' — "
                "not a dbt manifest.json"
            )
        return manifest

    @staticmethod
    def _graph_from_manifest(manifest: dict[str, Any]) -> LineageGraph:
        nodes: dict[str, Node] = {}
        for unique_id, raw in (manifest.get("nodes") or {}).items():
            if not isinstance(raw, dict):
                continue
            if raw.get("resource_type") not in _INCLUDED_KINDS:
                continue
            nodes[unique_id] = _node_from_manifest_entry(unique_id, raw)
        for unique_id, raw in (manifest.get("sources") or {}).items():
            if isinstance(raw, dict):
                nodes[unique_id] = _node_from_manifest_entry(unique_id, raw)
        return LineageGraph(nodes=nodes)

    @staticmethod
    def _resolve_root(root: str, graph: LineageGraph) -> str:
        """A root is a unique_id, or a bare model/source name if unambiguous."""
        if root in graph.nodes:
            return root
        matches = sorted(
            node_id for node_id, node in graph.nodes.items() if node.name == root
        )
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise SensiflowInputError(
                f"unknown root {root!r}: not a unique_id or a model/source name "
                "in the manifest"
            )
        raise SensiflowInputError(
            f"ambiguous root {root!r}: matches {', '.join(matches)} — "
            "use the full unique_id"
        )
