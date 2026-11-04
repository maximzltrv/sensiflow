"""OpenMetadata connector: builds a LineageGraph from the OMD REST API.

Implements ADR-0002: a thin read-only client over the stable v1 endpoints
(tables, lineage), shipped behind the ``openmetadata`` extra. ``httpx`` is
imported lazily so the base install never needs it.

Secrets hygiene: the JWT token lives only in the Authorization header of the
HTTP client. It must never appear in ``repr()``, exception messages, or
anything else that can reach logs or reports.
"""

from __future__ import annotations

import importlib
import json
import unicodedata
import uuid
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from types import ModuleType
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit

from sensiflow.exceptions import (
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowInputError,
)
from sensiflow.model import LineageGraph, Node, PiiTag
from sensiflow.root_selectors import GraphSelection, resolve_patterns
from sensiflow.sources.base import ExistingTag
from sensiflow.writeback import ApplyResult, TagChange, recheck_reason, reclassify_change

if TYPE_CHECKING:
    import httpx

_TABLE_FIELDS = "columns,tags,owners"
_PAGE_LIMIT = 100
_UP, _DOWN = 0, 1

# Write-back names are a frozen public contract (ADR-0006 review resolution 5).
MARKER_CLASSIFICATION = "Sensiflow"
MARKER_TAG = "Sensiflow.Propagated"
_PII_SENSITIVE = "PII.Sensitive"
_PII_NON_SENSITIVE = "PII.NonSensitive"
_PII_FQNS = (_PII_SENSITIVE, _PII_NON_SENSITIVE)
_PATCH_CONTENT_TYPE = "application/json-patch+json"

#: fqn -> (upstream fqns, downstream fqns), one lineage call per table max.
_EdgeCache = dict[str, tuple[list[str], list[str]]]


def _require_httpx(
    import_module: Callable[[str], ModuleType] = importlib.import_module,
) -> ModuleType:
    try:
        return import_module("httpx")
    except ImportError as exc:
        raise SensiflowDependencyError(
            "the OpenMetadata connector requires the 'openmetadata' extra: "
            "pip install 'sensiflow[openmetadata]'"
        ) from exc


def _tag_fqns(column: dict[str, Any]) -> list[str]:
    """Tag FQNs by position ('' for malformed entries) so indexes match the payload."""
    tags = column.get("tags") or []
    return [tag.get("tagFQN", "") if isinstance(tag, dict) else "" for tag in tags]


def _declared_pii(table: dict[str, Any]) -> dict[str, PiiTag]:
    """Columns of an OMD table entity carrying a PII.* tag (ADR-0002 §4).

    Columns carrying the sensiflow marker are skipped: their PII tag was
    written by ``propagate`` and must never seed a trace (ADR-0006 §4).
    """
    declared: dict[str, PiiTag] = {}
    for column in table.get("columns") or []:
        fqns = _tag_fqns(column)
        if MARKER_TAG in fqns:
            continue
        for tag_fqn in fqns:
            if tag_fqn == _PII_SENSITIVE:
                declared[column["name"]] = PiiTag(category="pii", sensitive=True)
            elif tag_fqn == _PII_NON_SENSITIVE:
                declared[column["name"]] = PiiTag(category="pii", sensitive=False)
    return declared


#: Characters that would change the meaning of an FQN interpolated into a URL path.
_FQN_FORBIDDEN = frozenset("/\\?#%;")


def _unsafe_fqn(fqn: str) -> bool:
    """True when an FQN cannot be put in a URL path as-is (ADR-0006 A7).

    Catalog content is untrusted: a name carrying path, query or fragment
    metacharacters, a raw ``%``, ``;``, control characters or a ``..`` segment
    could address a different API resource than the one named in the plan.
    """
    return (
        not fqn
        or ".." in fqn
        or fqn.startswith(".")  # "." and ".x" collapse or escape the /name/ segment
        or fqn.endswith(".")
        or any(ch in _FQN_FORBIDDEN or unicodedata.category(ch) == "Cc" for ch in fqn)
    )


def _name_path(prefix: str, fqn: str) -> str:
    """``/prefix/name/<fqn>`` with the FQN percent-encoded (callers validated it first)."""
    return f"{prefix}/name/{quote(fqn, safe='')}"


def _is_unconfirmed_automated(label: Any) -> bool:
    return (
        isinstance(label, dict)
        and label.get("labelType") == "Automated"
        and label.get("state") == "Suggested"
    )


def _markup_of(column: dict[str, Any]) -> tuple[ExistingTag | None, int | None]:
    """A column's PII markup in the neutral shape, plus the slot of the managed label.

    *Managed* (ADR-0006 A1) iff the marker is present AND the PII label itself
    is ``Automated`` + ``Suggested``; a steward's confirmation or a foreign
    label moves it into human authority. The returned slot is that label's
    index in ``tags`` — the only label a write may ever replace. Otherwise any
    PII label makes the markup human (sensitive wins among several).
    """
    fqns = _tag_fqns(column)
    tags = column.get("tags") or []
    pii_slots = [i for i, fqn in enumerate(fqns) if fqn in _PII_FQNS]
    if not pii_slots:
        return None, None
    if MARKER_TAG in fqns:
        for slot in pii_slots:
            if _is_unconfirmed_automated(tags[slot]):
                return ExistingTag(sensitive=fqns[slot] == _PII_SENSITIVE, managed=True), slot
    sensitive = any(fqns[i] == _PII_SENSITIVE for i in pii_slots)
    return ExistingTag(sensitive=sensitive, managed=False), None


def _existing_tag(column: dict[str, Any]) -> ExistingTag | None:
    return _markup_of(column)[0]


def _tag_label(tag_fqn: str) -> dict[str, str]:
    """A TagLabel as sensiflow writes it: tool-proposed, not human-confirmed."""
    return {
        "tagFQN": tag_fqn,
        "source": "Classification",
        "labelType": "Automated",
        "state": "Suggested",
    }


def _node_from_table(table: dict[str, Any], upstream: list[str]) -> Node:
    """Map an OMD table entity onto a sensiflow Node (ADR-0002 §3-§4)."""
    owners: list[str] = []
    for owner in table.get("owners") or []:
        label = owner.get("email") or owner.get("name") or owner.get("displayName")
        if label:
            owners.append(label)

    sql = table.get("schemaDefinition")
    if not isinstance(sql, str) or not sql.strip():
        sql = None

    fqn = table["fullyQualifiedName"]
    return Node(
        id=fqn,
        name=table.get("name") or fqn.rsplit(".", 1)[-1],
        owners=owners,
        upstream=upstream,
        sql=sql,
        declared_pii=_declared_pii(table),
    )


def _columns_of(table: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Well-formed ``(name, column)`` pairs of an untrusted table payload."""
    return [
        (column["name"], column)
        for column in table.get("columns") or []
        if isinstance(column, dict) and isinstance(column.get("name"), str)
    ]


def _group_by_node(changes: Sequence[TagChange]) -> dict[str, list[TagChange]]:
    grouped: dict[str, list[TagChange]] = {}
    for change in changes:
        grouped.setdefault(change.node_id, []).append(change)
    return grouped


@dataclass
class _PatchPlan:
    ops: list[dict[str, Any]] = field(default_factory=list)
    patched: list[TagChange] = field(default_factory=list)
    skipped: list[tuple[TagChange, str]] = field(default_factory=list)


def _plan_patch(table: dict[str, Any], changes: list[TagChange]) -> _PatchPlan:
    """JSON Patch operations for one table, re-verified against its live state.

    Each change is re-classified by the core policy against the freshly
    fetched column; only ``add``/``update`` verdicts produce operations, the
    rest are skipped with the reason. Every touched column is pinned by a
    ``test`` on its name (and, on ``replace``, on the label being replaced), so
    a concurrent reordering fails the patch instead of tagging the wrong column.
    """
    columns = table.get("columns") or []
    index_of: dict[str, int] = {}
    for position, column in enumerate(columns):
        name = column.get("name") if isinstance(column, dict) else None
        if isinstance(name, str):
            index_of.setdefault(name.lower(), position)
    plan = _PatchPlan()
    pinned: set[int] = set()
    for change in changes:
        at = index_of.get(change.column.lower())
        if at is None:
            plan.skipped.append((change, "skipped: column no longer exists in the table"))
            continue
        column = columns[at]
        live, slot = _markup_of(column)
        verdict = reclassify_change(change, live)
        if verdict.action not in ("add", "update"):
            plan.skipped.append((change, f"skipped: {recheck_reason(verdict)}"))
            continue
        if at not in pinned:
            pinned.add(at)
            plan.ops.append({"op": "test", "path": f"/columns/{at}/name", "value": column["name"]})
        base = f"/columns/{at}/tags"
        label = _tag_label(_PII_SENSITIVE if change.tag.sensitive else _PII_NON_SENSITIVE)
        if verdict.action == "update" and slot is not None:
            old = _tag_fqns(column)[slot]
            plan.ops.append({"op": "test", "path": f"{base}/{slot}/tagFQN", "value": old})
            plan.ops.append({"op": "replace", "path": f"{base}/{slot}", "value": label})
        else:
            labels = [label]
            if MARKER_TAG not in _tag_fqns(column):
                labels.append(_tag_label(MARKER_TAG))
            if isinstance(column.get("tags"), list):
                plan.ops.extend({"op": "add", "path": f"{base}/-", "value": lbl} for lbl in labels)
            else:
                if "tags" in column:
                    # A null array: pin it, so a tag added concurrently is not clobbered by
                    # the whole-array add. An absent key is guarded by If-Match instead.
                    plan.ops.append({"op": "test", "path": base, "value": None})
                plan.ops.append({"op": "add", "path": base, "value": labels})
        plan.patched.append(change)
    return plan


def _has_userinfo(host: str) -> bool:
    try:
        parts = urlsplit(host)
    except ValueError:
        return False
    return "@" in parts.netloc


class OpenMetadataSource:
    """LineageSource and WritebackTarget over the OpenMetadata REST API.

    Reading is the default; the only mutating entry point is ``write_changes``,
    reachable through ``apply_writeback(..., confirm=True)`` (ADR-0006).
    """

    def __init__(
        self,
        host: str,
        jwt_token: str,
        *,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        # Scheme first: a scheme-less "user:pw@host" parses with no netloc, so it
        # must be rejected here, before any code path could interpolate the host.
        if not host.lower().startswith(("http://", "https://")):
            raise SensiflowInputError(
                "the OpenMetadata host URL must start with http:// or https://"
            )
        if _has_userinfo(host):
            # Never echo the userinfo: it would leak the embedded credentials.
            raise SensiflowInputError(
                "credentials embedded in the OpenMetadata host URL are not supported; "
                "pass the JWT via --omd-token / OMD_TOKEN"
            )
        self.host = host.rstrip("/")
        self._token = jwt_token
        self._unsafe_names: set[str] = set()  # catalog names skipped during one build_graph
        self._timeout = timeout
        self._transport = transport  # injection point for tests (MockTransport)

    def __repr__(self) -> str:
        return f"OpenMetadataSource(host={self.host!r})"

    # -- public API ---------------------------------------------------------

    def _open_client(self) -> httpx.Client:
        httpx_mod = _require_httpx()
        client: httpx.Client = httpx_mod.Client(
            base_url=f"{self.host}/api/v1",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=self._timeout,
            transport=self._transport,
        )
        return client

    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
        client = self._open_client()
        self._unsafe_names = set()
        try:
            if selection is None or selection.is_full_scan():
                graph = self._full_scan(client)
            else:
                graph = self._walk(
                    client,
                    self._resolve_selection(client, selection),
                    selection.upstream_depth,
                    selection.downstream_depth,
                )
        finally:
            client.close()
        if self._unsafe_names:
            # Count only: the names are hostile input and are not echoed.
            graph.warnings.append(
                f"skipped {len(self._unsafe_names)} catalog entries whose names are unsafe "
                "or inconsistent; their lineage was not analyzed"
            )
        return graph

    def _usable(self, fqn: str) -> bool:
        """Whether a catalog-supplied FQN may be used in a URL; remembers rejects (A7)."""
        if _unsafe_fqn(fqn):
            self._unsafe_names.add(fqn)
            return False
        return True

    def _resolve_selection(self, client: httpx.Client, selection: GraphSelection) -> list[str]:
        """Resolve the selection to concrete root FQNs (ADR-0002 amendment A5).

        Exact roots keep the listing-free path. Patterns and from-seeds cost
        one paginated pass over /tables (from-seeds with ``fields=columns,tags``
        so PII markup is visible); the lineage walk then fetches only the
        matched closures.
        """
        if selection.from_seeds:
            tables = self._list_tables(client, fields="columns,tags")
            seeded = sorted(table["fullyQualifiedName"] for table in tables if _declared_pii(table))
            if not seeded:
                raise SensiflowInputError(
                    f"--roots-from-seeds found no PII-tagged tables at {self.host}; "
                    "sensiflow needs declared PII markup to trace from "
                    "(ADR-0001 applicability precondition)"
                )
            return [fqn for fqn in seeded if self._usable(fqn)]
        for root in selection.roots:
            if _unsafe_fqn(root):
                raise SensiflowInputError(
                    "a --root value contains characters that are not valid in a catalog name"
                )
        resolved = list(selection.roots)
        if selection.patterns:
            candidates = [
                (table["fullyQualifiedName"], table.get("name") or "")
                for table in self._list_tables(client, fields=None)
            ]
            matched = resolve_patterns(selection.patterns, candidates)
            resolved.extend(fqn for fqn in matched if self._usable(fqn))
        # One node matched by several selectors appears once (A2).
        return list(dict.fromkeys(resolved))

    # -- WritebackTarget (ADR-0006 §3, §5) ------------------------------------

    def read_markup(self, node_ids: Sequence[str]) -> dict[tuple[str, str], ExistingTag]:
        """PII markup per column; managed per ADR-0006 A1 (see :func:`_markup_of`)."""
        client = self._open_client()
        try:
            markup: dict[tuple[str, str], ExistingTag] = {}
            for fqn in node_ids:
                table, _ = self._fetch_markup_table(client, fqn)
                for name, column in _columns_of(table or {}):
                    existing = _existing_tag(column)
                    if existing is not None:
                        markup[(fqn, name.lower())] = existing
            return markup
        finally:
            client.close()

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[tuple[str, str], str]:
        """Planned columns the live table cannot place (physical placement only, A6)."""
        client = self._open_client()
        try:
            unmatched: dict[tuple[str, str], str] = {}
            for fqn, node_changes in _group_by_node(changes).items():
                table, _ = self._fetch_markup_table(client, fqn)
                names = {name.lower() for name, _ in _columns_of(table or {})}
                for change in node_changes:
                    key = (fqn, change.column.lower())
                    if _unsafe_fqn(fqn):
                        unmatched[key] = "node name is not safe to address in the catalog API"
                    elif table is None:
                        unmatched[key] = "table not found in OpenMetadata"
                    elif key[1] not in names:
                        unmatched[key] = "column is not in the table's schema in OpenMetadata"
            return unmatched
        finally:
            client.close()

    def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
        """Append TagLabels with one JSON Patch per table, re-verified against live state.

        The marker classification/tag is created idempotently first. Changes the
        live re-check reclassifies (column gone, a human tag appeared, the label
        was confirmed, a concurrent edit) are *skipped* with the reason, never
        forced; a failed PATCH *fails* only that table's changes (A3).
        """
        result = ApplyResult(applied=[], failed=[])
        if not changes:
            return result
        client = self._open_client()
        ensured = False

        def ensure_marker() -> None:
            # Created lazily, right before the first PATCH that needs it: a run
            # whose changes are all skipped never mutates the catalog at all.
            nonlocal ensured
            if not ensured:
                self._ensure_marker(client)
                ensured = True

        try:
            for fqn, table_changes in _group_by_node(changes).items():
                self._patch_table(client, fqn, table_changes, result, ensure_marker)
        finally:
            client.close()
        return result

    def _fetch_markup_table(
        self, client: httpx.Client, fqn: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        """The table (``fields=columns,tags``) and its ETag; ``(None, None)`` when absent.

        Absent covers: an unsafe FQN (never sent), a 404, and a returned entity
        whose own ``fullyQualifiedName`` is not the one requested — the plan
        names exactly one table and nothing else may be read or patched (A7).
        """
        if _unsafe_fqn(fqn):
            return None, None
        path = _name_path("/tables", fqn)
        response = self._send(
            client, "GET", path, params={"fields": "columns,tags"}, tolerate=frozenset({404})
        )
        if response.status_code == 404:
            return None, None
        table = self._json(response, path)
        if table.get("fullyQualifiedName") != fqn:
            return None, None
        return table, response.headers.get("etag")

    def _ensure_marker(self, client: httpx.Client) -> None:
        """Create the Sensiflow classification and Propagated tag if absent (idempotent)."""
        tolerate = frozenset({404, 409})
        class_name = MARKER_CLASSIFICATION
        tag_name = MARKER_TAG.split(".", 1)[1]
        probes = (
            (
                f"/classifications/name/{class_name}",
                "/classifications",
                {
                    "name": class_name,
                    "description": "Namespace for markup written by sensiflow propagate.",
                },
            ),
            (
                f"/tags/name/{MARKER_TAG}",
                "/tags",
                {
                    "classification": class_name,
                    "name": tag_name,
                    "description": "PII markup derived from lineage by sensiflow; "
                    "remove this tag to adopt the PII tag as a declaration.",
                },
            ),
        )
        for lookup, create, payload in probes:
            if self._send(client, "GET", lookup, tolerate=tolerate).status_code != 404:
                continue
            # 409 = created concurrently by another run; either way it now exists.
            self._send(client, "POST", create, body=payload, tolerate=tolerate)

    def _patch_table(
        self,
        client: httpx.Client,
        fqn: str,
        changes: list[TagChange],
        result: ApplyResult,
        ensure_marker: Callable[[], None],
    ) -> None:
        def skip_all(reason: str) -> None:
            result.skipped.extend((c, f"skipped: {reason}") for c in changes)

        if _unsafe_fqn(fqn):
            skip_all("node name is not safe to address in the catalog API")
            return
        try:
            # Re-fetch right before patching: JSON Patch paths are index-based
            # and the plan may be minutes old (ADR-0006 §5).
            table, etag = self._fetch_markup_table(client, fqn)
        except SensiflowConnectionError as exc:
            result.failed.extend((c, str(exc)) for c in changes)
            return
        if table is None:
            skip_all("table no longer exists or does not match the requested name")
            return
        try:
            table_id = str(uuid.UUID(str(table.get("id"))))
        except ValueError:
            skip_all("table entity has no valid id; cannot patch")
            return
        plan = _plan_patch(table, changes)
        result.skipped.extend(plan.skipped)
        if not plan.ops:
            return
        ensure_marker()  # a failure here aborts the run before any tag is written
        try:
            response = self._send(
                client,
                "PATCH",
                f"/tables/{table_id}",
                body=plan.ops,
                content_type=_PATCH_CONTENT_TYPE,
                headers={"If-Match": etag} if etag else None,
                tolerate=frozenset({400, 412}),
            )
            if response.status_code == 412:
                result.skipped.extend(
                    (c, "skipped: table modified concurrently; re-run") for c in plan.patched
                )
                return
            if response.status_code == 400:
                # Fail closed: a rejected patch may be a failed pinned test (concurrent
                # edit) or a real error, and the two cannot be told apart reliably.
                result.failed.extend(
                    (c, "write rejected (possibly concurrent modification)")
                    for c in plan.patched
                )
                return
            self._raise_for_status(response, f"/tables/{table_id}")
        except SensiflowConnectionError as exc:
            result.failed.extend((c, str(exc)) for c in plan.patched)
            return
        result.applied.extend(plan.patched)

    # -- graph construction (ADR-0002 §3) -----------------------------------

    def _walk(
        self,
        client: httpx.Client,
        roots: list[str],
        upstream_depth: int | None,
        downstream_depth: int | None,
    ) -> LineageGraph:
        cache: _EdgeCache = {}
        ancestors, truncated_up = self._expand(client, roots, upstream_depth, cache, direction=_UP)
        descendants, truncated_down = self._expand(
            client, roots, downstream_depth, cache, direction=_DOWN
        )

        nodes: dict[str, Node] = {}
        for fqn in sorted(set(roots) | ancestors | descendants):
            table = self._fetch_table(client, fqn)
            if table is None:
                continue
            upstream = list(self._edges(client, fqn, cache)[_UP])
            node = _node_from_table(table, upstream)
            nodes[node.id] = node

        warnings: list[str] = []
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

    def _expand(
        self,
        client: httpx.Client,
        roots: list[str],
        limit: int | None,
        cache: _EdgeCache,
        *,
        direction: int,
    ) -> tuple[set[str], bool]:
        """BFS in one direction from all roots; returns (reached, truncated)."""
        reached: set[str] = set()
        truncated = False
        seen: set[str] = set(roots)
        frontier: deque[tuple[str, int]] = deque((root, 0) for root in roots)
        while frontier:
            fqn, dist = frontier.popleft()
            neighbors = self._edges(client, fqn, cache)[direction]
            if limit is not None and dist >= limit:
                if any(n not in seen for n in neighbors):
                    truncated = True
                continue
            for neighbor in neighbors:
                if neighbor not in seen:
                    seen.add(neighbor)
                    reached.add(neighbor)
                    frontier.append((neighbor, dist + 1))
        return reached, truncated

    def _full_scan(self, client: httpx.Client) -> LineageGraph:
        cache: _EdgeCache = {}
        tables = self._list_tables(client, fields=_TABLE_FIELDS)
        nodes: dict[str, Node] = {}
        for table in tables:
            fqn = table["fullyQualifiedName"]
            if not self._usable(fqn):
                continue
            upstream = list(self._edges(client, fqn, cache)[_UP])
            node = _node_from_table(table, upstream)
            nodes[node.id] = node
        return LineageGraph(nodes=nodes)

    # -- OMD endpoints -------------------------------------------------------

    def _list_tables(self, client: httpx.Client, *, fields: str | None) -> list[dict[str, Any]]:
        """One paginated pass over /tables; ``fields=None`` keeps the payload light.

        The payload is untrusted: entries that are not mappings or lack a
        non-empty ``fullyQualifiedName`` are skipped, so one malformed catalog
        entry never aborts the listing.
        """
        tables: list[dict[str, Any]] = []
        after: str | None = None
        while True:
            params: dict[str, Any] = {"limit": _PAGE_LIMIT}
            if fields:
                params["fields"] = fields
            if after:
                params["after"] = after
            payload = self._get(client, "/tables", params)
            tables.extend(
                entry
                for entry in payload.get("data") or []
                if isinstance(entry, dict) and entry.get("fullyQualifiedName")
            )
            after = (payload.get("paging") or {}).get("after")
            if not after:
                break
        return tables

    def _fetch_table(self, client: httpx.Client, fqn: str) -> dict[str, Any] | None:
        """The table entity, or ``None`` when it answers to a different name (A7)."""
        table = self._get(client, _name_path("/tables", fqn), {"fields": _TABLE_FIELDS})
        if table.get("fullyQualifiedName") != fqn:
            self._unsafe_names.add(fqn)
            return None
        return table

    def _edges(
        self, client: httpx.Client, fqn: str, cache: _EdgeCache
    ) -> tuple[list[str], list[str]]:
        if fqn in cache:
            return cache[fqn]
        payload = self._get(
            client,
            _name_path("/lineage/table", fqn),
            {"upstreamDepth": 1, "downstreamDepth": 1},
        )
        entity = payload.get("entity") or {}
        entity_id = entity.get("id")
        id_to_fqn: dict[Any, Any] = {entity_id: entity.get("fullyQualifiedName", fqn)}
        for node in payload.get("nodes") or []:
            id_to_fqn[node.get("id")] = node.get("fullyQualifiedName")

        ups = [
            id_to_fqn.get(edge.get("fromEntity"))
            for edge in payload.get("upstreamEdges") or []
            if edge.get("toEntity") == entity_id
        ]
        downs = [
            id_to_fqn.get(edge.get("toEntity"))
            for edge in payload.get("downstreamEdges") or []
            if edge.get("fromEntity") == entity_id
        ]
        cache[fqn] = (
            [u for u in ups if isinstance(u, str) and self._usable(u)],
            [d for d in downs if isinstance(d, str) and self._usable(d)],
        )
        return cache[fqn]

    # -- transport with error mapping (ADR-0002 §5) --------------------------

    def _get(self, client: httpx.Client, path: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._request(client, "GET", path, params=params)

    def _request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        response = self._send(
            client, method, path, params=params, body=body, content_type=content_type
        )
        return self._json(response, path)

    def _json(self, response: httpx.Response, path: str) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError:
            raise SensiflowConnectionError(f"invalid JSON from {self.host} for {path}") from None
        if not isinstance(data, dict):
            raise SensiflowConnectionError(f"unexpected payload shape from {self.host} for {path}")
        return data

    def _send(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
        tolerate: frozenset[int] = frozenset(),
    ) -> httpx.Response:
        """One HTTP call with the shared error mapping.

        Statuses in ``tolerate`` are returned as-is instead of raising (callers
        that treat e.g. 404 / 409 as an answer). Error messages carry host,
        path and status only — never headers or bodies.
        """
        httpx_mod = _require_httpx()
        try:
            if body is None:
                response: httpx.Response = client.request(method, path, params=params)
            else:
                response = client.request(
                    method,
                    path,
                    params=params,
                    content=json.dumps(body),
                    headers={"Content-Type": content_type, **(headers or {})},
                )
        except httpx_mod.HTTPError as exc:
            # `from None`: httpx exceptions can embed the request (headers
            # included) — keep them out of anything a caller might log.
            raise SensiflowConnectionError(
                f"cannot reach OpenMetadata at {self.host}: {type(exc).__name__}"
            ) from None
        if response.status_code not in tolerate:
            self._raise_for_status(response, path)
        return response

    def _raise_for_status(self, response: httpx.Response, path: str) -> None:
        if response.status_code == 401:
            raise SensiflowConnectionError(
                f"authentication failed (401) at {self.host} — check the JWT token"
            )
        if response.status_code >= 400:
            raise SensiflowConnectionError(
                f"OpenMetadata at {self.host} returned {response.status_code} for {path}"
            )
