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
from collections import deque
from collections.abc import Callable, Sequence
from types import ModuleType
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sensiflow.exceptions import (
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowInputError,
)
from sensiflow.model import LineageGraph, Node, PiiTag
from sensiflow.root_selectors import GraphSelection, resolve_patterns
from sensiflow.sources.base import ExistingTag
from sensiflow.writeback import ApplyResult, TagChange

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


def _existing_tag(column: dict[str, Any]) -> ExistingTag | None:
    """The PII markup on one OMD column in the neutral write-back shape.

    ``managed`` iff the marker tag is present. Sensitive wins when a column
    carries both PII labels (the conservative reading).
    """
    fqns = _tag_fqns(column)
    if _PII_SENSITIVE in fqns:
        sensitive = True
    elif _PII_NON_SENSITIVE in fqns:
        sensitive = False
    else:
        return None
    return ExistingTag(
        tag=PiiTag(category="pii", sensitive=sensitive), managed=MARKER_TAG in fqns
    )


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


def _plan_patch(
    table: dict[str, Any], changes: list[TagChange]
) -> tuple[list[dict[str, Any]], list[TagChange], list[tuple[TagChange, str]]]:
    """JSON Patch operations for one table, verified against its live state.

    Returns ``(operations, patched changes, skipped changes with reasons)``.
    """
    columns = table.get("columns") or []
    index_of = {
        name.lower(): position
        for position, column in enumerate(columns)
        if isinstance(column, dict) and isinstance(name := column.get("name"), str)
    }
    ops: list[dict[str, Any]] = []
    patched: list[TagChange] = []
    skipped: list[tuple[TagChange, str]] = []
    for change in changes:
        position = index_of.get(change.column.lower())
        if position is None:
            skipped.append((change, "skipped: column no longer exists in the table"))
            continue
        column = columns[position]
        live = _existing_tag(column)
        label = _tag_label(_PII_SENSITIVE if change.tag.sensitive else _PII_NON_SENSITIVE)
        base = f"/columns/{position}/tags"
        if live is not None and not live.managed:
            skipped.append((change, "skipped: a human-placed PII tag appeared since the diff"))
        elif live is not None and live.tag.sensitive == change.tag.sensitive:
            skipped.append((change, "skipped: the column already carries this managed tag"))
        elif live is not None:
            fqns = _tag_fqns(column)
            slot = next(i for i, fqn in enumerate(fqns) if fqn in _PII_FQNS)
            ops.append({"op": "replace", "path": f"{base}/{slot}", "value": label})
            patched.append(change)
        else:
            labels = [label]
            if MARKER_TAG not in _tag_fqns(column):
                labels.append(_tag_label(MARKER_TAG))
            if isinstance(column.get("tags"), list):
                ops.extend({"op": "add", "path": f"{base}/-", "value": lbl} for lbl in labels)
            else:
                ops.append({"op": "add", "path": base, "value": labels})
            patched.append(change)
    return ops, patched, skipped


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
        try:
            if selection is None or selection.is_full_scan():
                return self._full_scan(client)
            return self._walk(
                client,
                self._resolve_selection(client, selection),
                selection.upstream_depth,
                selection.downstream_depth,
            )
        finally:
            client.close()

    def _resolve_selection(
        self, client: httpx.Client, selection: GraphSelection
    ) -> list[str]:
        """Resolve the selection to concrete root FQNs (ADR-0002 amendment A5).

        Exact roots keep the listing-free path. Patterns and from-seeds cost
        one paginated pass over /tables (from-seeds with ``fields=columns,tags``
        so PII markup is visible); the lineage walk then fetches only the
        matched closures.
        """
        if selection.from_seeds:
            tables = self._list_tables(client, fields="columns,tags")
            seeded = sorted(
                table["fullyQualifiedName"] for table in tables if _declared_pii(table)
            )
            if not seeded:
                raise SensiflowInputError(
                    f"--roots-from-seeds found no PII-tagged tables at {self.host}; "
                    "sensiflow needs declared PII markup to trace from "
                    "(ADR-0001 applicability precondition)"
                )
            return seeded
        resolved = list(selection.roots)
        if selection.patterns:
            candidates = [
                (table["fullyQualifiedName"], table.get("name") or "")
                for table in self._list_tables(client, fields=None)
            ]
            resolved.extend(resolve_patterns(selection.patterns, candidates))
        # One node matched by several selectors appears once (A2).
        return list(dict.fromkeys(resolved))

    # -- WritebackTarget (ADR-0006 §3, §5) ------------------------------------

    def read_markup(self, node_ids: Sequence[str]) -> dict[tuple[str, str], ExistingTag]:
        """PII markup per column; managed iff the sensiflow marker is present."""
        client = self._open_client()
        try:
            markup: dict[tuple[str, str], ExistingTag] = {}
            for fqn in node_ids:
                table = self._fetch_markup_table(client, fqn)
                for name, column in _columns_of(table or {}):
                    existing = _existing_tag(column)
                    if existing is not None:
                        markup[(fqn, name.lower())] = existing
            return markup
        finally:
            client.close()

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[tuple[str, str], str]:
        """Planned columns missing from the live table schema (e.g. JOIN-only findings)."""
        client = self._open_client()
        try:
            unmatched: dict[tuple[str, str], str] = {}
            for fqn, node_changes in _group_by_node(changes).items():
                table = self._fetch_markup_table(client, fqn)
                names = {name.lower() for name, _ in _columns_of(table or {})}
                for change in node_changes:
                    key = (fqn, change.column.lower())
                    if table is None:
                        unmatched[key] = "table not found in OpenMetadata"
                    elif key[1] not in names:
                        unmatched[key] = (
                            "column is not in the table's schema in OpenMetadata "
                            "(e.g. referenced only in JOIN/WHERE)"
                        )
            return unmatched
        finally:
            client.close()

    def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
        """Append TagLabels with one JSON Patch per table, re-verified against live state.

        The marker classification/tag is created idempotently first. A failed
        PATCH fails only that table's changes; changes the live re-check
        reclassifies (column gone, a human tag appeared) are skipped and
        reported in ``failed`` with a ``skipped:`` message, never forced.
        """
        result = ApplyResult(applied=[], failed=[])
        if not changes:
            return result
        client = self._open_client()
        try:
            self._ensure_marker(client)
            for fqn, table_changes in _group_by_node(changes).items():
                self._patch_table(client, fqn, table_changes, result)
        finally:
            client.close()
        return result

    def _fetch_markup_table(self, client: httpx.Client, fqn: str) -> dict[str, Any] | None:
        """The table with ``fields=columns,tags``; ``None`` when it no longer exists."""
        path = f"/tables/name/{fqn}"
        response = self._send(
            client, "GET", path, params={"fields": "columns,tags"}, tolerate=frozenset({404})
        )
        if response.status_code == 404:
            return None
        return self._json(response, path)

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
    ) -> None:
        try:
            # Re-fetch right before patching: JSON Patch paths are index-based
            # and the plan may be minutes old (ADR-0006 §5).
            table = self._fetch_markup_table(client, fqn)
            if table is None:
                result.failed.extend((c, "skipped: table no longer exists") for c in changes)
                return
            table_id = table.get("id")
            if not isinstance(table_id, str) or not table_id:
                result.failed.extend((c, "table entity has no id; cannot patch") for c in changes)
                return
            ops, patched, skipped = _plan_patch(table, changes)
            result.failed.extend(skipped)
            if ops:
                self._request(
                    client,
                    "PATCH",
                    f"/tables/{table_id}",
                    body=ops,
                    content_type=_PATCH_CONTENT_TYPE,
                )
        except SensiflowConnectionError as exc:
            # Only this table's not-yet-reported changes fail; other tables proceed.
            reported = {id(change) for change, _ in result.failed}
            result.failed.extend((c, str(exc)) for c in changes if id(c) not in reported)
            return
        result.applied.extend(patched)

    # -- graph construction (ADR-0002 §3) -----------------------------------

    def _walk(
        self,
        client: httpx.Client,
        roots: list[str],
        upstream_depth: int | None,
        downstream_depth: int | None,
    ) -> LineageGraph:
        cache: _EdgeCache = {}
        ancestors, truncated_up = self._expand(
            client, roots, upstream_depth, cache, direction=_UP
        )
        descendants, truncated_down = self._expand(
            client, roots, downstream_depth, cache, direction=_DOWN
        )

        nodes: dict[str, Node] = {}
        for fqn in sorted(set(roots) | ancestors | descendants):
            table = self._fetch_table(client, fqn)
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
            upstream = list(self._edges(client, fqn, cache)[_UP])
            node = _node_from_table(table, upstream)
            nodes[node.id] = node
        return LineageGraph(nodes=nodes)

    # -- OMD endpoints -------------------------------------------------------

    def _list_tables(
        self, client: httpx.Client, *, fields: str | None
    ) -> list[dict[str, Any]]:
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

    def _fetch_table(
        self, client: httpx.Client, fqn: str, fields: str = _TABLE_FIELDS
    ) -> dict[str, Any]:
        return self._get(client, f"/tables/name/{fqn}", {"fields": fields})

    def _edges(
        self, client: httpx.Client, fqn: str, cache: _EdgeCache
    ) -> tuple[list[str], list[str]]:
        if fqn in cache:
            return cache[fqn]
        payload = self._get(
            client,
            f"/lineage/table/name/{fqn}",
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
        cache[fqn] = ([u for u in ups if u], [d for d in downs if d])
        return cache[fqn]

    # -- transport with error mapping (ADR-0002 §5) --------------------------

    def _get(
        self, client: httpx.Client, path: str, params: dict[str, Any]
    ) -> dict[str, Any]:
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
            data: dict[str, Any] = response.json()
        except ValueError:
            raise SensiflowConnectionError(
                f"invalid JSON from {self.host} for {path}"
            ) from None
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
                    headers={"Content-Type": content_type},
                )
        except httpx_mod.HTTPError as exc:
            # `from None`: httpx exceptions can embed the request (headers
            # included) — keep them out of anything a caller might log.
            raise SensiflowConnectionError(
                f"cannot reach OpenMetadata at {self.host}: {type(exc).__name__}"
            ) from None
        if response.status_code in tolerate:
            return response
        if response.status_code == 401:
            raise SensiflowConnectionError(
                f"authentication failed (401) at {self.host} — check the JWT token"
            )
        if response.status_code >= 400:
            raise SensiflowConnectionError(
                f"OpenMetadata at {self.host} returned {response.status_code} for {path}"
            )
        return response
