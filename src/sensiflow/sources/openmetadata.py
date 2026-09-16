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
from collections import deque
from collections.abc import Callable, Sequence
from types import ModuleType
from typing import TYPE_CHECKING, Any

from sensiflow.exceptions import SensiflowConnectionError, SensiflowDependencyError
from sensiflow.model import LineageGraph, Node, PiiTag

if TYPE_CHECKING:
    import httpx

_TABLE_FIELDS = "columns,tags,owners"
_PAGE_LIMIT = 100
_UP, _DOWN = 0, 1

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


def _node_from_table(table: dict[str, Any], upstream: list[str]) -> Node:
    """Map an OMD table entity onto a sensiflow Node (ADR-0002 §3-§4)."""
    declared: dict[str, PiiTag] = {}
    for column in table.get("columns") or []:
        for tag in column.get("tags") or []:
            tag_fqn = tag.get("tagFQN", "")
            if tag_fqn == "PII.Sensitive":
                declared[column["name"]] = PiiTag(category="pii", sensitive=True)
            elif tag_fqn == "PII.NonSensitive":
                declared[column["name"]] = PiiTag(category="pii", sensitive=False)

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
        declared_pii=declared,
    )


class OpenMetadataSource:
    """Read-only LineageSource over the OpenMetadata REST API."""

    def __init__(
        self,
        host: str,
        jwt_token: str,
        *,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.host = host.rstrip("/")
        self._token = jwt_token
        self._timeout = timeout
        self._transport = transport  # injection point for tests (MockTransport)

    def __repr__(self) -> str:
        return f"OpenMetadataSource(host={self.host!r})"

    # -- public API ---------------------------------------------------------

    def build_graph(
        self,
        roots: Sequence[str] | None = None,
        *,
        upstream_depth: int | None = None,
        downstream_depth: int | None = None,
    ) -> LineageGraph:
        httpx_mod = _require_httpx()
        client = httpx_mod.Client(
            base_url=f"{self.host}/api/v1",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=self._timeout,
            transport=self._transport,
        )
        try:
            if roots:
                return self._walk(client, list(roots), upstream_depth, downstream_depth)
            return self._full_scan(client)
        finally:
            client.close()

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
        tables: list[dict[str, Any]] = []
        after: str | None = None
        while True:
            params: dict[str, Any] = {"fields": _TABLE_FIELDS, "limit": _PAGE_LIMIT}
            if after:
                params["after"] = after
            payload = self._get(client, "/tables", params)
            tables.extend(payload.get("data") or [])
            after = (payload.get("paging") or {}).get("after")
            if not after:
                break

        nodes: dict[str, Node] = {}
        for table in tables:
            fqn = table["fullyQualifiedName"]
            upstream = list(self._edges(client, fqn, cache)[_UP])
            node = _node_from_table(table, upstream)
            nodes[node.id] = node
        return LineageGraph(nodes=nodes)

    # -- OMD endpoints -------------------------------------------------------

    def _fetch_table(self, client: httpx.Client, fqn: str) -> dict[str, Any]:
        return self._get(client, f"/tables/name/{fqn}", {"fields": _TABLE_FIELDS})

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
        httpx_mod = _require_httpx()
        try:
            response = client.get(path, params=params)
        except httpx_mod.HTTPError as exc:
            # `from None`: httpx exceptions can embed the request (headers
            # included) — keep them out of anything a caller might log.
            raise SensiflowConnectionError(
                f"cannot reach OpenMetadata at {self.host}: {type(exc).__name__}"
            ) from None
        if response.status_code == 401:
            raise SensiflowConnectionError(
                f"authentication failed (401) at {self.host} — check the JWT token"
            )
        if response.status_code >= 400:
            raise SensiflowConnectionError(
                f"OpenMetadata at {self.host} returned {response.status_code} for {path}"
            )
        try:
            data: dict[str, Any] = response.json()
        except ValueError:
            raise SensiflowConnectionError(
                f"invalid JSON from {self.host} for {path}"
            ) from None
        return data
