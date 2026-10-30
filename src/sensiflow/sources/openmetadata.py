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
import logging
from collections import deque
from collections.abc import Callable
from types import ModuleType
from typing import TYPE_CHECKING, Any, TypeGuard
from urllib.parse import quote, urlsplit

from sensiflow.exceptions import (
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowInputError,
)
from sensiflow.model import LineageGraph, Node, PiiTag
from sensiflow.root_selectors import GraphSelection, resolve_patterns

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)

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


def _declared_pii(table: dict[str, Any]) -> dict[str, PiiTag]:
    """Columns of an OMD table entity carrying a PII.* tag (ADR-0002 §4)."""
    declared: dict[str, PiiTag] = {}
    for column in table.get("columns") or []:
        for tag in column.get("tags") or []:
            tag_fqn = tag.get("tagFQN", "")
            if tag_fqn == "PII.Sensitive":
                declared[column["name"]] = PiiTag(category="pii", sensitive=True)
            elif tag_fqn == "PII.NonSensitive":
                declared[column["name"]] = PiiTag(category="pii", sensitive=False)
    return declared


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


def _fqn_problem(fqn: str) -> str | None:
    """Why ``fqn`` cannot be spliced into a request path, or None when it is safe.

    FQNs travel as a single path segment, so anything that would change the
    URL's structure (separators, query/fragment markers, escape sequences,
    dot-segments) or smuggle control characters is refused outright.
    """
    if not fqn:
        return "it is empty"
    for ch in fqn:
        if ch in "/\\?#%;" or ord(ch) < 0x20 or ord(ch) == 0x7F:
            return "it contains a character that is not allowed in a table name"
    if fqn == "." or ".." in fqn:
        return "it contains a dot-segment"
    return None


def _validate_fqn(fqn: str) -> str:
    """Return ``fqn`` unchanged or raise SensiflowInputError (never echoes control chars)."""
    problem = _fqn_problem(fqn)
    if problem is not None:
        raise SensiflowInputError(f"invalid table name {fqn!r}: {problem}")
    return fqn


def _usable_fqn(fqn: object) -> TypeGuard[str]:
    """Catalog-returned FQNs are untrusted: unsafe ones are skipped, not fatal."""
    if not isinstance(fqn, str):
        return False
    problem = _fqn_problem(fqn)
    if problem is not None:
        logger.debug("skipping catalog entry with an unusable table name (%s)", problem)
        return False
    return True


def _has_userinfo(host: str) -> bool:
    try:
        parts = urlsplit(host)
    except ValueError:
        return False
    return "@" in parts.netloc


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

    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
        httpx_mod = _require_httpx()
        client = httpx_mod.Client(
            base_url=f"{self.host}/api/v1",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=self._timeout,
            transport=self._transport,
        )
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
                table["fullyQualifiedName"]
                for table in tables
                if _declared_pii(table) and _usable_fqn(table["fullyQualifiedName"])
            )
            if not seeded:
                raise SensiflowInputError(
                    "--roots-from-seeds found no PII-tagged tables in the catalog; "
                    "sensiflow needs declared PII markup to trace from "
                    "(ADR-0001 applicability precondition)"
                )
            return seeded
        resolved = [_validate_fqn(root) for root in selection.roots]
        if selection.patterns:
            candidates = [
                (table["fullyQualifiedName"], table.get("name") or "")
                for table in self._list_tables(client, fields=None)
                if _usable_fqn(table["fullyQualifiedName"])
            ]
            resolved.extend(resolve_patterns(selection.patterns, candidates))
        # One node matched by several selectors appears once (A2).
        return list(dict.fromkeys(resolved))

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
            if not _usable_fqn(fqn):
                continue
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

    def _fetch_table(self, client: httpx.Client, fqn: str) -> dict[str, Any]:
        return self._get(client, f"/tables/name/{quote(fqn, safe='')}", {"fields": _TABLE_FIELDS})

    def _edges(
        self, client: httpx.Client, fqn: str, cache: _EdgeCache
    ) -> tuple[list[str], list[str]]:
        if fqn in cache:
            return cache[fqn]
        payload = self._get(
            client,
            f"/lineage/table/name/{quote(fqn, safe='')}",
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
            [u for u in ups if _usable_fqn(u)],
            [d for d in downs if _usable_fqn(d)],
        )
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
        except httpx_mod.InvalidURL:
            raise SensiflowInputError("a table name produced an invalid request URL") from None
        if response.status_code == 401:
            raise SensiflowConnectionError(
                f"authentication failed (401) at {self.host} — check the JWT token"
            )
        if response.status_code >= 400:
            raise SensiflowConnectionError(
                f"OpenMetadata at {self.host} returned {response.status_code}"
            )
        try:
            data: dict[str, Any] = response.json()
        except ValueError:
            raise SensiflowConnectionError(
                f"invalid JSON from {self.host}"
            ) from None
        return data
