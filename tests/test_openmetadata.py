"""OpenMetadata connector tests: contract fixtures, walks, depths, errors.

The synthetic catalog lives in tests/fixtures/omd/ (tables.json + edges.json,
synthetic names only). A httpx.MockTransport handler serves it in the shapes
the real OMD v1 API uses: paginated /tables, /tables/name/{fqn}, and the
lineage envelope with entity/nodes/upstreamEdges/downstreamEdges. No network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from sensiflow import (
    GraphSelection,
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowInputError,
    trace,
)
from sensiflow.report import render_text
from sensiflow.sources.openmetadata import OpenMetadataSource, _require_httpx

FIXTURES = Path(__file__).parent / "fixtures" / "omd"
TABLES: list[dict[str, Any]] = json.loads((FIXTURES / "tables.json").read_text())
EDGES: list[dict[str, str]] = json.loads((FIXTURES / "edges.json").read_text())["edges"]
BY_FQN = {t["fullyQualifiedName"]: t for t in TABLES}
PREFIX = "demo.warehouse.crm"
PAGE_SIZE = 3  # forces the full scan through several pages
TOKEN = "fake-jwt-token-123"


def _lineage_payload(fqn: str) -> dict[str, Any]:
    entity = BY_FQN[fqn]
    ups = [e["from"] for e in EDGES if e["to"] == fqn]
    downs = [e["to"] for e in EDGES if e["from"] == fqn]
    return {
        "entity": {"id": entity["id"], "fullyQualifiedName": fqn, "type": "table"},
        "nodes": [
            {"id": BY_FQN[n]["id"], "fullyQualifiedName": n, "type": "table"}
            for n in ups + downs
        ],
        "upstreamEdges": [
            {"fromEntity": BY_FQN[u]["id"], "toEntity": entity["id"]} for u in ups
        ],
        "downstreamEdges": [
            {"fromEntity": entity["id"], "toEntity": BY_FQN[d]["id"]} for d in downs
        ],
    }


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/api/v1/tables":
        start = int(request.url.params.get("after") or 0)
        page = TABLES[start : start + PAGE_SIZE]
        paging: dict[str, str] = {}
        if start + PAGE_SIZE < len(TABLES):
            paging["after"] = str(start + PAGE_SIZE)
        return httpx.Response(200, json={"data": page, "paging": paging})
    if path.startswith("/api/v1/tables/name/"):
        fqn = path.removeprefix("/api/v1/tables/name/")
        if fqn not in BY_FQN:
            return httpx.Response(404, json={"message": "table instance not found"})
        return httpx.Response(200, json=BY_FQN[fqn])
    if path.startswith("/api/v1/lineage/table/name/"):
        fqn = path.removeprefix("/api/v1/lineage/table/name/")
        if fqn not in BY_FQN:
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(200, json=_lineage_payload(fqn))
    return httpx.Response(404, json={})


def make_source(handler: Any = _handler) -> OpenMetadataSource:
    return OpenMetadataSource(
        "http://omd.test", TOKEN, transport=httpx.MockTransport(handler)
    )


# --- full scan ---------------------------------------------------------------


def test_full_scan_builds_all_nodes_through_pagination() -> None:
    graph = make_source().build_graph()
    assert len(graph.nodes) == 7  # PAGE_SIZE=3 -> three pages were followed
    dim = graph.nodes[f"{PREFIX}.dim_customers"]
    assert dim.upstream == [f"{PREFIX}.stg_customers"]


def test_pii_tags_map_onto_declared_pii() -> None:
    graph = make_source().build_graph()
    raw = graph.nodes[f"{PREFIX}.raw_customers"]
    assert set(raw.declared_pii) == {"email", "phone", "full_name"}
    assert all(t.category == "pii" and t.sensitive for t in raw.declared_pii.values())
    assert graph.nodes[f"{PREFIX}.raw_orders"].declared_pii == {}


def test_owners_and_sql_are_mapped() -> None:
    graph = make_source().build_graph()
    stg = graph.nodes[f"{PREFIX}.stg_customers"]
    assert stg.owners == ["core-data@example.com"]
    assert stg.sql is not None and "FROM raw_customers" in stg.sql
    assert graph.nodes[f"{PREFIX}.raw_customers"].sql is None


# --- root walks (ADR-0002 §3) -------------------------------------------------


def test_root_walk_collects_ancestors_and_descendants() -> None:
    graph = make_source().build_graph(GraphSelection(roots=(f"{PREFIX}.mart_customer_dump",)))
    assert set(graph.nodes) == {
        f"{PREFIX}.mart_customer_dump",
        f"{PREFIX}.dim_customers",
        f"{PREFIX}.stg_customers",
        f"{PREFIX}.raw_customers",
    }
    assert graph.warnings == []


def test_root_downstream_walk_excludes_unrelated_sources() -> None:
    graph = make_source().build_graph(GraphSelection(roots=(f"{PREFIX}.raw_customers",)))
    assert f"{PREFIX}.mart_daily_revenue" in graph.nodes
    assert f"{PREFIX}.raw_orders" not in graph.nodes  # cousin, not a descendant


def test_multiple_roots_union_and_dedupe() -> None:
    graph = make_source().build_graph(
        GraphSelection(
            roots=(f"{PREFIX}.mart_customer_dump", f"{PREFIX}.mart_daily_revenue")
        )
    )
    # Shared ancestors appear once; both closures are present.
    assert f"{PREFIX}.raw_customers" in graph.nodes
    assert f"{PREFIX}.raw_orders" in graph.nodes
    assert len(graph.nodes) == 7


# --- depth limits and warnings ------------------------------------------------


def test_upstream_truncation_without_seeds_warns_hard() -> None:
    graph = make_source().build_graph(
        GraphSelection(roots=(f"{PREFIX}.mart_customer_dump",), upstream_depth=1)
    )
    assert set(graph.nodes) == {
        f"{PREFIX}.mart_customer_dump",
        f"{PREFIX}.dim_customers",
    }
    assert any("upstream truncated" in w for w in graph.warnings)
    # The engine keeps the warning and adds its own no-seeds one.
    result = trace(graph)
    assert any("upstream truncated" in w for w in result.warnings)
    assert any("no PII seeds" in w for w in result.warnings)
    assert "warning:" in render_text(result)


def test_downstream_zero_disables_direction_with_mild_note() -> None:
    graph = make_source().build_graph(
        GraphSelection(roots=(f"{PREFIX}.raw_customers",), downstream_depth=0)
    )
    assert set(graph.nodes) == {f"{PREFIX}.raw_customers"}
    assert any("downstream truncated" in w for w in graph.warnings)
    assert not any("upstream truncated" in w for w in graph.warnings)  # seeds present


def test_deep_enough_limit_produces_no_warnings() -> None:
    graph = make_source().build_graph(
        GraphSelection(
            roots=(f"{PREFIX}.mart_customer_dump",),
            upstream_depth=3,
            downstream_depth=5,
        )
    )
    assert graph.warnings == []
    assert f"{PREFIX}.raw_customers" in graph.nodes


# --- root selectors (ADR-0002 amendment: one listing pass, then the walk) -------


def recording_source() -> tuple[OpenMetadataSource, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _handler(request)

    return make_source(handler), requests


def test_exact_roots_keep_the_listing_free_path() -> None:
    source, requests = recording_source()
    source.build_graph(GraphSelection(roots=(f"{PREFIX}.mart_customer_dump",)))
    assert all(r.url.path != "/api/v1/tables" for r in requests)


def test_pattern_resolves_via_one_light_listing_pass() -> None:
    source, requests = recording_source()
    graph = source.build_graph(GraphSelection(patterns=("mart_customer_*",)))
    assert set(graph.nodes) == {
        f"{PREFIX}.mart_customer_dump",
        f"{PREFIX}.dim_customers",
        f"{PREFIX}.stg_customers",
        f"{PREFIX}.raw_customers",
    }
    listing = [r for r in requests if r.url.path == "/api/v1/tables"]
    assert len(listing) == 3  # PAGE_SIZE=3 over 7 tables -> exactly one pass
    assert all("fields" not in r.url.params for r in listing)  # names only


def test_pattern_matches_fqns_too() -> None:
    graph = make_source().build_graph(GraphSelection(patterns=(f"{PREFIX}.raw_*",)))
    assert len(graph.nodes) == 7  # both raw tables plus their joint closure


def test_pattern_matching_nothing_is_hard_error() -> None:
    with pytest.raises(SensiflowInputError, match="'nothing_\\*' matched no tables"):
        make_source().build_graph(GraphSelection(patterns=("nothing_*",)))


def test_from_seeds_lists_with_column_tags_then_walks() -> None:
    source, requests = recording_source()
    graph = source.build_graph(GraphSelection(from_seeds=True))
    # Only raw_customers is PII-tagged; its closure excludes the cousin source.
    assert set(graph.nodes) == {
        f"{PREFIX}.raw_customers",
        f"{PREFIX}.stg_customers",
        f"{PREFIX}.dim_customers",
        f"{PREFIX}.mart_orders_enriched",
        f"{PREFIX}.mart_customer_dump",
        f"{PREFIX}.mart_daily_revenue",
    }
    listing = [r for r in requests if r.url.path == "/api/v1/tables"]
    assert listing and all(
        r.url.params["fields"] == "columns,tags" for r in listing
    )  # markup must be visible on the listing pass


def test_from_seeds_depths_flow_into_the_walk() -> None:
    graph = make_source().build_graph(
        GraphSelection(from_seeds=True, downstream_depth=1)
    )
    assert set(graph.nodes) == {f"{PREFIX}.raw_customers", f"{PREFIX}.stg_customers"}
    assert any("downstream truncated" in w for w in graph.warnings)


def test_from_seeds_without_any_pii_tags_is_input_error() -> None:
    untagged = json.loads(json.dumps(TABLES))  # deep copy of the fixture
    for table in untagged:
        for column in table["columns"]:
            column["tags"] = []

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("after") or 0)
        page = untagged[start : start + PAGE_SIZE]
        paging: dict[str, str] = {}
        if start + PAGE_SIZE < len(untagged):
            paging["after"] = str(start + PAGE_SIZE)
        return httpx.Response(200, json={"data": page, "paging": paging})

    with pytest.raises(SensiflowInputError, match="no PII-tagged"):
        make_source(handler).build_graph(GraphSelection(from_seeds=True))


# --- end to end through the engine ---------------------------------------------


def test_trace_over_fetched_graph_matches_risk_semantics() -> None:
    result = trace(make_source().build_graph())
    nodes = result.nodes
    assert nodes[f"{PREFIX}.mart_orders_enriched"].max_risk == "HIGH"
    high = nodes[f"{PREFIX}.mart_orders_enriched"].findings["email"]
    assert high.origin_node == f"{PREFIX}.raw_customers"
    assert nodes[f"{PREFIX}.mart_customer_dump"].max_risk == "LOW"
    assert nodes[f"{PREFIX}.mart_daily_revenue"].max_risk == "NONE"


# --- errors and hygiene ---------------------------------------------------------


def test_401_maps_to_connection_error_without_token() -> None:
    def unauthorized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Not authorized"})

    with pytest.raises(SensiflowConnectionError) as excinfo:
        make_source(unauthorized).build_graph()
    message = str(excinfo.value)
    assert "401" in message
    assert TOKEN not in message


def test_unknown_root_maps_to_connection_error() -> None:
    with pytest.raises(SensiflowConnectionError, match="404"):
        make_source().build_graph(GraphSelection(roots=(f"{PREFIX}.no_such_table",)))


def test_network_failure_message_has_no_request_details() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with pytest.raises(SensiflowConnectionError) as excinfo:
        make_source(broken).build_graph()
    assert TOKEN not in str(excinfo.value)
    assert excinfo.value.__cause__ is None  # original exception dropped on purpose


def test_repr_never_contains_token() -> None:
    assert TOKEN not in repr(make_source())


def test_missing_httpx_raises_dependency_error() -> None:
    def failing_import(name: str) -> Any:
        raise ImportError(name)

    with pytest.raises(SensiflowDependencyError, match=r"sensiflow\[openmetadata\]"):
        _require_httpx(import_module=failing_import)
