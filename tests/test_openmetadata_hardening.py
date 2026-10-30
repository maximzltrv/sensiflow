"""OpenMetadata connector input hardening (ADR-0005 verification fixes).

Table names are spliced into request paths, so hostile names must be refused
(roots) or skipped (catalog-returned) before any URL is built, and the names
that do pass must travel percent-encoded as one path segment.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest

from sensiflow import GraphSelection, SensiflowInputError
from sensiflow.sources.openmetadata import OpenMetadataSource, _fqn_problem, _validate_fqn
from tests.test_openmetadata import PREFIX, TOKEN, _handler, make_source

HOSTILE = [
    "",
    "a/b",
    "a\\b",
    "a?x=1",
    "a#frag",
    "a%2fb",
    "a;b",
    "a\nb",
    "a\x00b",
    "a\x7fb",
    ".",
    "..",
    "a..b",
    "../etc",
]


@pytest.mark.parametrize("fqn", HOSTILE)
def test_validate_fqn_rejects_hostile_names(fqn: str) -> None:
    with pytest.raises(SensiflowInputError):
        _validate_fqn(fqn)


@pytest.mark.parametrize(
    "fqn", [f"{PREFIX}.mart_customer_dump", 'svc."quoted.name".t', "svc.db.schema.tbl 1", "a.b-c_d"]
)
def test_validate_fqn_accepts_ordinary_names(fqn: str) -> None:
    assert _validate_fqn(fqn) == fqn
    assert _fqn_problem(fqn) is None


@pytest.mark.parametrize("fqn", ["a/b", "a?x=1", "a#frag", "a%2fb", "a\nb", ".."])
def test_hostile_root_is_rejected_before_any_request(fqn: str) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _handler(request)

    with pytest.raises(SensiflowInputError):
        make_source(handler).build_graph(GraphSelection(roots=(fqn,)))
    assert requests == []


def test_control_characters_in_a_pattern_are_rejected_by_the_selection() -> None:
    with pytest.raises(SensiflowInputError, match="control characters"):
        GraphSelection(patterns=("mart_*\n",))
    with pytest.raises(SensiflowInputError, match="control characters"):
        GraphSelection(roots=("mart\n",))


def test_fqn_is_percent_encoded_as_a_single_path_segment() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        return httpx.Response(404, json={})

    odd = 'svc.db."a b".t'
    source = OpenMetadataSource("http://omd.test", TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(Exception, match="404"):
        source.build_graph(GraphSelection(roots=(odd,)))
    assert seen
    assert all("%22a%20b%22" in path for path in seen)
    assert all(" " not in path and '"' not in path for path in seen)


def test_catalog_returned_hostile_fqns_are_skipped_not_fatal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    root = f"{PREFIX}.mart_customer_dump"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        response = _handler(request)
        if request.url.path.startswith("/api/v1/lineage/table/name/") and response.is_success:
            payload: dict[str, Any] = response.json()
            entity_id = payload["entity"]["id"]
            payload["nodes"].append({"id": "evil", "fullyQualifiedName": "x/../../admin"})
            payload["upstreamEdges"].append({"fromEntity": "evil", "toEntity": entity_id})
            return httpx.Response(200, json=payload)
        return response

    with caplog.at_level(logging.DEBUG, logger="sensiflow.sources.openmetadata"):
        graph = make_source(handler).build_graph(GraphSelection(roots=(root,)))
    assert root in graph.nodes
    assert not any("admin" in path for path in requests)
    assert any("skipping catalog entry" in r.getMessage() for r in caplog.records)
    assert "x/../../admin" not in caplog.text


def test_invalid_url_from_httpx_is_an_input_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.InvalidURL("bad")

    source = OpenMetadataSource("http://omd.test", TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(SensiflowInputError) as excinfo:
        source.build_graph(GraphSelection(roots=(f"{PREFIX}.mart_customer_dump",)))
    assert "omd.test" not in str(excinfo.value)


def test_from_seeds_failure_message_does_not_name_the_host() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [], "paging": {}})

    source = OpenMetadataSource("http://omd.test", TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(SensiflowInputError) as excinfo:
        source.build_graph(GraphSelection(from_seeds=True))
    assert "omd.test" not in str(excinfo.value)
