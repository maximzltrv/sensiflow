"""dbt connector tests: manifest mapping, scoping, errors, end-to-end trace.

The synthetic manifest fixture (tests/fixtures/dbt/manifest.json) mirrors the
mock graph and adds edge cases: a jinja-only model (raw_code that cannot
parse), a seed, a test node (must be skipped), and every owner convention.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sensiflow import SensiflowInputError, trace
from sensiflow.cli import main
from sensiflow.sources.dbt import DbtSource

MANIFEST = Path(__file__).parent / "fixtures" / "dbt" / "manifest.json"
P = "demo_shop"
RAW_CUSTOMERS = f"source.{P}.crm.raw_customers"
STG = f"model.{P}.stg_customers"
DIM = f"model.{P}.dim_customers"
ENRICHED = f"model.{P}.mart_orders_enriched"
DUMP = f"model.{P}.mart_customer_dump"
DAILY = f"model.{P}.mart_daily_revenue"
RAW_ONLY = f"model.{P}.mart_raw_only"


def source() -> DbtSource:
    return DbtSource(MANIFEST)


# --- manifest mapping ---------------------------------------------------------


def test_vertices_models_seeds_sources_but_not_tests() -> None:
    graph = source().build_graph()
    assert len(graph.nodes) == 9  # 6 models + 1 seed + 2 sources
    assert f"seed.{P}.country_codes" in graph.nodes
    assert f"test.{P}.not_null_stg_customers_email" not in graph.nodes


def test_edges_come_from_depends_on() -> None:
    graph = source().build_graph()
    assert graph.nodes[STG].upstream == [RAW_CUSTOMERS]
    assert set(graph.nodes[ENRICHED].upstream) == {DIM, f"source.{P}.crm.raw_orders"}


def test_compiled_code_preferred_over_raw_code() -> None:
    graph = source().build_graph()
    sql = graph.nodes[STG].sql
    assert sql is not None
    assert "FROM raw_customers" in sql  # compiled, not the jinja raw_code
    assert "{{" not in sql


def test_raw_code_fallback_when_no_compiled() -> None:
    graph = source().build_graph()
    sql = graph.nodes[RAW_ONLY].sql
    assert sql is not None and "{{ ref(" in sql  # jinja survives; parsing will fail


def test_pii_seeds_from_meta_and_tags() -> None:
    declared = source().build_graph().nodes[RAW_CUSTOMERS].declared_pii
    assert declared["email"].category == "email" and declared["email"].sensitive
    assert declared["phone"].category == "phone"
    assert declared["full_name"].category == "name"  # from tag "pii:name"
    assert "customer_id" not in declared


def test_owner_conventions() -> None:
    nodes = source().build_graph().nodes
    assert nodes[STG].owners == ["core-data@example.com"]  # config.meta.owner str
    assert nodes[DIM].owners == ["analytics@example.com", "governance@example.com"]  # list
    assert nodes[RAW_CUSTOMERS].owners == ["core-data@example.com"]  # source meta.owner
    assert nodes[DUMP].owners == ["marketing"]  # group fallback
    assert nodes[RAW_ONLY].owners == []  # nothing declared


# --- scoping (shared graph_scope helper through the connector) -----------------


def test_root_by_unique_id_scopes_to_closure() -> None:
    graph = source().build_graph([DUMP])
    assert set(graph.nodes) == {DUMP, DIM, STG, RAW_CUSTOMERS}
    assert graph.warnings == []


def test_root_by_bare_name_resolves() -> None:
    graph = source().build_graph(["mart_customer_dump"])
    assert DUMP in graph.nodes and len(graph.nodes) == 4


def test_unknown_root_raises_input_error() -> None:
    with pytest.raises(SensiflowInputError, match="unknown root"):
        source().build_graph(["no_such_model"])


def test_ambiguous_root_lists_matches(tmp_path: Path) -> None:
    manifest: dict[str, Any] = {
        "nodes": {},
        "sources": {
            "source.p.a.dup": {"resource_type": "source", "name": "dup"},
            "source.p.b.dup": {"resource_type": "source", "name": "dup"},
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(SensiflowInputError, match="ambiguous root 'dup'"):
        DbtSource(path).build_graph(["dup"])


def test_upstream_truncation_without_seeds_warns_hard() -> None:
    graph = source().build_graph([DUMP], upstream_depth=1)
    assert set(graph.nodes) == {DUMP, DIM}
    assert any("upstream truncated" in w for w in graph.warnings)


def test_downstream_zero_with_seeds_gives_mild_note_only() -> None:
    graph = source().build_graph([RAW_CUSTOMERS], downstream_depth=0)
    assert set(graph.nodes) == {RAW_CUSTOMERS}
    assert any("downstream truncated" in w for w in graph.warnings)
    assert not any("upstream truncated" in w for w in graph.warnings)


# --- end to end -----------------------------------------------------------------


def test_trace_over_manifest_matches_risk_semantics() -> None:
    result = trace(source().build_graph())
    nodes = result.nodes
    assert nodes[RAW_CUSTOMERS].max_risk == "ORIGIN"
    assert nodes[STG].max_risk == "MEDIUM"
    assert nodes[ENRICHED].max_risk == "HIGH"
    assert nodes[ENRICHED].findings["email"].origin_node == RAW_CUSTOMERS
    assert nodes[DUMP].max_risk == "LOW"
    assert nodes[DAILY].max_risk == "NONE"


def test_jinja_only_model_degrades_to_presence_based() -> None:
    result = trace(source().build_graph())
    node = result.nodes[RAW_ONLY]
    assert node.max_risk == "LOW"
    assert node.findings["email"].reason == "present via lineage (no SQL available)"


# --- errors ----------------------------------------------------------------------


def test_missing_manifest_file() -> None:
    with pytest.raises(SensiflowInputError, match="not found"):
        DbtSource("/nowhere/manifest.json").build_graph()


def test_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{{{ not json")
    with pytest.raises(SensiflowInputError, match="not valid JSON"):
        DbtSource(path).build_graph()


def test_json_but_not_a_manifest(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"foo": 1}))
    with pytest.raises(SensiflowInputError, match="not a dbt manifest"):
        DbtSource(path).build_graph()


# --- CLI --------------------------------------------------------------------------


def test_cli_dbt_end_to_end(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--source", "dbt", "--dbt-manifest", str(MANIFEST)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "[HIGH] mart_orders_enriched" in out


def test_cli_dbt_requires_manifest_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["report", "--source", "dbt"])
    assert excinfo.value.code == 2
    assert "--dbt-manifest" in capsys.readouterr().err


def test_cli_dbt_missing_file_is_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--source", "dbt", "--dbt-manifest", "/nowhere.json"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err.startswith("error:")
