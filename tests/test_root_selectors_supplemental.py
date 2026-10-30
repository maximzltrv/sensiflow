"""QA-supplemental tests for the root-selectors slice (ADR-0002 amendment).

Angles not covered by the developer suite: selection equivalence
(``GraphSelection()`` vs ``None``) on all three sources, case-sensitivity
proof at the connector level (not just ``resolve_patterns``), multi-seed
from-seeds resolution on OMD, pattern-derived roots interacting with
truncation warnings, roots-file byte-level edge cases, duplicate entries,
and CLI stderr quality for each failure mode.

All fixtures are synthetic (clean-room); OMD traffic goes through
httpx.MockTransport — no network.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import httpx
import pytest

from sensiflow import GraphSelection, SensiflowInputError
from sensiflow.cli import main
from sensiflow.root_selectors import load_roots_file
from sensiflow.sources.dbt import DbtSource
from sensiflow.sources.mock import MockSource
from tests.support import PREFIX, TABLES
from tests.support import lineage_payload as _lineage_payload
from tests.test_dbt import DIM, DUMP, MANIFEST, RAW_CUSTOMERS, STG
from tests.test_openmetadata import PAGE_SIZE, make_source


def dbt_source() -> DbtSource:
    return DbtSource(MANIFEST)


def write_roots(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "roots.yaml"
    path.write_text(content)
    return path


# --- selection equivalence: GraphSelection() == None on every source -------------


def test_mock_default_selection_equals_none() -> None:
    assert set(MockSource().build_graph(GraphSelection()).nodes) == set(
        MockSource().build_graph(None).nodes
    )


def test_dbt_default_selection_equals_none() -> None:
    assert set(dbt_source().build_graph(GraphSelection()).nodes) == set(
        dbt_source().build_graph(None).nodes
    )


def test_omd_default_selection_equals_none() -> None:
    assert set(make_source().build_graph(GraphSelection()).nodes) == set(
        make_source().build_graph(None).nodes
    )


# --- case sensitivity proven at the connector level ------------------------------


def test_dbt_pattern_matching_is_case_sensitive() -> None:
    with pytest.raises(SensiflowInputError, match="matched no tables"):
        dbt_source().build_graph(GraphSelection(patterns=("MART_CUSTOMER_*",)))


def test_omd_pattern_matching_is_case_sensitive() -> None:
    with pytest.raises(SensiflowInputError, match="matched no tables"):
        make_source().build_graph(GraphSelection(patterns=("RAW_*",)))


# --- OMD: pattern + exact root dedup, multi-seed from-seeds ----------------------


def test_omd_exact_root_and_pattern_union_deduplicates() -> None:
    graph = make_source().build_graph(
        GraphSelection(
            roots=(f"{PREFIX}.mart_customer_dump",),
            patterns=("mart_customer_*",),
        )
    )
    assert set(graph.nodes) == {
        f"{PREFIX}.mart_customer_dump",
        f"{PREFIX}.dim_customers",
        f"{PREFIX}.stg_customers",
        f"{PREFIX}.raw_customers",
    }


def _handler_for(tables: list[dict[str, Any]]) -> Any:
    """A full OMD mock handler (tables + lineage) over a modified table list."""
    by_fqn = {t["fullyQualifiedName"]: t for t in tables}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/tables":
            start = int(request.url.params.get("after") or 0)
            page = tables[start : start + PAGE_SIZE]
            paging: dict[str, str] = {}
            if start + PAGE_SIZE < len(tables):
                paging["after"] = str(start + PAGE_SIZE)
            return httpx.Response(200, json={"data": page, "paging": paging})
        if path.startswith("/api/v1/tables/name/"):
            fqn = path.removeprefix("/api/v1/tables/name/")
            if fqn not in by_fqn:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json=by_fqn[fqn])
        if path.startswith("/api/v1/lineage/table/name/"):
            fqn = path.removeprefix("/api/v1/lineage/table/name/")
            if fqn not in by_fqn:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json=_lineage_payload(fqn))
        return httpx.Response(404, json={})

    return handler


def test_omd_from_seeds_with_two_seeded_tables_roots_both() -> None:
    tables = copy.deepcopy(TABLES)
    by_fqn = {t["fullyQualifiedName"]: t for t in tables}
    orders = by_fqn[f"{PREFIX}.raw_orders"]
    orders["columns"][0]["tags"] = [{"tagFQN": "PII.Sensitive"}]

    graph = make_source(_handler_for(tables)).build_graph(GraphSelection(from_seeds=True))
    # raw_customers' closure (6 nodes) plus raw_orders' closure brings in the cousin.
    assert f"{PREFIX}.raw_orders" in graph.nodes
    assert len(graph.nodes) == 7
    assert graph.warnings == []


# --- pattern-derived roots interact with depths/truncation as exact roots do -----


def test_dbt_pattern_roots_still_warn_on_upstream_truncation() -> None:
    graph = dbt_source().build_graph(
        GraphSelection(patterns=("mart_customer_d*",), upstream_depth=1)
    )
    assert set(graph.nodes) == {DUMP, DIM}
    assert any("upstream truncated" in w for w in graph.warnings)


def test_omd_pattern_roots_still_warn_on_downstream_truncation() -> None:
    graph = make_source().build_graph(
        GraphSelection(patterns=("stg_*",), downstream_depth=1)
    )
    assert set(graph.nodes) == {
        f"{PREFIX}.stg_customers",
        f"{PREFIX}.raw_customers",
        f"{PREFIX}.dim_customers",
    }
    assert any("downstream truncated" in w for w in graph.warnings)
    assert not any("upstream truncated" in w for w in graph.warnings)  # seed in scope


# --- roots file: byte/structure edge cases ---------------------------------------


def test_roots_file_with_undecodable_bytes_is_input_error(tmp_path: Path) -> None:
    """A3: every unreadable/unparseable file must raise SensiflowInputError.

    A roots file that is not valid UTF-8 (e.g. saved as UTF-16 or latin-1)
    currently escapes as a raw UnicodeDecodeError — defect, see QA report.
    """
    path = tmp_path / "roots.yaml"
    path.write_bytes(b"version: 1\nroots:\n  - id: caf\xe9\n")  # latin-1 bytes
    with pytest.raises(SensiflowInputError, match="roots file"):
        load_roots_file(path)


def test_empty_roots_file_is_rejected(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "")
    with pytest.raises(SensiflowInputError, match="top level must be a mapping"):
        load_roots_file(path)


def test_roots_file_with_null_entry_is_rejected(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  -\n")
    with pytest.raises(SensiflowInputError, match=r"roots\[0\] must be a mapping"):
        load_roots_file(path)


def test_duplicate_file_entries_survive_loading_in_order(tmp_path: Path) -> None:
    # The loader is lossless; dedup happens at resolution time (A2).
    path = write_roots(
        tmp_path,
        "version: 1\nroots:\n  - id: a_node\n  - id: a_node\n  - pattern: 'a_*'\n",
    )
    selection = load_roots_file(path)
    assert selection.roots == ("a_node", "a_node")
    assert selection.patterns == ("a_*",)


def test_duplicate_roots_resolve_to_one_node_on_dbt() -> None:
    graph = dbt_source().build_graph(
        GraphSelection(
            roots=(DUMP, DUMP, "mart_customer_dump"),  # id twice + bare name
            patterns=("mart_customer_*",),
        )
    )
    assert set(graph.nodes) == {DUMP, DIM, STG, RAW_CUSTOMERS}


# --- CLI stderr quality per failure mode ------------------------------------------


def test_cli_empty_root_value_is_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--root", ""])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "non-empty" in err


def test_cli_depth_without_roots_is_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--upstream-depth", "2"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "depths require roots" in err


def test_cli_pattern_matching_nothing_is_clean_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        ["report", "--source", "dbt", "--dbt-manifest", str(MANIFEST), "--root", "zzz_*"]
    )
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "matched no tables" in err


def test_cli_missing_roots_file_is_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--roots-file", "/nowhere/roots.yaml"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "roots file not found" in err


def test_cli_roots_file_excludes_roots_from_seeds(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - id: raw_customers\n")
    exit_code = main(["report", "--roots-file", str(path), "--roots-from-seeds"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "mutually exclusive" in err


def test_cli_invalid_roots_file_names_file_and_problem(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = write_roots(tmp_path, "version: 2\nroots:\n  - id: raw_customers\n")
    exit_code = main(["report", "--roots-file", str(path)])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "roots.yaml" in err
    assert "unsupported roots-file version" in err


def test_cli_roots_file_unions_with_root_flag(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = write_roots(tmp_path, f"version: 1\nroots:\n  - id: {DUMP}\n")
    exit_code = main(
        [
            "report",
            "--source",
            "dbt",
            "--dbt-manifest",
            str(MANIFEST),
            "--roots-file",
            str(path),
            "--root",
            "mart_daily_revenue",
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    # dump closure (4) + daily closure (daily <- enriched <- dim/raw_orders) -> 7 nodes;
    # the unconnected seed and mart_raw_only stay out, proving the union was scoped.
    assert "7 nodes analyzed" in out
    assert "mart_daily_revenue" in out
    assert "country_codes" not in out
    assert "mart_raw_only" not in out
