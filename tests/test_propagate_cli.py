"""`sensiflow propagate` CLI tests: argv in -> document on stdout, exit code out.

Everything runs against the in-memory mock target (the network-free smoke
path of every exit code). Tests that need a configured target swap the
source factory, the same seam the CLI itself uses.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

from sensiflow import (
    ApplyResult,
    ExistingTag,
    LineageGraph,
    PiiTag,
    SensiflowConnectionError,
    TagChange,
)
from sensiflow import cli as cli_module
from sensiflow.cli import main
from sensiflow.root_selectors import GraphSelection
from sensiflow.sources.mock import MockSource

RAW = "raw_customers"


def use_source(monkeypatch: pytest.MonkeyPatch, source: Any) -> None:
    monkeypatch.setattr(cli_module, "_make_source", lambda parser, args: source)


# --- argument handling ------------------------------------------------------------------------


def test_min_risk_is_required(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["propagate"])
    assert excinfo.value.code == 2
    assert "--min-risk" in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["ORIGIN", "NONE", "critical", ""])
def test_min_risk_rejects_non_thresholds(bad: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["propagate", "--min-risk", bad])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("value", ["low", "Medium", "HIGH"])
def test_min_risk_is_case_insensitive(value: str) -> None:
    assert main(["propagate", "--min-risk", value]) == 0


def test_apply_without_yes_is_a_usage_error_naming_the_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["propagate", "--min-risk", "low", "--apply"])
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "--yes" in captured.err
    assert captured.out == ""


def test_dry_run_and_apply_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["propagate", "--min-risk", "low", "--dry-run", "--apply", "--yes"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("bad", ["-0.1", "1.5", "nan"])
def test_out_of_range_min_confidence_is_exit_two(
    bad: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["propagate", "--min-risk", "low", "--min-confidence", bad]) == 2
    assert "min-confidence" in capsys.readouterr().err


def test_source_without_write_support_is_exit_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class ReadOnly:
        def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
            raise AssertionError("must not be reached")

    use_source(monkeypatch, ReadOnly())
    assert main(["propagate", "--min-risk", "low"]) == 2
    assert "does not support write-back" in capsys.readouterr().err


# --- dry-run ----------------------------------------------------------------------------------


def test_dry_run_is_the_default_and_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = MockSource()
    use_source(monkeypatch, source)
    assert main(["propagate", "--min-risk", "medium"]) == 0
    out = capsys.readouterr().out
    assert "mode=dry-run" in out
    assert "result: DRY-RUN — 5 changes pending" in out
    assert source.read_markup(["stg_customers", "dim_customers"]) == {}


def test_explicit_dry_run_flag_is_an_accepted_no_op(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["propagate", "--min-risk", "medium"]) == 0
    default_out = capsys.readouterr().out
    assert main(["propagate", "--min-risk", "medium", "--dry-run"]) == 0
    assert capsys.readouterr().out == default_out


def test_dry_run_with_conflicts_still_exits_zero_and_shows_them_first(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = MockSource()
    # Placed after the source is built: a tag that predates the trace would seed it.
    real_build = source.build_graph

    def build_then_place(selection: GraphSelection | None = None) -> LineageGraph:
        graph = real_build(selection)
        source.set_markup("dim_customers", "email", ExistingTag(PiiTag("pii", False), False))
        return graph

    monkeypatch.setattr(source, "build_graph", build_then_place)
    use_source(monkeypatch, source)
    assert main(["propagate", "--min-risk", "medium"]) == 0
    out = capsys.readouterr().out
    assert "conflict=1" in out
    assert out.index("CONFLICTS") < out.index("ADD")
    assert "human-placed pii tag (non-sensitive)" in out


def test_json_dry_run_golden(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["propagate", "--min-risk", "high", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "mode": "dry-run",
        "target": "mock",
        "min_risk": "HIGH",
        "min_confidence": 0.0,
        "summary": {
            "conflict": 0,
            "add": 0,
            "update": 0,
            "unchanged": 0,
            "manual": 0,
            "unmatched": 1,
            "stale": 0,
        },
        "changes": [
            {
                "node_id": "mart_orders_enriched",
                "name": "mart_orders_enriched",
                "column": "email",
                "tag": {"category": "email", "sensitive": True},
                "risk": "HIGH",
                "confidence": 0.729,
                "origin": RAW,
                "action": "unmatched",
                "detail": "column is not in the node's output schema",
            }
        ],
        "suppressed": [],
        "warnings": [],
        "applied": None,
    }


def test_min_confidence_suppression_is_surfaced_in_both_formats(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = ["propagate", "--min-risk", "low", "--min-confidence", "0.8"]
    assert main(args) == 0
    text = capsys.readouterr().out
    assert "suppressed by --min-confidence 0.8 (not written): 3 findings" in text

    assert main([*args, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {s["name"] for s in payload["suppressed"]} == {
        "mart_customer_dump",
        "mart_orders_enriched",
    }
    assert payload["min_confidence"] == 0.8
    assert all("action" not in s for s in payload["suppressed"])


# --- apply ------------------------------------------------------------------------------------


def test_full_mock_cycle_apply_then_converged_rerun(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = MockSource()
    use_source(monkeypatch, source)
    assert main(["propagate", "--min-risk", "low", "--apply", "--yes"]) == 0
    out = capsys.readouterr().out
    # The resolved diff is printed before anything is applied, then the outcome.
    assert out.index("ADD — markup to be written: 7") < out.index("applying 7 pending changes")
    assert out.index("applying 7") < out.index("applied: 7")
    assert "result: APPLIED — 7 applied, 0 failed" in out

    assert main(["propagate", "--min-risk", "low", "--apply", "--yes"]) == 0
    rerun = capsys.readouterr().out
    assert "unchanged=7" in rerun
    assert "result: APPLIED — 0 applied, 0 failed" in rerun


def test_json_apply_document_carries_the_outcome(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use_source(monkeypatch, MockSource())
    args = ["propagate", "--min-risk", "medium", "--apply", "--yes", "--format", "json"]
    assert main(args) == 0
    payload = json.loads(capsys.readouterr().out)  # exactly one document on stdout
    assert payload["mode"] == "apply"
    assert len(payload["applied"]["applied"]) == 5
    assert payload["applied"]["failed"] == []


def test_apply_with_nothing_to_do_is_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["propagate", "--min-risk", "high", "--apply", "--yes"]) == 0
    assert "result: APPLIED — 0 applied, 0 failed" in capsys.readouterr().out


def test_partial_failure_is_exit_three_and_lists_both_sides(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use_source(monkeypatch, MockSource(fail_on=[("stg_customers", "phone")]))
    assert main(["propagate", "--min-risk", "medium", "--apply", "--yes"]) == 3
    out = capsys.readouterr().out
    assert "applied: 4" in out
    assert "failed: 1" in out
    assert "error: simulated write failure" in out
    assert "result: APPLIED — 4 applied, 1 failed" in out


def test_json_partial_failure_is_exit_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use_source(monkeypatch, MockSource(fail_on=[("stg_customers", "phone")]))
    args = ["propagate", "--min-risk", "medium", "--apply", "--yes", "--format", "json"]
    assert main(args) == 3
    failed = json.loads(capsys.readouterr().out)["applied"]["failed"]
    assert [(f["name"], f["column"], f["error"]) for f in failed] == [
        ("stg_customers", "phone", "simulated write failure")
    ]


def test_catalog_failure_during_apply_is_exit_three_with_a_clean_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Unreachable(MockSource):
        def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
            raise SensiflowConnectionError("cannot reach OpenMetadata at http://omd.test")

    use_source(monkeypatch, Unreachable())
    assert main(["propagate", "--min-risk", "low", "--apply", "--yes"]) == 3
    assert "cannot reach OpenMetadata" in capsys.readouterr().err


def test_unexpected_crash_is_exit_three_never_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Crashing(MockSource):
        def read_markup(self, node_ids: Sequence[str]) -> dict[tuple[str, str], ExistingTag]:
            raise RuntimeError("bug")

    use_source(monkeypatch, Crashing())
    assert main(["propagate", "--min-risk", "low"]) == 3
    assert "RuntimeError" in capsys.readouterr().err


def test_dry_run_never_calls_write_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoWrites(MockSource):
        def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
            raise AssertionError("dry-run must not write")

    use_source(monkeypatch, NoWrites())
    assert main(["propagate", "--min-risk", "low", "--yes"]) == 0  # --yes alone does not apply
