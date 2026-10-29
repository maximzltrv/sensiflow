"""QA supplemental tests for the `check` CI gate (ADR-0004).

Grey-box probes of what the spec promises beyond the developer's own tests:

- the exit-code contract under stdout failures and crashes (exit 1 must be
  impossible on any non-trip path; `report` must never exit 1);
- the inclusive confidence boundary as the *user* sees it (published values);
- the partition invariant: every at/above-risk finding is either gating or
  suppressed — exactly one, never neither;
- output purity and shape for `--format json` (empty graph, warnings);
- boundary policy values (0.0, 1.0, NaN/inf) and ORIGIN at `--fail-on LOW`.

Defects found in this QA pass are fixed (ADR-0004 A1-A4); their tests are
plain regression tests now. Synthetic names only.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sensiflow.cli import ExitCode, main
from sensiflow.engine import trace
from sensiflow.exceptions import SensiflowError
from sensiflow.gate import GateRisk, evaluate_gate
from sensiflow.model import RISK_RANK, Finding, NodeResult, PiiTag, Risk, TraceResult
from sensiflow.report import render_check_json, render_check_text
from sensiflow.root_selectors import GraphSelection
from sensiflow.sources.mock import MockSource

GATE_RISKS: tuple[GateRisk, ...] = ("LOW", "MEDIUM", "HIGH")
SOURCE_ID = "source.demo_shop.crm.raw_people"
PII_EMAIL = {"email": {"meta": {"pii": True, "pii_category": "email"}}}


# --- helpers -------------------------------------------------------------------


def _model(name: str, deps: list[str], sql: str) -> dict[str, Any]:
    return {
        "resource_type": "model",
        "name": name,
        "depends_on": {"nodes": deps},
        "columns": {},
        "compiled_code": sql,
    }


def _write_manifest(
    tmp_path: Path, nodes: dict[str, Any], source_columns: dict[str, Any] | None = None
) -> str:
    manifest = {
        "metadata": {"project_name": "demo_shop"},
        "nodes": nodes,
        "sources": {
            SOURCE_ID: {
                "resource_type": "source",
                "name": "raw_people",
                "columns": PII_EMAIL if source_columns is None else source_columns,
            }
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    return str(path)


def _alias_then_star_manifest(tmp_path: Path) -> str:
    """raw_people -> stg_people (aliased, conf 0.8) -> people_dump (SELECT *, 0.8*0.7)."""
    return _write_manifest(
        tmp_path,
        {
            "model.demo_shop.stg_people": _model(
                "stg_people", [SOURCE_ID], "SELECT email AS contact_email FROM raw_people"
            ),
            "model.demo_shop.people_dump": _model(
                "people_dump", ["model.demo_shop.stg_people"], "SELECT * FROM stg_people"
            ),
        },
    )


def _finding(column: str, risk: Risk, confidence: float) -> Finding:
    return Finding(
        column=column,
        tag=PiiTag(category="email"),
        risk=risk,
        reason="selected in projection",
        confidence=confidence,
        origin_node="raw_people",
    )


def _node(node_id: str, *findings: Finding, name: str | None = None) -> NodeResult:
    return NodeResult(
        node_id=node_id,
        name=name or node_id,
        owners=[],
        is_source=False,
        findings={f.column: f for f in findings},
    )


def _result(*nodes: NodeResult) -> TraceResult:
    return TraceResult(nodes={n.node_id: n for n in nodes})


class _BrokenPipeStdout(io.StringIO):
    """A stdout whose reader has gone away (`sensiflow check ... | head -1`)."""

    def write(self, s: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")


# --- DEFECT: stdout failures escape the wrapper (exit 1 on a PASS path) ----------


def test_check_pass_with_unencodable_stdout_never_exits_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The text renderer always emits U+2014 (em dash) in its header and verdict.
    ascii_stdout = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
    monkeypatch.setattr(sys, "stdout", ascii_stdout)
    # PASS path on the mock graph: the only HIGH finding (conf 0.73) is suppressed.
    exit_code = main(["check", "--fail-on", "HIGH", "--min-confidence", "0.9"])
    assert exit_code in (ExitCode.OK, ExitCode.OPERATIONAL_ERROR)


def test_check_pass_with_broken_pipe_never_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _BrokenPipeStdout())
    exit_code = main(["check", "--fail-on", "HIGH", "--min-confidence", "0.9"])
    assert exit_code in (ExitCode.OK, ExitCode.OPERATIONAL_ERROR)


def test_check_pass_process_exit_code_with_ascii_stdout() -> None:
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}
    proc = subprocess.run(
        [sys.executable, "-m", "sensiflow.cli", "check", "--fail-on", "HIGH",
         "--min-confidence", "0.9"],
        env=env,
        capture_output=True,
        check=False,
    )
    assert proc.returncode != ExitCode.GATE_TRIPPED
    assert proc.returncode in (ExitCode.OK, ExitCode.OPERATIONAL_ERROR)


# --- DEFECT: `report` can still exit 1 on an internal error -----------------------


def test_report_unexpected_crash_exits_3(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: MockSource, selection: GraphSelection | None = None) -> None:
        raise RuntimeError("synthetic internal failure")

    monkeypatch.setattr(MockSource, "build_graph", boom)
    exit_code = main(["report", "--source", "mock"])
    assert exit_code == ExitCode.OPERATIONAL_ERROR
    assert "synthetic internal failure" in capsys.readouterr().err


def test_report_cyclic_graph_never_exits_1(tmp_path: Path) -> None:
    manifest = _write_manifest(
        tmp_path,
        {
            "model.demo_shop.a_model": _model(
                "a_model", [SOURCE_ID, "model.demo_shop.b_model"], "SELECT email FROM raw_people"
            ),
            "model.demo_shop.b_model": _model(
                "b_model", ["model.demo_shop.a_model"], "SELECT email FROM a_model"
            ),
        },
    )
    exit_code = main(["report", "--source", "dbt", "--dbt-manifest", manifest])
    assert exit_code == ExitCode.INPUT_ERROR


def test_check_cyclic_graph_is_input_error_without_traceback(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # A cycle is an input error (ADR-0004 A3): one-line message, no traceback.
    manifest = _write_manifest(
        tmp_path,
        {
            "model.demo_shop.a_model": _model(
                "a_model", [SOURCE_ID, "model.demo_shop.b_model"], "SELECT email FROM raw_people"
            ),
            "model.demo_shop.b_model": _model(
                "b_model", ["model.demo_shop.a_model"], "SELECT email FROM a_model"
            ),
        },
    )
    exit_code = main(["check", "--source", "dbt", "--dbt-manifest", manifest, "--fail-on", "LOW"])
    captured = capsys.readouterr()
    assert exit_code == ExitCode.INPUT_ERROR
    assert "error: lineage graph contains a cycle" in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""


# --- DEFECT: inclusive confidence boundary vs published confidence ----------------


def test_min_confidence_equal_to_published_confidence_gates(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    manifest = _alias_then_star_manifest(tmp_path)
    base = ["check", "--source", "dbt", "--dbt-manifest", manifest, "--fail-on", "LOW",
            "--format", "json"]
    assert main(base) == ExitCode.GATE_TRIPPED
    doc = json.loads(capsys.readouterr().out)
    dump = next(n for n in doc["violations"] if n["name"] == "people_dump")
    published = dump["findings"][0]["confidence"]
    assert published == 0.56  # what a user reads and copies into CI config

    main([*base, "--min-confidence", str(published)])
    doc = json.loads(capsys.readouterr().out)
    assert doc["suppressed"] == [], "a finding at exactly min_confidence must gate"
    assert "people_dump" in [n["name"] for n in doc["violations"]]


# --- partition invariant: gating XOR suppressed, never neither --------------------


def _at_or_above(result: TraceResult, fail_on: GateRisk) -> set[tuple[str, str]]:
    threshold = RISK_RANK[fail_on]
    return {
        (node.node_id, finding.column)
        for node in result.nodes.values()
        for finding in node.findings.values()
        if RISK_RANK[finding.risk] >= threshold
    }


@pytest.mark.parametrize("fail_on", GATE_RISKS)
@pytest.mark.parametrize("min_confidence", [0.0, 0.5, 0.6, 0.73, 0.8, 0.85, 0.9, 1.0])
def test_every_at_or_above_finding_is_gating_xor_suppressed(
    fail_on: GateRisk, min_confidence: float
) -> None:
    result = trace(MockSource().build_graph())
    outcome = evaluate_gate(result, fail_on=fail_on, min_confidence=min_confidence)

    gating = {
        (node.node_id, f.column)
        for node in outcome.violations
        for f in node.findings.values()
        if RISK_RANK[f.risk] >= RISK_RANK[fail_on] and f.confidence >= min_confidence
    }
    suppressed = {(node_id, f.column) for node_id, f in outcome.suppressed}

    assert gating.isdisjoint(suppressed)
    assert gating | suppressed == _at_or_above(result, fail_on)
    assert len(suppressed) == len(outcome.suppressed)  # no duplicates
    assert outcome.tripped == bool(gating)
    # ORIGIN never appears in either set: it ranks below every gate threshold.
    assert all(result.nodes[n].findings[c].risk != "ORIGIN" for n, c in gating | suppressed)


@pytest.mark.parametrize("fail_on", GATE_RISKS)
@pytest.mark.parametrize("min_confidence", [0.0, 0.75, 0.9])
def test_text_render_lists_each_at_or_above_finding_exactly_once(
    fail_on: GateRisk, min_confidence: float
) -> None:
    # Renderer-level partition: a suppressed finding must not also be listed
    # under its violating node, and no gating finding may be omitted.
    result = trace(MockSource().build_graph())
    outcome = evaluate_gate(result, fail_on=fail_on, min_confidence=min_confidence)
    text = render_check_text(result, outcome)

    for node_id, column in _at_or_above(result, fail_on):
        node = result.nodes[node_id]
        finding = node.findings[column]
        suppressed_line = f"{node.name}.{column}   conf="
        if finding.confidence >= min_confidence:
            assert suppressed_line not in text
            block = text.split(f"] {node.name}  (owners:", 1)[1].split("\n\n", 1)[0]
            assert sum(line.split()[0] == column for line in block.splitlines()[1:]) == 1
        else:
            assert text.count(suppressed_line) == 1


# --- per-finding filtering inside one node ---------------------------------------


def test_text_violation_block_omits_its_own_suppressed_finding() -> None:
    result = _result(
        _node("mixed_node", _finding("email", "HIGH", 0.95), _finding("phone", "HIGH", 0.4))
    )
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.5)
    text = render_check_text(result, outcome)
    violation_block = text.split("\n\n")[1]
    assert "email" in violation_block
    assert "phone" not in violation_block
    assert "[HIGH] mixed_node.phone   conf=0.40" in text
    assert text.rstrip().endswith(
        "result: FAIL — 1 node at or above HIGH (1 suppressed below confidence)"
    )


# --- boundary policy values ------------------------------------------------------


def test_float_boundary_exact_vs_next_published_step_below() -> None:
    # A4: the comparison is at 4 dp, so the next distinguishable value is 0.7499.
    exact = _result(_node("n", _finding("email", "HIGH", 0.75)))
    below = _result(_node("n", _finding("email", "HIGH", 0.7499)))
    assert evaluate_gate(exact, fail_on="HIGH", min_confidence=0.75).tripped
    outcome = evaluate_gate(below, fail_on="HIGH", min_confidence=0.75)
    assert not outcome.tripped
    assert len(outcome.suppressed) == 1


def test_min_confidence_one_gates_only_full_confidence_findings() -> None:
    result = _result(
        _node("certain", _finding("email", "HIGH", 1.0)),
        _node("almost", _finding("email", "HIGH", 0.9999)),
    )
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=1.0)
    assert [n.node_id for n in outcome.violations] == ["certain"]
    assert [node_id for node_id, _ in outcome.suppressed] == ["almost"]


def test_cli_min_confidence_one_on_mock_passes_with_everything_suppressed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["check", "--fail-on", "LOW", "--min-confidence", "1.0", "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert exit_code == ExitCode.OK
    assert doc["tripped"] is False
    assert doc["violations"] == []
    # every non-ORIGIN finding of the mock graph is surfaced, none hidden
    result = trace(MockSource().build_graph())
    assert len(doc["suppressed"]) == len(_at_or_above(result, "LOW"))


def test_cli_explicit_zero_min_confidence_equals_default(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["check", "--fail-on", "LOW", "--format", "json"]) == 1
    default_doc = capsys.readouterr().out
    assert main(["check", "--fail-on", "LOW", "--format", "json", "--min-confidence", "0"]) == 1
    explicit_doc = capsys.readouterr().out
    assert default_doc == explicit_doc
    assert json.loads(explicit_doc)["suppressed"] == []


@pytest.mark.parametrize("bad", ["nan", "NaN", "inf", "-inf", "infinity"])
def test_cli_non_finite_min_confidence_is_input_error(
    capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    # `=` form: argparse would otherwise read "-inf" as an option flag.
    exit_code = main(["check", "--fail-on", "HIGH", f"--min-confidence={bad}"])
    captured = capsys.readouterr()
    assert exit_code == ExitCode.INPUT_ERROR
    assert captured.err.startswith("error:")
    assert captured.out == ""


# --- ORIGIN never trips ----------------------------------------------------------


def test_cli_fail_on_low_never_lists_origin_nodes(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", "--fail-on", "LOW", "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["ORIGIN"] == 1
    assert "raw_customers" not in [n["node_id"] for n in doc["violations"]]
    assert all(entry["risk"] != "ORIGIN" for entry in doc["suppressed"])


def test_cli_seed_only_graph_passes_at_fail_on_low(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # A graph whose only PII is the declared seed: nothing propagated, nothing exposed.
    manifest = _write_manifest(
        tmp_path,
        {"model.demo_shop.people_count": _model(
            "people_count", [SOURCE_ID], "SELECT COUNT(*) AS n FROM raw_people"
        )},
    )
    exit_code = main(["check", "--source", "dbt", "--dbt-manifest", manifest, "--fail-on", "LOW"])
    out = capsys.readouterr().out
    assert exit_code == ExitCode.OK
    assert "ORIGIN=1" in out
    assert "result: PASS — no findings at or above LOW" in out


# --- findings below threshold at every level --------------------------------------


def test_only_low_findings_pass_medium_and_high_and_suppress_nothing() -> None:
    result = _result(
        _node("dump_a", _finding("email", "LOW", 0.3)),
        _node("dump_b", _finding("phone", "LOW", 0.99)),
    )
    for fail_on in ("MEDIUM", "HIGH"):
        outcome = evaluate_gate(result, fail_on=fail_on, min_confidence=0.99)
        assert not outcome.tripped
        assert outcome.suppressed == ()  # suppression only applies at/above risk
    low = evaluate_gate(result, fail_on="LOW", min_confidence=0.99)
    assert [n.node_id for n in low.violations] == ["dump_b"]
    assert [node_id for node_id, _ in low.suppressed] == ["dump_a"]


# --- suppressed ordering tie-breakers --------------------------------------------


def test_suppressed_order_risk_then_name_then_column_independent_of_insertion() -> None:
    nodes = [
        _node("n3", _finding("zip", "MEDIUM", 0.1), _finding("email", "MEDIUM", 0.1), name="b"),
        _node("n1", _finding("phone", "HIGH", 0.1), name="z"),
        _node("n2", _finding("email", "MEDIUM", 0.1), name="a"),
        _node("n4", _finding("ssn", "HIGH", 0.1), name="a"),
    ]
    expected = [("n4", "ssn"), ("n1", "phone"), ("n2", "email"), ("n3", "email"), ("n3", "zip")]
    for ordering in (nodes, list(reversed(nodes))):
        outcome = evaluate_gate(_result(*ordering), fail_on="MEDIUM", min_confidence=0.5)
        assert [(nid, f.column) for nid, f in outcome.suppressed] == expected


# --- JSON output purity and shape -------------------------------------------------

_CHECK_JSON_KEYS = {
    "fail_on", "min_confidence", "tripped", "summary", "warnings", "violations", "suppressed"
}


@pytest.mark.parametrize(
    "argv",
    [
        ["check", "--fail-on", "HIGH", "--format", "json"],  # trip
        ["check", "--fail-on", "HIGH", "--format", "json", "--min-confidence", "0.9"],  # pass
    ],
)
def test_json_stdout_is_exactly_one_document(
    capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    main(argv)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.endswith("}\n")
    doc, end = json.JSONDecoder().raw_decode(captured.out)
    assert captured.out[end:] == "\n"
    assert set(doc) == _CHECK_JSON_KEYS


def test_json_with_warnings_keeps_stdout_pure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    manifest = _write_manifest(
        tmp_path,
        {"model.demo_shop.stg_people": _model(
            "stg_people", [SOURCE_ID], "SELECT person_id FROM raw_people"
        )},
        source_columns={},
    )
    exit_code = main(
        ["check", "--source", "dbt", "--dbt-manifest", manifest, "--fail-on", "LOW",
         "--format", "json"]
    )
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert exit_code == ExitCode.OK
    assert captured.err == ""
    assert any("no PII seeds declared" in w for w in doc["warnings"])
    assert "warning:" not in captured.out  # no text-mode lines leak into JSON


def test_empty_graph_json_shape_and_pass(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"metadata": {"project_name": "demo_shop"},
                                "nodes": {}, "sources": {}}))
    exit_code = main(
        ["check", "--source", "dbt", "--dbt-manifest", str(path), "--fail-on", "LOW",
         "--format", "json"]
    )
    doc = json.loads(capsys.readouterr().out)
    assert exit_code == ExitCode.OK
    assert doc == {
        "fail_on": "LOW",
        "min_confidence": 0.0,
        "tripped": False,
        "summary": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "ORIGIN": 0, "NONE": 0},
        "warnings": [],
        "violations": [],
        "suppressed": [],
    }


def test_library_empty_result_renders_in_both_formats() -> None:
    empty = TraceResult(nodes={})
    outcome = evaluate_gate(empty, fail_on="HIGH", min_confidence=0.5)
    assert not outcome.tripped
    assert outcome.violations == () and outcome.suppressed == ()
    assert set(render_check_json(empty, outcome)) == _CHECK_JSON_KEYS
    assert render_check_text(empty, outcome).endswith(
        "result: PASS — no findings at or above HIGH with confidence >= 0.5\n"
    )


def test_check_and_report_agree_on_summary_warnings_and_node_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["report", "--format", "json"])
    report_doc = json.loads(capsys.readouterr().out)
    main(["check", "--fail-on", "LOW", "--format", "json"])
    check_doc = json.loads(capsys.readouterr().out)
    assert check_doc["summary"] == report_doc["summary"]
    assert check_doc["warnings"] == report_doc["warnings"]
    report_nodes = {n["node_id"]: n for n in report_doc["nodes"]}
    for violation in check_doc["violations"]:
        assert violation == report_nodes[violation["node_id"]]


# --- error mapping across both commands ------------------------------------------


@pytest.mark.parametrize("command", [["report"], ["check", "--fail-on", "HIGH"]])
def test_bare_sensiflow_error_exits_3(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    def boom(self: MockSource, selection: GraphSelection | None = None) -> None:
        raise SensiflowError("synthetic unclassified failure")

    monkeypatch.setattr(MockSource, "build_graph", boom)
    exit_code = main(command)
    captured = capsys.readouterr()
    assert exit_code == ExitCode.OPERATIONAL_ERROR
    assert captured.err == "error: synthetic unclassified failure\n"
    assert captured.out == ""


def test_check_usage_error_inside_wrapper_stays_exit_2(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # parser.error() fires inside _run_check's try (in _make_source); SystemExit
    # is not an Exception, so the broad wrapper must not remap it to 3.
    monkeypatch.delenv("OMD_HOST", raising=False)
    monkeypatch.delenv("OMD_TOKEN", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--fail-on", "HIGH", "--source", "openmetadata"])
    assert excinfo.value.code == ExitCode.INPUT_ERROR
    assert "Traceback" not in capsys.readouterr().err


def test_check_roots_file_twice_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--fail-on", "HIGH", "--roots-file", "a.yaml", "--roots-file", "b.yaml"])
    assert excinfo.value.code == ExitCode.INPUT_ERROR
    assert "--roots-file may be given at most once" in capsys.readouterr().err


def test_renderer_crash_maps_to_3_not_1(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A renderer bug on a TRIP path must still exit 3: 1 only after a full,
    # successful run.
    import sensiflow.cli as cli_module

    def broken(result: TraceResult, outcome: object) -> str:
        raise KeyError("synthetic renderer bug")

    monkeypatch.setattr(cli_module, "render_check_text", broken)
    exit_code = main(["check", "--fail-on", "HIGH"])
    captured = capsys.readouterr()
    assert exit_code == ExitCode.OPERATIONAL_ERROR
    assert captured.out == ""
    assert "synthetic renderer bug" in captured.err
