"""Renderer tests for the write-back document (text and JSON) and terminal safety."""

from __future__ import annotations

import json

import pytest

from sensiflow import (
    ApplyResult,
    Finding,
    GateOutcome,
    NodeResult,
    PiiTag,
    TagChange,
    TagPlan,
    TraceResult,
    WritebackAction,
    WritebackDiff,
    evaluate_gate,
)
from sensiflow.report import (
    _display,
    render_apply_text,
    render_check_text,
    render_plan_json,
    render_plan_text,
    render_text,
)


def change(
    column: str,
    action: WritebackAction,
    *,
    detail: str = "",
    confidence: float = 0.72,
    sensitive: bool = True,
) -> TagChange:
    return TagChange(
        node_id="n1",
        node_name="stg_customers",
        column=column,
        tag=PiiTag("email", sensitive),
        risk="MEDIUM",
        confidence=confidence,
        origin_node="raw_customers",
        action=action,
        detail=detail,
    )


def diff_of(*changes: TagChange, suppressed: tuple[TagChange, ...] = ()) -> WritebackDiff:
    plan = TagPlan(
        min_risk="MEDIUM",
        min_confidence=0.5,
        changes=list(changes),
        suppressed=list(suppressed),
        warnings=["trace caveat"],
    )
    return WritebackDiff(plan=plan, changes=list(changes))


def test_text_orders_sections_with_conflicts_first_and_counts_in_header() -> None:
    diff = diff_of(
        change("a", "add"),
        change("b", "conflict", detail="human says no"),
        change("c", "unchanged"),
        change("d", "manual"),
        change("e", "stale", detail="no current finding"),
        change("f", "update", detail="risk LOW -> MEDIUM"),
        change("g", "unmatched", detail="no entry"),
    )
    text = render_plan_text(diff, target="mock")
    order = [text.index(title) for title in ("CONFLICTS", "ADD", "UPDATE", "UNCHANGED",
                                             "MANUAL", "UNMATCHED", "STALE")]  # fmt: skip
    assert order == sorted(order)
    assert (
        "summary: conflict=1  add=1  update=1  unchanged=1  manual=1  unmatched=1  stale=1" in text
    )
    assert "min-risk=MEDIUM min-confidence=0.5 — target=mock — mode=dry-run" in text
    assert "warning: trace caveat" in text
    assert "no supporting planned change in this run (reported only; never removed)" in text
    assert "result: DRY-RUN — 2 changes pending; re-run with --apply --yes to write" in text


def test_text_pluralises_and_omits_empty_sections() -> None:
    text = render_plan_text(diff_of(change("a", "add")))
    assert "1 change pending" in text
    assert "CONFLICTS" not in text
    assert "suppressed by" not in text


def test_text_shows_non_sensitive_and_multiline_detail_indented() -> None:
    text = render_plan_text(
        diff_of(
            change("a", "unmatched", detail="add manually:\nmodels:\n  - name: m", sensitive=False)
        )
    )
    assert "tag=email (non-sensitive)" in text
    assert "      add manually:\n      models:\n        - name: m" in text


def test_text_suppressed_section_in_gate_style() -> None:
    low = change("a", "add", confidence=0.31)
    text = render_plan_text(diff_of(suppressed=(low,)))
    assert "suppressed by --min-confidence 0.5 (not written): 1 finding" in text
    assert "[MEDIUM] stg_customers.a   conf=0.31  origin=raw_customers" in text


def test_text_applying_header_precedes_the_outcome() -> None:
    diff = diff_of(change("a", "add"))
    text = render_plan_text(diff, applying=True)
    assert "applying 1 pending change..." in text
    assert "mode=apply" in text


def test_apply_text_verdict_is_honest_about_skips_and_failures() -> None:
    clean = ApplyResult(applied=[change("a", "add")], failed=[])
    assert (
        render_apply_text(clean)
        .rstrip()
        .endswith("result: APPLIED — 1 applied, 0 skipped, 0 failed")
    )

    skipped_only = ApplyResult(
        applied=[], failed=[], skipped=[(change("c", "add"), "skipped: re-check found manual")]
    )
    text = render_apply_text(skipped_only)
    assert "skipped: 1" in text
    assert "reason: skipped: re-check found manual" in text
    assert text.rstrip().endswith("result: APPLIED — 0 applied, 1 skipped, 0 failed")

    partial = ApplyResult(applied=[change("a", "add")], failed=[(change("b", "add"), "boom")])
    text = render_apply_text(partial)
    assert "error: boom" in text
    assert "APPLIED" not in text
    assert text.rstrip().endswith(
        "result: PARTIAL — 1 applied, 0 skipped, 1 failed; re-run to converge on the remainder"
    )


def test_json_shape_dry_run_and_apply() -> None:
    diff = diff_of(change("a", "add", confidence=0.123456), suppressed=(change("s", "add"),))
    document = render_plan_json(diff, target="dbt")
    assert document["mode"] == "dry-run"
    assert document["target"] == "dbt"
    assert document["applied"] is None
    assert document["changes"][0]["confidence"] == 0.1235  # published 4-decimal precision
    assert document["summary"]["add"] == 1
    assert document["warnings"] == ["trace caveat"]
    assert document["suppressed"][0]["column"] == "s"

    outcome = ApplyResult(
        applied=[change("a", "add")],
        failed=[(change("b", "add"), "boom")],
        skipped=[(change("c", "add"), "skipped: re-check found manual")],
    )
    applied = render_plan_json(diff, outcome, target="dbt")
    assert applied["mode"] == "apply"
    assert applied["applied"]["failed"][0]["error"] == "boom"
    assert applied["applied"]["skipped"][0]["reason"] == "skipped: re-check found manual"
    assert applied["applied"]["applied"][0]["column"] == "a"


# --- terminal-safe rendering of catalog-controlled text (ADR-0006 A7) -----------------------------

ESC, NEL, LS, PS, RLO, LRI, PDI = (
    chr(0x1B),
    chr(0x85),
    chr(0x2028),
    chr(0x2029),
    chr(0x202E),
    chr(0x2066),
    chr(0x2069),
)
HOSTILE_TEXT = f"x{ESC}[2Jy{NEL}z{LS}{PS}{RLO}w{LRI}v{PDI}\r\x00\x7f"
FORBIDDEN = [ESC, NEL, LS, PS, RLO, LRI, PDI, "\r", "\x00", "\x7f"]


def assert_terminal_safe(text: str) -> None:
    for char in FORBIDDEN:
        assert char not in text, repr(char)
    # No raw control character other than the newlines separating lines.
    assert all(c == "\n" or (c >= " " and c != "\x7f") for c in text)


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        (ESC, "\\x1b"),
        ("\x00", "\\x00"),
        ("\x7f", "\\x7f"),
        (NEL, "\\x85"),
        (LS, "\\u2028"),
        (PS, "\\u2029"),
        (RLO, "\\u202e"),
        (LRI, "\\u2066"),
        (PDI, "\\u2069"),
        ("\n", "\\x0a"),
        ("plain é text", "plain é text"),
    ],
)
def test_display_escapes_control_c1_separator_and_bidi_characters(raw: str, escaped: str) -> None:
    assert _display(raw) == escaped


def test_display_keeps_newlines_only_when_asked_to() -> None:
    assert _display("a\nb", multiline=True) == "a\nb"
    assert _display(f"a\n{ESC}b", multiline=True) == "a\n\\x1bb"


def hostile_diff() -> WritebackDiff:
    hostile = TagChange(
        node_id="n1",
        node_name=f"node{HOSTILE_TEXT}",
        column=f"col{HOSTILE_TEXT}",
        tag=PiiTag(f"cat{HOSTILE_TEXT}"),
        risk="MEDIUM",
        confidence=0.7,
        origin_node=f"origin{HOSTILE_TEXT}",
        action="conflict",
        detail=f"line one {HOSTILE_TEXT}\nline two {HOSTILE_TEXT}",
    )
    plan = TagPlan(
        min_risk="LOW",
        min_confidence=0.0,
        changes=[hostile],
        suppressed=[hostile],
        warnings=[f"warn{HOSTILE_TEXT}"],
    )
    return WritebackDiff(plan=plan, changes=[hostile])


def test_plan_text_escapes_every_catalog_derived_field() -> None:
    text = render_plan_text(hostile_diff(), target=f"tgt{HOSTILE_TEXT}")
    assert_terminal_safe(text)
    assert "\\x1b[2J" in text  # visible, not executed
    assert "line one" in text and "line two" in text  # multi-line detail stays multi-line


def test_apply_text_escapes_reasons_and_errors() -> None:
    diff = hostile_diff()
    outcome = ApplyResult(
        applied=[diff.changes[0]],
        failed=[(diff.changes[0], f"boom{HOSTILE_TEXT}")],
        skipped=[(diff.changes[0], f"why{HOSTILE_TEXT}")],
    )
    assert_terminal_safe(render_apply_text(outcome))


def test_json_output_keeps_the_raw_strings() -> None:
    document = render_plan_json(hostile_diff(), target="t")
    assert document["changes"][0]["name"] == f"node{HOSTILE_TEXT}"
    assert ESC not in json.dumps(document)  # serialization escapes control characters itself


def hostile_trace() -> tuple[TraceResult, GateOutcome]:
    findings = {
        f"col{HOSTILE_TEXT}": Finding(
            f"col{HOSTILE_TEXT}",
            PiiTag("email"),
            "HIGH",
            f"reason{HOSTILE_TEXT}",
            0.5,
            f"origin{HOSTILE_TEXT}",
        )
    }
    node = NodeResult("n1", f"node{HOSTILE_TEXT}", [f"owner{HOSTILE_TEXT}"], False, findings)
    result = TraceResult(nodes={"n1": node}, warnings=[f"warn{HOSTILE_TEXT}"])
    return result, evaluate_gate(result, fail_on="LOW", min_confidence=0.9)


def test_report_text_escapes_names_owners_columns_origins_and_warnings() -> None:
    result, _ = hostile_trace()
    assert_terminal_safe(render_text(result))


def test_check_text_escapes_violations_and_suppressed_lines() -> None:
    result, outcome = hostile_trace()
    assert outcome.suppressed  # the suppressed-line path is the one under test
    assert_terminal_safe(render_check_text(result, outcome))

    unsuppressed = evaluate_gate(result, fail_on="LOW")
    assert unsuppressed.violations
    assert_terminal_safe(render_check_text(result, unsuppressed))
