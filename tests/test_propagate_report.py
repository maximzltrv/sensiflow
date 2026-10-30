"""Renderer tests for the write-back document (text and JSON)."""

from __future__ import annotations

from sensiflow import (
    ApplyResult,
    PiiTag,
    TagChange,
    TagPlan,
    WritebackAction,
    WritebackDiff,
)
from sensiflow.report import render_apply_text, render_plan_json, render_plan_text


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
    assert "would be removed by a future --prune" in text
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


def test_text_apply_modes() -> None:
    diff = diff_of(change("a", "add"))
    assert "applying 1 pending change..." in render_plan_text(diff, applying=True)
    assert "mode=apply" in render_plan_text(diff, applying=True)

    outcome = ApplyResult(applied=[change("a", "add")], failed=[(change("b", "add"), "boom")])
    full = render_plan_text(diff, outcome)
    assert "mode=apply" in full
    assert full.rstrip().endswith("result: APPLIED — 1 applied, 1 failed")
    assert "error: boom" in render_apply_text(outcome)


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

    outcome = ApplyResult(applied=[change("a", "add")], failed=[(change("b", "add"), "boom")])
    applied = render_plan_json(diff, outcome, target="dbt")
    assert applied["mode"] == "apply"
    assert applied["applied"]["failed"][0]["error"] == "boom"
    assert applied["applied"]["applied"][0]["column"] == "a"
