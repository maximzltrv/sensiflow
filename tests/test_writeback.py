"""Write-back core tests: plan (pure), diff (policy), apply (gate), convergence.

Everything runs offline against the in-memory MockSource target, which
implements the full WritebackTarget cycle. Hand-built TraceResults pin the
boundary values (ADR-0004 A4 rounding) without depending on engine numbers.
"""

from __future__ import annotations

import copy
import subprocess
import sys
from collections.abc import Sequence

import pytest

from sensiflow import (
    ApplyResult,
    ExistingTag,
    Finding,
    NodeResult,
    PiiTag,
    Risk,
    SensiflowInputError,
    TagChange,
    TagPlan,
    TraceResult,
    WritebackTarget,
    apply_writeback,
    diff_writeback,
    plan_writeback,
    trace,
)
from sensiflow.sources.mock import MockSource

EMAIL = PiiTag(category="email")


def finding(column: str, risk: Risk, confidence: float, tag: PiiTag = EMAIL) -> Finding:
    return Finding(
        column=column,
        tag=tag,
        risk=risk,
        reason="test",
        confidence=confidence,
        origin_node="raw",
    )


def result_of(*findings: Finding, node_id: str = "n1") -> TraceResult:
    node = NodeResult(
        node_id=node_id,
        name=node_id,
        owners=[],
        is_source=False,
        findings={f.column: f for f in findings},
    )
    return TraceResult(nodes={node_id: node}, warnings=["trace caveat"])


def mock_plan(min_risk: Risk = "LOW", min_confidence: float = 0.0) -> tuple[MockSource, TagPlan]:
    source = MockSource()
    result = trace(source.build_graph())
    return source, plan_writeback(result, min_risk=min_risk, min_confidence=min_confidence)


def changes_by_key(diff_changes: Sequence[TagChange]) -> dict[tuple[str, str], TagChange]:
    return {(c.node_id, c.column): c for c in diff_changes}


# --- plan ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("min_risk", "expected"),
    [("LOW", 8), ("MEDIUM", 6), ("HIGH", 1)],
)
def test_plan_selects_findings_at_or_above_min_risk(min_risk: Risk, expected: int) -> None:
    _, plan = mock_plan(min_risk)
    assert len(plan.changes) == expected
    assert all(c.action == "add" for c in plan.changes)


def test_plan_never_contains_origin_findings() -> None:
    _, plan = mock_plan("LOW")
    assert "raw_customers" not in {c.node_id for c in plan.changes}
    assert all(c.risk != "ORIGIN" for c in plan.changes)


@pytest.mark.parametrize("bad", ["ORIGIN", "NONE", "CRITICAL", ""])
def test_plan_rejects_non_threshold_risks(bad: str) -> None:
    with pytest.raises(SensiflowInputError, match="LOW, MEDIUM, HIGH"):
        plan_writeback(result_of(), min_risk=bad)  # type: ignore[arg-type]  # deliberately not a Risk


@pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan")])
def test_plan_rejects_out_of_range_confidence(bad: float) -> None:
    with pytest.raises(SensiflowInputError, match=r"between 0\.0 and 1\.0"):
        plan_writeback(result_of(), min_risk="LOW", min_confidence=bad)


def test_plan_confidence_gate_is_inclusive_at_published_precision() -> None:
    # 0.8 * 0.7 == 0.5599999999999999 in binary floating point: it must still
    # gate at the 0.56 printed in the JSON output.
    result = result_of(finding("email", "MEDIUM", 0.8 * 0.7))
    plan = plan_writeback(result, min_risk="LOW", min_confidence=0.56)
    assert [c.column for c in plan.changes] == ["email"]
    assert plan.suppressed == []


def test_plan_rounds_the_finding_up_to_the_threshold() -> None:
    result = result_of(finding("email", "MEDIUM", 0.99996))
    plan = plan_writeback(result, min_risk="LOW", min_confidence=1.0)
    assert [c.column for c in plan.changes] == ["email"]


def test_plan_suppresses_below_confidence_and_never_drops() -> None:
    result = result_of(
        finding("a_col", "MEDIUM", 0.9),
        finding("b_col", "MEDIUM", 0.5),
        finding("c_col", "LOW", 0.1),  # below risk threshold: not suppressed, just out of scope
    )
    plan = plan_writeback(result, min_risk="MEDIUM", min_confidence=0.8)
    assert [c.column for c in plan.changes] == ["a_col"]
    assert [c.column for c in plan.suppressed] == ["b_col"]


def test_plan_orders_by_risk_then_node_then_column_and_carries_context() -> None:
    result = result_of(
        finding("z_col", "HIGH", 0.9),
        finding("a_col", "MEDIUM", 0.9),
        finding("b_col", "HIGH", 0.9),
    )
    plan = plan_writeback(result, min_risk="LOW")
    assert [c.column for c in plan.changes] == ["b_col", "z_col", "a_col"]
    assert plan.traced_nodes == {"n1": "n1"}
    assert plan.warnings == ["trace caveat"]
    assert plan.min_risk == "LOW"


def test_plan_is_pure_and_deterministic() -> None:
    source = MockSource()
    result = trace(source.build_graph())
    before = copy.deepcopy(result)
    first = plan_writeback(result, min_risk="LOW")
    second = plan_writeback(result, min_risk="LOW")
    assert first == second
    assert result == before
    assert source.read_markup(list(result.nodes)) == {}  # no target was ever touched


# --- diff ------------------------------------------------------------------------


def test_diff_every_action_is_reachable() -> None:
    source, plan = mock_plan("LOW")
    # unchanged: managed, identical provenance
    stg_email = next(c for c in plan.changes if (c.node_id, c.column) == ("stg_customers", "email"))
    source.set_markup(
        "stg_customers",
        "email",
        ExistingTag(
            sensitive=stg_email.tag.sensitive,
            managed=True,
            category=stg_email.tag.category,
            risk=stg_email.risk,
            confidence=stg_email.confidence,
            origin=stg_email.origin_node,
        ),
    )
    # update: managed, risk drifted
    source.set_markup(
        "stg_customers", "phone", ExistingTag(True, managed=True, category="phone", risk="LOW")
    )
    # manual: human, same sensitivity
    source.set_markup("dim_customers", "email", ExistingTag(True, managed=False, category="email"))
    # conflict: human, contradicting sensitivity
    source.set_markup(
        "dim_customers", "full_name", ExistingTag(False, managed=False, category="pii")
    )
    # stale: managed markup nothing supports
    source.set_markup(
        "mart_daily_revenue", "revenue", ExistingTag(True, managed=True, category="email")
    )

    diff = diff_writeback(plan, source)
    actions = {key: c.action for key, c in changes_by_key(diff.changes).items()}

    assert actions[("stg_customers", "email")] == "unchanged"
    assert actions[("stg_customers", "phone")] == "update"
    assert actions[("dim_customers", "email")] == "manual"
    assert actions[("dim_customers", "full_name")] == "conflict"
    assert actions[("stg_customers", "full_name")] == "add"
    assert actions[("mart_orders_enriched", "email")] == "unmatched"  # JOIN-only HIGH
    assert actions[("mart_daily_revenue", "revenue")] == "stale"
    assert {c.action for c in diff.changes} == {
        "add",
        "update",
        "unchanged",
        "manual",
        "conflict",
        "unmatched",
        "stale",
    }


def test_conflict_names_the_human_tag_and_is_never_pending() -> None:
    source, plan = mock_plan("MEDIUM")
    human = ExistingTag(False, managed=False, category="pii")
    source.set_markup("dim_customers", "email", human)
    diff = diff_writeback(plan, source)
    conflict = changes_by_key(diff.changes)[("dim_customers", "email")]
    assert conflict.action == "conflict"
    assert "human-placed pii tag (non-sensitive)" in conflict.detail
    assert conflict not in diff.pending
    apply_writeback(diff, source, confirm=True)
    assert source.read_markup(["dim_customers"])[("dim_customers", "email")] == human


def test_managed_update_detail_lists_every_drifted_field() -> None:
    source, plan = mock_plan("MEDIUM")
    source.set_markup(
        "stg_customers",
        "email",
        ExistingTag(False, managed=True, category="name", risk="LOW", confidence=0.1, origin="x"),
    )
    detail = changes_by_key(diff_writeback(plan, source).changes)[("stg_customers", "email")].detail
    assert "sensitive False -> True" in detail
    assert "category name -> email" in detail
    assert "risk LOW -> MEDIUM" in detail
    assert "confidence 0.1000 -> 0.9000" in detail
    assert "origin x -> raw_customers" in detail


def test_managed_confidence_is_compared_at_published_precision() -> None:
    plan = plan_writeback(result_of(finding("email", "MEDIUM", 0.72004)), min_risk="LOW")
    source = _Target({("n1", "email"): ExistingTag(True, True, "email", "MEDIUM", 0.72, "raw")})
    assert diff_writeback(plan, source).changes[0].action == "unchanged"


def test_stale_is_limited_to_traced_nodes() -> None:
    source, plan = mock_plan("MEDIUM")
    scoped = TagPlan(
        min_risk=plan.min_risk,
        min_confidence=plan.min_confidence,
        changes=[c for c in plan.changes if c.node_id == "stg_customers"],
        suppressed=[],
        traced_nodes={"stg_customers": "stg_customers"},
    )
    source.set_markup("dim_customers", "email", ExistingTag(True, managed=True, category="email"))
    source.set_markup("stg_customers", "segment", ExistingTag(True, managed=True, category="email"))
    diff = diff_writeback(scoped, source)
    stale = [c for c in diff.changes if c.action == "stale"]
    assert [(c.node_id, c.column) for c in stale] == [("stg_customers", "segment")]
    assert "--prune" in stale[0].detail


def test_stale_for_a_suppressed_finding_and_human_markup_is_never_stale() -> None:
    source, plan = mock_plan("HIGH")  # MEDIUM findings drop out of the plan
    source.set_markup("stg_customers", "email", ExistingTag(True, managed=True, category="email"))
    source.set_markup("stg_customers", "phone", ExistingTag(True, managed=False, category="email"))
    diff = diff_writeback(plan, source)
    stale = {(c.node_id, c.column) for c in diff.changes if c.action == "stale"}
    assert stale == {("stg_customers", "email")}


def test_diff_is_read_only() -> None:
    source, plan = mock_plan("LOW")
    diff_writeback(plan, source)
    assert source.read_markup(list(plan.traced_nodes)) == {}


def test_diff_normalises_column_case() -> None:
    plan = plan_writeback(result_of(finding("email", "MEDIUM", 0.9)), min_risk="LOW")
    target = _Target({("n1", "EMAIL"): ExistingTag(True, managed=False, category="email")})
    assert diff_writeback(plan, target).changes[0].action == "manual"


# --- apply -----------------------------------------------------------------------


class _Target:
    """A recording WritebackTarget stub with canned markup."""

    def __init__(self, markup: dict[tuple[str, str], ExistingTag] | None = None) -> None:
        self.markup = markup or {}
        self.written: list[TagChange] = []

    def read_markup(self, node_ids: Sequence[str]) -> dict[tuple[str, str], ExistingTag]:
        return self.markup

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[tuple[str, str], str]:
        return {}

    def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
        self.written.extend(changes)
        return ApplyResult(applied=list(changes), failed=[])


@pytest.mark.parametrize("confirm", [False, None, 1, "yes"])
def test_apply_refuses_without_confirm_true(confirm: object) -> None:
    source, plan = mock_plan("MEDIUM")
    diff = diff_writeback(plan, source)
    with pytest.raises(SensiflowInputError, match="confirm=True"):
        apply_writeback(diff, source, confirm=confirm)  # type: ignore[arg-type]  # not a bool on purpose
    assert source.read_markup(list(plan.traced_nodes)) == {}


def test_apply_writes_only_pending_changes() -> None:
    source, plan = mock_plan("LOW")
    source.set_markup("dim_customers", "email", ExistingTag(True, managed=False, category="email"))
    diff = diff_writeback(plan, source)
    result = apply_writeback(diff, source, confirm=True)
    assert {(c.node_id, c.column) for c in result.applied} == {
        (c.node_id, c.column) for c in diff.pending
    }
    markup = source.read_markup(list(plan.traced_nodes))
    assert markup[("dim_customers", "email")].managed is False  # human untouched
    assert ("mart_orders_enriched", "email") not in markup  # unmatched not written


def test_apply_with_nothing_pending_does_not_touch_the_target() -> None:
    plan = plan_writeback(result_of(finding("email", "MEDIUM", 0.9)), min_risk="LOW")
    target = _Target({("n1", "email"): ExistingTag(True, managed=False, category="email")})
    result = apply_writeback(diff_writeback(plan, target), target, confirm=True)
    assert result == ApplyResult(applied=[], failed=[])
    assert target.written == []


def test_partial_failure_applies_the_remainder_and_a_rerun_converges() -> None:
    source = MockSource(fail_on=[("stg_customers", "phone")])
    plan = plan_writeback(trace(source.build_graph()), min_risk="MEDIUM")
    diff = diff_writeback(plan, source)
    result = apply_writeback(diff, source, confirm=True)

    assert [(c.node_id, c.column) for c, _ in result.failed] == [("stg_customers", "phone")]
    assert len(result.applied) == len(diff.pending) - 1

    healthy = MockSource(markup=source.read_markup(list(plan.traced_nodes)))
    rerun = diff_writeback(plan, healthy)
    assert [(c.node_id, c.column) for c in rerun.pending] == [("stg_customers", "phone")]
    assert not apply_writeback(rerun, healthy, confirm=True).failed
    assert diff_writeback(plan, healthy).pending == []


# --- convergence invariant (ADR-0006 §4) --------------------------------------------


@pytest.mark.parametrize("min_risk", ["LOW", "MEDIUM", "HIGH"])
def test_convergence_retrace_is_identical_and_rediff_is_empty(min_risk: Risk) -> None:
    source = MockSource()
    before = trace(source.build_graph())
    plan = plan_writeback(before, min_risk=min_risk)
    apply_writeback(diff_writeback(plan, source), source, confirm=True)

    after = trace(source.build_graph())
    assert after == before  # no ORIGIN inflation, no lost origins

    replan = plan_writeback(after, min_risk=min_risk)
    rediff = diff_writeback(replan, source)
    assert rediff.pending == []
    assert {c.action for c in rediff.changes} <= {"unchanged", "unmatched"}


def test_apply_twice_never_duplicates() -> None:
    source = MockSource()
    plan = plan_writeback(trace(source.build_graph()), min_risk="LOW")
    first = apply_writeback(diff_writeback(plan, source), source, confirm=True)
    second = apply_writeback(diff_writeback(plan, source), source, confirm=True)
    assert first.applied
    assert second == ApplyResult(applied=[], failed=[])


def test_human_markup_on_a_descendant_seeds_and_managed_markup_does_not() -> None:
    source = MockSource()
    source.set_markup("dim_customers", "email", ExistingTag(True, managed=False, category="email"))
    source.set_markup("stg_customers", "email", ExistingTag(True, managed=True, category="email"))
    result = trace(source.build_graph())
    assert result.nodes["dim_customers"].findings["email"].risk == "ORIGIN"
    assert result.nodes["stg_customers"].findings["email"].risk == "MEDIUM"


# --- protocol / packaging ------------------------------------------------------------


def test_mock_and_stub_satisfy_the_writeback_protocol() -> None:
    assert isinstance(MockSource(), WritebackTarget)
    assert isinstance(_Target(), WritebackTarget)


def test_importing_the_dbt_connector_does_not_load_ruamel() -> None:
    code = (
        "import sys, sensiflow.sources.dbt;"
        "assert not [m for m in sys.modules if m.startswith('ruamel')]"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True)


def test_importing_the_package_does_not_load_connectors_or_optional_deps() -> None:
    code = (
        "import sys, sensiflow;"
        "bad = [m for m in sys.modules if m.startswith(('sensiflow.sources.openmetadata',"
        " 'sensiflow.sources.dbt', 'sensiflow.sources._dbt_yaml', 'httpx', 'ruamel', 'yaml'))];"
        "assert not bad, bad"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True)


# --- A6: non-output findings are core-unmatched ---------------------------------------------


class _RecordingTarget(_Target):
    def __init__(self) -> None:
        super().__init__()
        self.asked: list[TagChange] = []

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[tuple[str, str], str]:
        self.asked.extend(changes)
        return {}


def test_non_output_findings_are_unmatched_in_core_before_the_target_is_asked() -> None:
    joined = Finding("email", EMAIL, "HIGH", "x", 0.9, "raw", in_output=False)
    placed = finding("phone", "MEDIUM", 0.9)
    plan = plan_writeback(result_of(joined, placed), min_risk="LOW")
    target = _RecordingTarget()

    diff = diff_writeback(plan, target)

    by_column = {c.column: c for c in diff.changes}
    assert by_column["email"].action == "unmatched"
    assert "not part of the node's output" in by_column["email"].detail
    assert "add manually" not in by_column["email"].detail  # no paste-snippet for a phantom column
    assert by_column["phone"].action == "add"
    assert [c.column for c in target.asked] == ["phone"]
    assert by_column["email"] not in diff.pending
    assert {c.column: c.in_output for c in plan.changes} == {"email": False, "phone": True}


# --- A2 / A5: classification policy ------------------------------------------------------


def _classify(change_sensitive: bool, existing: ExistingTag | None) -> TagChange:
    from sensiflow.writeback import reclassify_change

    change = TagChange("n1", "n1", "email", PiiTag("email", change_sensitive), "MEDIUM", 0.9, "raw")
    return reclassify_change(change, existing)


def test_managed_sensitivity_downgrade_is_a_withheld_conflict() -> None:
    verdict = _classify(False, ExistingTag(True, managed=True))
    assert verdict.action == "conflict"
    assert "downgrade withheld" in verdict.detail
    assert "needs a human" in verdict.detail


def test_managed_sensitivity_upgrade_is_an_update() -> None:
    verdict = _classify(True, ExistingTag(False, managed=True))
    assert verdict.action == "update"
    assert "sensitive False -> True" in verdict.detail


def test_downgrade_conflict_is_never_pending_and_never_written() -> None:
    plan = plan_writeback(
        result_of(finding("email", "MEDIUM", 0.9, PiiTag("email", sensitive=False))),
        min_risk="LOW",
    )
    target = _Target({("n1", "email"): ExistingTag(True, managed=True, category="email")})
    diff = diff_writeback(plan, target)
    assert diff.changes[0].action == "conflict"
    assert diff.pending == []
    apply_writeback(diff, target, confirm=True)
    assert target.written == []


@pytest.mark.parametrize("sensitive", [True, False])
def test_explicit_not_pii_is_always_a_conflict_never_manual(sensitive: bool) -> None:
    verdict = _classify(sensitive, ExistingTag(False, managed=False, not_pii=True))
    assert verdict.action == "conflict"
    assert "not PII" in verdict.detail


def test_category_drift_on_managed_markup_is_an_update_only_when_the_target_stores_it() -> None:
    stored = _classify(True, ExistingTag(True, managed=True, category="phone"))
    assert stored.action == "update"
    assert "category phone -> email" in stored.detail
    unstored = _classify(True, ExistingTag(True, managed=True, category=None))
    assert unstored.action == "unchanged"


def test_confidence_drift_compares_at_published_precision() -> None:
    near = _classify(True, ExistingTag(True, managed=True, confidence=0.90004))
    assert near.action == "unchanged"
    far = _classify(True, ExistingTag(True, managed=True, confidence=0.8))
    assert far.action == "update"


def test_recheck_reason_names_the_verdict_and_its_detail() -> None:
    from sensiflow.writeback import recheck_reason

    assert recheck_reason(_classify(True, ExistingTag(True, managed=True))) == (
        "re-check found unchanged"
    )
    manual = recheck_reason(_classify(True, ExistingTag(True, managed=False, category="email")))
    assert manual == "re-check found manual: human-placed email tag (sensitive)"


# --- A4: stale detail is honest about why ------------------------------------------------------


def test_stale_detail_distinguishes_no_finding_from_a_finding_below_thresholds() -> None:
    result = result_of(finding("low_col", "LOW", 0.55), finding("hi_col", "HIGH", 0.9))
    plan = plan_writeback(result, min_risk="HIGH", min_confidence=0.8)
    assert plan.unplanned == {("n1", "low_col"): ("LOW", 0.55)}

    target = _Target(
        {
            ("n1", "low_col"): ExistingTag(True, managed=True),
            ("n1", "gone_col"): ExistingTag(True, managed=True),
        }
    )
    diff = diff_writeback(plan, target)
    stale = {c.column: c.detail for c in diff.changes if c.action == "stale"}
    assert "no current finding supports this tag" in stale["gone_col"]
    assert "below this run's thresholds (LOW, conf 0.55)" in stale["low_col"]
    assert "not a removal signal" in stale["low_col"]
    assert all("--prune" in detail for detail in stale.values())


def test_suppressed_findings_also_count_as_below_thresholds() -> None:
    plan = plan_writeback(
        result_of(finding("email", "MEDIUM", 0.5)), min_risk="LOW", min_confidence=0.9
    )
    assert plan.unplanned == {("n1", "email"): ("MEDIUM", 0.5)}
    assert plan.changes == []
    assert [c.column for c in plan.suppressed] == ["email"]


def test_origin_findings_are_not_unplanned_summaries() -> None:
    plan = plan_writeback(result_of(finding("email", "ORIGIN", 1.0)), min_risk="LOW")
    assert plan.unplanned == {}


# --- A3: ApplyResult carries skipped -----------------------------------------------------------


def test_apply_result_skipped_defaults_empty_and_is_passed_through() -> None:
    assert ApplyResult([], []).skipped == []

    class Skipping(_Target):
        def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
            return ApplyResult(applied=[], failed=[], skipped=[(changes[0], "skipped: x")])

    plan = plan_writeback(result_of(finding("email", "MEDIUM", 0.9)), min_risk="LOW")
    target = Skipping()
    result = apply_writeback(diff_writeback(plan, target), target, confirm=True)
    assert result.skipped[0][1] == "skipped: x"
    assert result.failed == []


# --- P1: one threshold implementation shared with the gate ---------------------------------------


def test_gate_and_plan_share_the_threshold_helpers() -> None:
    from sensiflow.gate import meets_confidence, validate_min_confidence, validate_risk_threshold

    assert meets_confidence(0.8 * 0.7, 0.56)
    assert meets_confidence(0.99996, 1.0)
    assert not meets_confidence(0.55994, 0.56)
    with pytest.raises(SensiflowInputError, match="min-risk threshold"):
        validate_risk_threshold("ORIGIN", "min-risk")
    with pytest.raises(SensiflowInputError, match="fail-on threshold"):
        validate_risk_threshold("NONE", "fail-on")
    validate_risk_threshold("HIGH", "min-risk")
    validate_min_confidence(1.0)
    with pytest.raises(SensiflowInputError):
        validate_min_confidence(float("nan"))
