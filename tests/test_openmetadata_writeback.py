"""OpenMetadata write-back contract tests (ADR-0006 §4-§5).

A stateful fake of the OMD v1 API (httpx.MockTransport) serves the synthetic
catalog from tests/fixtures/omd/ and applies JSON Patch documents to its own
state, so write-back can be exercised end to end: apply, then re-read. The
fake records every request, which is how the wire contract is asserted
(one PATCH per table, index paths, TagLabel fields, marker creation).
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from typing import Any

import httpx
import pytest

from sensiflow import (
    ApplyResult,
    GraphSelection,
    PiiTag,
    Risk,
    SensiflowConnectionError,
    SensiflowInputError,
    TagChange,
    apply_writeback,
    diff_writeback,
    plan_writeback,
    trace,
)
from sensiflow.sources.openmetadata import (
    MARKER_TAG,
    OpenMetadataSource,
    _declared_pii,
    _markup_of,
    _unsafe_fqn,
)
from tests.support import BY_FQN, PREFIX, TOKEN, FakeOmd, label

STG = f"{PREFIX}.stg_customers"
DIM = f"{PREFIX}.dim_customers"
DUMP = f"{PREFIX}.mart_customer_dump"
ENRICHED = f"{PREFIX}.mart_orders_enriched"
EMAIL = PiiTag(category="email")


def run_plan(omd: FakeOmd, min_risk: Risk = "MEDIUM") -> tuple[OpenMetadataSource, Any]:
    source = omd.source()
    result = trace(source.build_graph())
    plan = plan_writeback(result, min_risk=min_risk)
    return source, diff_writeback(plan, source)


# --- reader side ----------------------------------------------------------------------


def test_declared_pii_skips_columns_carrying_the_marker() -> None:
    table = {
        "columns": [
            {"name": "email", "tags": [{"tagFQN": "PII.Sensitive"}]},
            {"name": "phone", "tags": [{"tagFQN": "PII.Sensitive"}, {"tagFQN": MARKER_TAG}]},
            {"name": "note", "tags": [{"tagFQN": MARKER_TAG}]},
        ]
    }
    assert set(_declared_pii(table)) == {"email"}


def test_read_markup_distinguishes_managed_from_human_by_the_marker() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = [label("PII.Sensitive"), label(MARKER_TAG)]
    omd.column(STG, "phone")["tags"] = [label("PII.NonSensitive")]
    omd.column(STG, "full_name")["tags"] = [label("PII.Sensitive"), label("PII.NonSensitive")]
    omd.column(STG, "customer_id")["tags"] = [label("Tier.Tier1")]
    markup = omd.source().read_markup([STG, f"{PREFIX}.missing_table"])

    assert set(markup) == {(STG, "email"), (STG, "phone"), (STG, "full_name")}
    assert markup[(STG, "email")].managed is True
    assert markup[(STG, "phone")].managed is False
    assert markup[(STG, "phone")].sensitive is False
    assert markup[(STG, "full_name")].sensitive is True  # sensitive wins
    fields = [r.url.params["fields"] for r in omd.requests]
    assert set(fields) == {"columns,tags"}


def test_marked_columns_do_not_reseed_the_trace() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = [label("PII.Sensitive"), label(MARKER_TAG)]
    graph = omd.source().build_graph()
    assert "email" not in graph.nodes[STG].declared_pii


# --- wire contract --------------------------------------------------------------------


def test_apply_sends_one_json_patch_per_table_with_index_paths_and_labels() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd, "MEDIUM")
    result = apply_writeback(diff, source, confirm=True)

    assert not result.failed
    assert len(result.applied) == 5
    patched = {r.url.path for r in omd.patches}
    assert patched == {
        f"/api/v1/tables/{omd.tables[STG]['id']}",
        f"/api/v1/tables/{omd.tables[DIM]['id']}",
    }
    assert len(omd.patches) == 2  # one PATCH per table, never per column

    stg_ops = json.loads(
        next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path).content
    )
    assert {op["op"] for op in stg_ops} == {"test", "add"}  # nothing else may ever be sent
    # stg columns: customer_id=0 email=1 phone=2 full_name=3; changes sort by column name.
    # Each touched column is pinned by a name test before its first add.
    assert [(op["op"], op["path"]) for op in stg_ops] == [
        ("test", "/columns/1/name"),
        ("add", "/columns/1/tags/-"),
        ("add", "/columns/1/tags/-"),
        ("test", "/columns/3/name"),
        ("add", "/columns/3/tags/-"),
        ("add", "/columns/3/tags/-"),
        ("test", "/columns/2/name"),
        ("add", "/columns/2/tags/-"),
        ("add", "/columns/2/tags/-"),
    ]
    assert stg_ops[0]["value"] == "email"
    assert stg_ops[1] == {"op": "add", "path": "/columns/1/tags/-", "value": label("PII.Sensitive")}
    assert stg_ops[2]["value"] == label(MARKER_TAG)


def test_patch_carries_the_etag_of_the_refetch_as_if_match() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.versions[STG] = 7
    apply_writeback(diff, source, confirm=True)
    stg_patch = next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path)
    assert stg_patch.headers["if-match"] == '"7"'


def test_apply_end_to_end_state_and_convergence() -> None:
    omd = FakeOmd()
    source = omd.source()
    before = trace(source.build_graph())
    plan = plan_writeback(before, min_risk="LOW")
    result = apply_writeback(diff_writeback(plan, source), source, confirm=True)
    assert not result.failed
    assert omd.tag_fqns(STG, "email") == ["PII.Sensitive", MARKER_TAG]
    assert omd.tag_fqns(ENRICHED, "segment") == []  # JOIN-only email: not placeable, untouched

    # Convergence: same findings after the apply, nothing pending on re-diff.
    after = trace(source.build_graph())
    assert after == before
    rediff = diff_writeback(plan_writeback(after, min_risk="LOW"), source)
    assert rediff.pending == []
    assert {c.action for c in rediff.changes} == {"unchanged", "unmatched"}

    # And re-applying writes nothing at all.
    patches_before = len(omd.patches)
    assert apply_writeback(rediff, source, confirm=True) == ApplyResult([], [])
    assert len(omd.patches) == patches_before


def test_marker_classification_and_tag_are_created_once() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    creates = [(r.url.path, json.loads(r.content)) for r in omd.requests if r.method == "POST"]
    assert [path for path, _ in creates] == ["/api/v1/classifications", "/api/v1/tags"]
    assert creates[0][1]["name"] == "Sensiflow"
    assert creates[1][1]["classification"] == "Sensiflow"
    assert creates[1][1]["name"] == "Propagated"
    assert omd.classifications == {"Sensiflow"}
    assert omd.tags == {MARKER_TAG}

    # A second apply (fresh diff after state changed) must not create again.
    omd.requests.clear()
    omd.column(STG, "phone")["tags"] = []
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    assert not [r for r in omd.requests if r.method == "POST"]


def test_marker_creation_conflict_is_treated_as_exists() -> None:
    omd = FakeOmd()
    original = omd.handle

    def racing(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            omd.requests.append(request)
            return httpx.Response(409, json={})
        return original(request)

    source = OpenMetadataSource("http://omd.test", TOKEN, transport=httpx.MockTransport(racing))
    plan = plan_writeback(trace(source.build_graph()), min_risk="MEDIUM")
    result = apply_writeback(diff_writeback(plan, source), source, confirm=True)
    assert not result.failed


def test_marker_creation_failure_aborts_before_any_patch() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.deny_create = True
    with pytest.raises(SensiflowConnectionError, match="403"):
        apply_writeback(diff, source, confirm=True)
    assert omd.patches == []


# --- pre-patch re-fetch ------------------------------------------------------------------


def test_indexes_are_computed_from_a_fresh_fetch_not_the_plan() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    # The table changed after the diff: a column was inserted at the front.
    omd.tables[STG]["columns"].insert(0, {"name": "new_first", "tags": []})
    result = apply_writeback(diff, source, confirm=True)
    assert not result.failed
    assert omd.tag_fqns(STG, "email") == ["PII.Sensitive", MARKER_TAG]
    ops = json.loads(next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path).content)
    assert ops[0] == {"op": "test", "path": "/columns/2/name", "value": "email"}
    assert ops[1]["path"] == "/columns/2/tags/-"  # email moved from 1 to 2


def test_changes_reclassified_by_the_recheck_are_skipped_and_reported() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.column(STG, "email")["tags"] = [label("PII.NonSensitive")]  # a human got there first
    omd.tables[STG]["columns"] = [
        c for c in omd.tables[STG]["columns"] if c["name"] != "phone"
    ]  # and a column vanished
    result = apply_writeback(diff, source, confirm=True)

    assert result.failed == []  # nothing was attempted and broken: skips are not failures
    reasons = {(c.node_id.rsplit(".", 1)[1], c.column): msg for c, msg in result.skipped}
    assert "re-check found conflict" in reasons[("stg_customers", "email")]
    assert "human-placed" in reasons[("stg_customers", "email")]
    assert "column no longer exists" in reasons[("stg_customers", "phone")]
    assert all(msg.startswith("skipped:") for msg in reasons.values())
    assert omd.tag_fqns(STG, "email") == ["PII.NonSensitive"]  # human tag never touched
    assert omd.tag_fqns(STG, "full_name") == ["PII.Sensitive", MARKER_TAG]  # rest applied
    assert omd.tag_fqns(DIM, "email") == ["PII.Sensitive", MARKER_TAG]


def test_a_table_deleted_between_diff_and_apply_skips_only_its_changes() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    del omd.tables[STG]
    result = apply_writeback(diff, source, confirm=True)
    assert result.failed == []
    assert {c.node_id for c, _ in result.skipped} == {STG}
    assert all("table no longer exists" in msg for _, msg in result.skipped)
    assert {c.node_id for c in result.applied} == {DIM}


def test_already_managed_tag_found_by_the_recheck_is_skipped_not_duplicated() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.column(DIM, "email")["tags"] = [label("PII.Sensitive"), label(MARKER_TAG)]
    result = apply_writeback(diff, source, confirm=True)
    skipped = [c for c, msg in result.skipped if "re-check found unchanged" in msg]
    assert [(c.node_id, c.column) for c in skipped] == [(DIM, "email")]
    assert result.failed == []
    assert omd.tag_fqns(DIM, "email") == ["PII.Sensitive", MARKER_TAG]


# --- shapes and updates -------------------------------------------------------------------


def test_update_replaces_the_managed_pii_label_in_place() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = [label(MARKER_TAG), label("PII.NonSensitive")]
    source, diff = run_plan(omd)
    update = next(c for c in diff.changes if c.action == "update")
    assert (update.node_id, update.column) == (STG, "email")
    result = apply_writeback(diff, source, confirm=True)
    assert not result.failed
    ops = json.loads(next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path).content)
    assert {"op": "replace", "path": "/columns/1/tags/1", "value": label("PII.Sensitive")} in ops
    assert omd.tag_fqns(STG, "email") == [MARKER_TAG, "PII.Sensitive"]


def test_column_without_a_tags_array_gets_one_created() -> None:
    omd = FakeOmd()
    del omd.column(STG, "email")["tags"]
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    ops = json.loads(next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path).content)
    first = next(op for op in ops if op["op"] == "add")
    assert first["path"] == "/columns/1/tags"
    assert first["value"] == [label("PII.Sensitive"), label(MARKER_TAG)]
    assert omd.tag_fqns(STG, "email") == ["PII.Sensitive", MARKER_TAG]


def test_marker_alone_is_not_duplicated_when_the_pii_label_is_added() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = [label(MARKER_TAG)]
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    assert omd.tag_fqns(STG, "email") == [MARKER_TAG, "PII.Sensitive"]


def test_non_sensitive_derivation_writes_the_non_sensitive_label() -> None:
    omd = FakeOmd()
    source = omd.source()
    change = TagChange(
        STG, "stg_customers", "phone", PiiTag("phone", sensitive=False), "MEDIUM", 0.9, "raw"
    )
    assert not source.write_changes([change]).failed
    assert omd.tag_fqns(STG, "phone") == ["PII.NonSensitive", MARKER_TAG]


# --- unmatched / failure isolation ----------------------------------------------------------


def test_join_only_high_finding_is_unmatched_with_a_reason() -> None:
    omd = FakeOmd()
    _, diff = run_plan(omd, "HIGH")
    [change] = diff.changes
    assert (change.node_id, change.column, change.action) == (ENRICHED, "email", "unmatched")
    assert "not part of the node's output" in change.detail
    assert "add manually" not in change.detail  # no snippet may invite pasting a phantom column
    assert diff.pending == []


def test_find_unmatched_reports_a_missing_table() -> None:
    omd = FakeOmd()
    change = TagChange(f"{PREFIX}.gone", "gone", "email", EMAIL, "MEDIUM", 0.9, "raw")
    reasons = omd.source().find_unmatched([change])
    assert reasons == {(f"{PREFIX}.gone", "email"): "table not found in OpenMetadata"}


def test_failed_patch_fails_only_that_tables_changes_without_leaking_the_token() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.fail_patch_for.add(omd.tables[DIM]["id"])
    result = apply_writeback(diff, source, confirm=True)

    assert {c.node_id for c, _ in result.failed} == {DIM}
    assert {c.node_id for c in result.applied} == {STG}
    for _, message in result.failed:
        assert "500" in message
        assert TOKEN not in message
    assert omd.tag_fqns(STG, "email") == ["PII.Sensitive", MARKER_TAG]
    assert omd.tag_fqns(DIM, "email") == []

    # A re-run converges on the remainder.
    omd.fail_patch_for.clear()
    source, rediff = run_plan(omd)
    assert {c.node_id for c in rediff.pending} == {DIM}
    assert not apply_writeback(rediff, source, confirm=True).failed


def test_unreachable_catalog_during_patch_fails_the_table_not_the_run() -> None:
    omd = FakeOmd()
    _, diff = run_plan(omd)

    def dead(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            raise httpx.ConnectError("connection refused")
        return omd.handle(request)

    flaky = OpenMetadataSource("http://omd.test", TOKEN, transport=httpx.MockTransport(dead))
    result = apply_writeback(diff, flaky, confirm=True)
    assert len(result.failed) == len(diff.pending)
    assert all("cannot reach OpenMetadata" in msg and TOKEN not in msg for _, msg in result.failed)


def test_write_changes_with_no_changes_does_no_io() -> None:
    omd = FakeOmd()
    assert omd.source().write_changes([]) == ApplyResult([], [])
    assert omd.requests == []


@pytest.mark.parametrize("bad_id", [None, "", "not-a-uuid", "../tables/other", 42])
def test_table_entity_without_a_valid_uuid_is_skipped_never_patched(bad_id: object) -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.tables[STG]["id"] = bad_id
    result = apply_writeback(diff, source, confirm=True)
    assert {c.node_id for c, _ in result.skipped} == {STG}
    assert "no valid id" in result.skipped[0][1]
    assert {r.url.path for r in omd.patches} == {f"/api/v1/tables/{omd.tables[DIM]['id']}"}
    assert BY_FQN  # fixture sanity: other tables untouched


# --- malformed payloads and the CLI path ---------------------------------------------------------


def test_malformed_catalog_entries_never_abort_markup_reading() -> None:
    omd = FakeOmd()
    omd.tables[STG]["columns"] = [
        "not-a-dict",
        {"tags": [label("PII.Sensitive")]},  # no name
        {"name": "email", "tags": ["junk", {"nope": 1}, label("PII.Sensitive")]},
        {"name": "phone", "tags": None},
    ]
    source = omd.source()
    assert set(source.read_markup([STG])) == {(STG, "email")}
    change = TagChange(STG, "stg_customers", "phone", EMAIL, "MEDIUM", 0.9, "raw")
    assert not source.write_changes([change]).failed
    # indexes are positions in the raw payload, junk entries included
    ops = json.loads(omd.patches[0].content)
    assert [op["path"] for op in ops if op["op"] == "add"] == ["/columns/3/tags"]


def test_cli_dry_run_and_apply_against_the_catalog(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sensiflow.cli import main

    omd = FakeOmd()
    monkeypatch.setattr(
        "sensiflow.sources.openmetadata.OpenMetadataSource", lambda host, token: omd.source()
    )
    base = ["propagate", "--source", "openmetadata", "--omd-host", "http://omd.test",
            "--omd-token", TOKEN, "--min-risk", "medium"]  # fmt: skip

    assert main(base) == 0
    assert "result: DRY-RUN — 5 changes pending" in capsys.readouterr().out
    assert omd.patches == []  # dry-run never mutates

    omd.fail_patch_for.add(omd.tables[DIM]["id"])
    assert main([*base, "--apply", "--yes"]) == 3
    captured = capsys.readouterr()
    assert "result: PARTIAL — 3 applied, 0 skipped, 2 failed" in captured.out
    assert TOKEN not in captured.out + captured.err

    omd.fail_patch_for.clear()
    assert main([*base, "--apply", "--yes"]) == 0
    assert "result: APPLIED — 2 applied, 0 skipped, 0 failed" in capsys.readouterr().out


# --- A1: managed needs the marker AND an unconfirmed Automated label ----------------------------


def _tag(fqn: str, label_type: str | None = "Automated", state: str | None = "Suggested") -> Any:
    tag: dict[str, Any] = {"tagFQN": fqn, "source": "Classification"}
    if label_type is not None:
        tag["labelType"] = label_type
    if state is not None:
        tag["state"] = state
    return tag


@pytest.mark.parametrize(
    ("tags", "managed"),
    [
        ([_tag("PII.Sensitive"), _tag(MARKER_TAG)], True),
        ([_tag("PII.Sensitive", "Automated", "Confirmed"), _tag(MARKER_TAG)], False),
        ([_tag("PII.Sensitive", "Manual", "Confirmed"), _tag(MARKER_TAG)], False),
        ([_tag("PII.Sensitive", "Manual", "Suggested"), _tag(MARKER_TAG)], False),
        ([_tag("PII.Sensitive", "Propagated", "Suggested"), _tag(MARKER_TAG)], False),
        ([_tag("PII.Sensitive", None, None), _tag(MARKER_TAG)], False),
        ([_tag("PII.Sensitive")], False),  # Automated + Suggested but no marker: not ours
    ],
)
def test_managed_is_marker_plus_unconfirmed_automated_label(tags: list[Any], managed: bool) -> None:
    existing, slot = _markup_of({"name": "email", "tags": tags})
    assert existing is not None
    assert existing.managed is managed
    assert (slot is not None) is managed


def test_a_steward_confirmed_label_is_never_updated_or_replaced() -> None:
    omd = FakeOmd()
    confirmed = _tag("PII.NonSensitive", "Automated", "Confirmed")
    omd.column(STG, "email")["tags"] = [confirmed, label(MARKER_TAG)]
    source, diff = run_plan(omd)
    email = next(c for c in diff.changes if (c.node_id, c.column) == (STG, "email"))
    assert email.action == "conflict"  # derived sensitive vs the human-ratified non-sensitive
    apply_writeback(diff, source, confirm=True)
    assert omd.column(STG, "email")["tags"] == [confirmed, label(MARKER_TAG)]


def test_marker_spoofed_next_to_a_human_label_does_not_grant_authority() -> None:
    omd = FakeOmd()
    human = _tag("PII.Sensitive", "Manual", "Confirmed")
    omd.column(STG, "email")["tags"] = [human, label(MARKER_TAG)]
    _, diff = run_plan(omd)
    email = next(c for c in diff.changes if (c.node_id, c.column) == (STG, "email"))
    assert email.action == "manual"
    assert not any(c.action == "update" for c in diff.changes)


# --- A2: the tool never reduces protection on its own -------------------------------------------


def test_managed_sensitive_label_is_not_downgraded_by_a_non_sensitive_derivation() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = [label("PII.Sensitive"), label(MARKER_TAG)]
    source = omd.source()
    plan = plan_writeback(trace(source.build_graph()), min_risk="LOW")
    # Same finding, but now derived non-sensitive.
    flipped = [replace(c, tag=PiiTag(c.tag.category, False)) for c in plan.changes]
    plan.changes[:] = flipped
    diff = diff_writeback(plan, source)
    email = next(c for c in diff.changes if (c.node_id, c.column) == (STG, "email"))
    assert email.action == "conflict"
    assert "downgrade withheld" in email.detail
    apply_writeback(diff, source, confirm=True)
    assert omd.tag_fqns(STG, "email") == ["PII.Sensitive", MARKER_TAG]


def test_a_downgrade_that_appears_between_diff_and_apply_is_skipped_live() -> None:
    omd = FakeOmd()
    source = omd.source()
    change = TagChange(STG, "stg_customers", "email", PiiTag("email", False), "MEDIUM", 0.9, "raw")
    omd.column(STG, "email")["tags"] = [label("PII.Sensitive"), label(MARKER_TAG)]  # after the diff
    result = source.write_changes([change])
    assert result.applied == [] and result.failed == []
    assert "downgrade withheld" in result.skipped[0][1]
    assert omd.patches == []


# --- A7: hostile identifiers ---------------------------------------------------------------------

HOSTILE = [
    "svc.a#b",
    "svc.a?x=1",
    "..",
    "svc.a..b",
    "svc.a%2e%2e",
    "svc.a%2Fb",
    "svc.a/b",
    "svc.a\\b",
    "svc.a;b",
    "svc.a\nb",
    "svc.a\x00b",
    "svc.a\x7fb",
    "",
]


@pytest.mark.parametrize("fqn", HOSTILE)
def test_unsafe_fqns_are_recognised(fqn: str) -> None:
    assert _unsafe_fqn(fqn)


@pytest.mark.parametrize(
    "fqn", [f"{PREFIX}.stg_customers", 'svc."db.name".schema.tbl', "svc.db.sch.t-1_x", "svc.é.t"]
)
def test_ordinary_fqns_are_safe(fqn: str) -> None:
    assert not _unsafe_fqn(fqn)


@pytest.mark.parametrize("fqn", HOSTILE)
def test_write_path_never_sends_a_request_for_an_unsafe_fqn(fqn: str) -> None:
    omd = FakeOmd()
    source = omd.source()
    change = TagChange(fqn, "t", "email", EMAIL, "MEDIUM", 0.9, "raw")
    assert source.read_markup([fqn]) == {}
    assert "not safe" in source.find_unmatched([change])[(fqn, "email")]
    result = source.write_changes([change])
    assert result.applied == [] and result.failed == []
    assert "not safe" in result.skipped[0][1]
    assert omd.requests == []  # no GET, no marker creation, nothing


@pytest.mark.parametrize("fqn", [h for h in HOSTILE if h])
def test_hostile_lineage_neighbours_are_skipped_with_a_warning(fqn: str) -> None:
    omd = FakeOmd()
    original = omd.get

    def get(path: str) -> httpx.Response:
        response = original(path)
        if path.startswith("/lineage/table/name/") and path.endswith("stg_customers"):
            payload = json.loads(response.content)
            payload["nodes"].append({"id": "evil-id", "fullyQualifiedName": fqn})
            payload["downstreamEdges"].append(
                {"fromEntity": payload["entity"]["id"], "toEntity": "evil-id"}
            )
            return httpx.Response(200, json=payload)
        return response

    omd.get = get  # type: ignore[method-assign]  # test seam: wrap the fake's GET handler
    graph = omd.source().build_graph(GraphSelection(roots=(STG,), upstream_depth=0))
    assert fqn not in graph.nodes
    assert any(w.startswith("skipped 1 catalog entries") for w in graph.warnings)
    assert all(fqn not in str(r.url) for r in omd.requests)
    assert STG in graph.nodes  # the rest of the run is unaffected


def test_a_hostile_name_in_the_full_scan_listing_is_skipped_not_fatal() -> None:
    omd = FakeOmd()
    hostile = copy.deepcopy(omd.tables[STG])
    hostile["fullyQualifiedName"] = "svc.a/b"
    omd.tables["svc.a/b"] = hostile
    graph = omd.source().build_graph()
    assert "svc.a/b" not in graph.nodes
    assert STG in graph.nodes
    assert any("skipped 1 catalog entries" in w for w in graph.warnings)


def test_a_hostile_explicit_root_is_a_usage_error_without_any_request() -> None:
    omd = FakeOmd()
    with pytest.raises(SensiflowInputError, match="not valid in a catalog name"):
        omd.source().build_graph(GraphSelection(roots=("svc.a/../b",)))
    assert omd.requests == []


def test_hostile_names_found_by_patterns_or_seeds_are_dropped_with_a_warning() -> None:
    omd = FakeOmd()
    hostile = copy.deepcopy(omd.tables[STG])
    hostile["fullyQualifiedName"] = "svc.a#b"
    hostile["name"] = "stg_evil"
    omd.tables["svc.a#b"] = hostile
    graph = omd.source().build_graph(GraphSelection(patterns=("stg_*",), upstream_depth=0))
    assert "svc.a#b" not in graph.nodes
    assert any("skipped 1 catalog entries" in w for w in graph.warnings)
    seeded = omd.source().build_graph(GraphSelection(from_seeds=True))
    assert "svc.a#b" not in seeded.nodes


def test_fqns_are_percent_encoded_in_every_name_url() -> None:
    omd = FakeOmd()
    quoted = 'svc."db.name".sch.tbl'
    table = copy.deepcopy(omd.tables[STG])
    table.update(fullyQualifiedName=quoted, id="00000000-0000-0000-0000-0000000000aa")
    omd.tables[quoted] = table
    omd.column(quoted, "email")["tags"] = [label("PII.Sensitive")]
    assert omd.source().read_markup([quoted])
    raw = [r.url.raw_path for r in omd.requests]
    assert raw == [b"/api/v1/tables/name/svc.%22db.name%22.sch.tbl?fields=columns%2Ctags"]


def test_an_entity_answering_to_another_name_is_never_used() -> None:
    omd = FakeOmd()
    original = omd.get

    def get(path: str) -> httpx.Response:
        if path == f"/tables/name/{STG}":
            return original(f"/tables/name/{DIM}")  # the server returns a different table
        return original(path)

    omd.get = get  # type: ignore[method-assign]  # test seam: wrap the fake's GET handler
    source = omd.source()
    assert source.read_markup([STG]) == {}
    change = TagChange(STG, "stg_customers", "email", EMAIL, "MEDIUM", 0.9, "raw")
    assert source.find_unmatched([change])[(STG, "email")] == "table not found in OpenMetadata"
    result = source.write_changes([change])
    assert "does not match the requested name" in result.skipped[0][1]
    assert omd.patches == []
    graph = source.build_graph(GraphSelection(roots=(STG,), upstream_depth=0, downstream_depth=0))
    assert STG not in graph.nodes
    assert any("skipped 1 catalog entries" in w for w in graph.warnings)


# --- concurrent modification: test ops, If-Match, 412 ------------------------------------------


def test_a_concurrent_edit_makes_the_if_match_fail_and_skips_the_table() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.edit_during_patch.add(omd.tables[STG]["id"])
    result = apply_writeback(diff, source, confirm=True)
    assert result.failed == []
    assert {c.node_id for c, _ in result.skipped} == {STG}
    assert all("modified concurrently; re-run" in msg for _, msg in result.skipped)
    assert {c.node_id for c in result.applied} == {DIM}
    assert omd.tag_fqns(STG, "email") == []  # nothing was written to the raced table


def test_a_failed_patch_test_operation_fails_closed_with_a_concurrency_hint() -> None:
    omd = FakeOmd()
    _, diff = run_plan(omd)
    original = omd.handle

    def reorder_before_patch(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH" and omd.tables[STG]["id"] in request.url.path:
            omd.tables[STG]["columns"].reverse()  # the name tests no longer match; no ETag help
            request = httpx.Request(
                "PATCH",
                request.url,
                content=request.content,
                headers={"content-type": "application/json-patch+json"},
            )
        return original(request)

    flaky = OpenMetadataSource(
        "http://omd.test", TOKEN, transport=httpx.MockTransport(reorder_before_patch)
    )
    result = apply_writeback(diff, flaky, confirm=True)
    assert {c.node_id for c, _ in result.failed} == {STG}
    assert all(
        msg == "write rejected (possibly concurrent modification)" for _, msg in result.failed
    )
    assert result.skipped == []  # only a 412 is a benign skip


def test_replace_operations_pin_the_label_they_replace() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = [label(MARKER_TAG), label("PII.NonSensitive")]
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    ops = json.loads(next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path).content)
    tests = [op for op in ops if op["op"] == "test"]
    assert {"op": "test", "path": "/columns/1/tags/1/tagFQN", "value": "PII.NonSensitive"} in tests
    assert {"op": "test", "path": "/columns/1/name", "value": "email"} in tests


@pytest.mark.parametrize(
    "message", ["malformed patch", "invalid column contest_name", "test operation failed", ""]
)
def test_every_400_fails_closed_whatever_its_message(message: str) -> None:
    omd = FakeOmd()
    _, diff = run_plan(omd)
    original = omd.handle

    def bad_request(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            return httpx.Response(400, json={"message": message})
        return original(request)

    broken = OpenMetadataSource(
        "http://omd.test", TOKEN, transport=httpx.MockTransport(bad_request)
    )
    result = apply_writeback(diff, broken, confirm=True)
    assert result.skipped == []
    assert len(result.failed) == len(diff.pending)
    assert all("write rejected" in msg for _, msg in result.failed)


# --- skip-only runs mutate nothing; hostile payload shapes --------------------------------------


def test_a_run_whose_changes_are_all_skipped_never_creates_the_marker() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.tables.clear()
    result = apply_writeback(diff, source, confirm=True)
    assert result.applied == [] and result.failed == []
    assert len(result.skipped) == len(diff.pending)
    assert not [r for r in omd.requests if r.method in ("POST", "PATCH")]


def test_a_non_object_payload_is_a_clean_connection_error() -> None:
    omd = FakeOmd()
    original = omd.handle

    def listy(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/tables/name/" in request.url.path:
            return httpx.Response(200, json=["not", "an", "object"])
        return original(request)

    source = OpenMetadataSource("http://omd.test", TOKEN, transport=httpx.MockTransport(listy))
    with pytest.raises(SensiflowConnectionError, match="unexpected payload shape"):
        source.read_markup([STG])
    change = TagChange(STG, "stg_customers", "email", EMAIL, "MEDIUM", 0.9, "raw")
    result = source.write_changes([change])
    assert [m for _, m in result.failed] == [
        f"unexpected payload shape from http://omd.test for /tables/name/{STG}"
    ]


# --- round-2 hardening ---


@pytest.mark.parametrize("fqn", [".", ".x", "svc.", "svc.db.", ".."])
def test_dot_only_and_edge_dot_names_are_unsafe(fqn: str) -> None:
    assert _unsafe_fqn(fqn)


def test_a_single_dot_never_reaches_the_wire() -> None:
    omd = FakeOmd()
    change = TagChange(".", "t", "email", EMAIL, "MEDIUM", 0.9, "raw")
    assert omd.source().write_changes([change]).skipped
    assert omd.requests == []


def test_a_null_tags_array_is_pinned_before_the_whole_array_add() -> None:
    omd = FakeOmd()
    omd.column(STG, "email")["tags"] = None
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    ops = json.loads(next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path).content)
    position = ops.index({"op": "test", "path": "/columns/1/tags", "value": None})
    assert ops[position + 1]["op"] == "add"
    assert ops[position + 1]["path"] == "/columns/1/tags"
    assert omd.tag_fqns(STG, "email") == ["PII.Sensitive", MARKER_TAG]


def test_an_absent_tags_key_relies_on_if_match_not_a_null_test() -> None:
    omd = FakeOmd()
    del omd.column(STG, "email")["tags"]
    source, diff = run_plan(omd)
    apply_writeback(diff, source, confirm=True)
    stg_patch = next(r for r in omd.patches if omd.tables[STG]["id"] in r.url.path)
    assert "if-match" in stg_patch.headers
    assert {"op": "test", "path": "/columns/1/tags", "value": None} not in json.loads(
        stg_patch.content
    )
