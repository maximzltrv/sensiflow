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
from typing import Any

import httpx
import pytest

from sensiflow import (
    ApplyResult,
    PiiTag,
    SensiflowConnectionError,
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
)
from tests.test_openmetadata import BY_FQN, PREFIX, TABLES, TOKEN, _lineage_payload

STG = f"{PREFIX}.stg_customers"
DIM = f"{PREFIX}.dim_customers"
DUMP = f"{PREFIX}.mart_customer_dump"
ENRICHED = f"{PREFIX}.mart_orders_enriched"
EMAIL = PiiTag(category="email")


def label(fqn: str) -> dict[str, str]:
    return {
        "tagFQN": fqn,
        "source": "Classification",
        "labelType": "Automated",
        "state": "Suggested",
    }


def apply_json_patch(document: dict[str, Any], ops: list[dict[str, Any]]) -> None:
    for op in ops:
        *parents, leaf = op["path"].strip("/").split("/")
        target: Any = document
        for part in parents:
            target = target[int(part)] if isinstance(target, list) else target[part]
        if isinstance(target, list):
            if op["op"] == "add":
                target.append(op["value"]) if leaf == "-" else target.insert(int(leaf), op["value"])
            else:
                assert op["op"] == "replace"
                target[int(leaf)] = op["value"]
        else:
            target[leaf] = op["value"]


class FakeOmd:
    """Stateful OMD fake: tables, the Sensiflow classification/tag, a request log."""

    def __init__(self) -> None:
        self.tables = {t["fullyQualifiedName"]: copy.deepcopy(t) for t in TABLES}
        self.classifications: set[str] = set()
        self.tags: set[str] = set()
        self.requests: list[httpx.Request] = []
        self.fail_patch_for: set[str] = set()  # table ids answering 500
        self.deny_create = False

    @property
    def patches(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == "PATCH"]

    def source(self) -> OpenMetadataSource:
        return OpenMetadataSource(
            "http://omd.test", TOKEN, transport=httpx.MockTransport(self.handle)
        )

    def by_id(self, table_id: str) -> dict[str, Any]:
        return next(t for t in self.tables.values() if t.get("id") == table_id)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/api/v1")
        if request.method == "GET":
            return self.get(path)
        if request.method == "POST":
            if self.deny_create:
                return httpx.Response(403, json={})
            body = json.loads(request.content)
            if path == "/classifications":
                self.classifications.add(body["name"])
            else:
                self.tags.add(f"{body['classification']}.{body['name']}")
            return httpx.Response(201, json=body)
        assert request.method == "PATCH"
        assert request.headers["content-type"] == "application/json-patch+json"
        table = self.by_id(path.removeprefix("/tables/"))
        if table["id"] in self.fail_patch_for:
            return httpx.Response(500, json={"message": f"boom {TOKEN}"})
        apply_json_patch(table, json.loads(request.content))
        return httpx.Response(200, json=table)

    def get(self, path: str) -> httpx.Response:
        if path == "/tables":
            return httpx.Response(200, json={"data": list(self.tables.values()), "paging": {}})
        if path.startswith("/tables/name/"):
            fqn = path.removeprefix("/tables/name/")
            if fqn not in self.tables:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.tables[fqn])
        if path.startswith("/lineage/table/name/"):
            return httpx.Response(
                200, json=_lineage_payload(path.removeprefix("/lineage/table/name/"))
            )
        if path.startswith("/classifications/name/"):
            known = path.removeprefix("/classifications/name/") in self.classifications
            return httpx.Response(200 if known else 404, json={})
        if path.startswith("/tags/name/"):
            return httpx.Response(
                200 if path.removeprefix("/tags/name/") in self.tags else 404, json={}
            )
        return httpx.Response(404, json={})

    def column(self, fqn: str, name: str) -> dict[str, Any]:
        return next(c for c in self.tables[fqn]["columns"] if c["name"] == name)

    def tag_fqns(self, fqn: str, name: str) -> list[str]:
        return [t["tagFQN"] for t in self.column(fqn, name)["tags"]]


def run_plan(omd: FakeOmd, min_risk: str = "MEDIUM") -> tuple[OpenMetadataSource, Any]:
    source = omd.source()
    result = trace(source.build_graph())
    plan = plan_writeback(result, min_risk=min_risk)  # type: ignore[arg-type]
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
    assert markup[(STG, "phone")].tag.sensitive is False
    assert markup[(STG, "full_name")].tag.sensitive is True  # sensitive wins
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
    paths = [op["path"] for op in stg_ops]
    # stg columns: customer_id=0 email=1 phone=2 full_name=3; changes sort by column name
    assert paths == [f"/columns/{i}/tags/-" for i in (1, 1, 3, 3, 2, 2)]
    assert stg_ops[0] == {"op": "add", "path": "/columns/1/tags/-", "value": label("PII.Sensitive")}
    assert stg_ops[1]["value"] == label(MARKER_TAG)
    assert all(op["op"] == "add" for op in stg_ops)


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
    assert ops[0]["path"] == "/columns/2/tags/-"  # email moved from 1 to 2


def test_changes_reclassified_by_the_recheck_are_skipped_and_reported() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.column(STG, "email")["tags"] = [label("PII.NonSensitive")]  # a human got there first
    omd.tables[STG]["columns"] = [
        c for c in omd.tables[STG]["columns"] if c["name"] != "phone"
    ]  # and a column vanished
    result = apply_writeback(diff, source, confirm=True)

    reasons = {(c.node_id.rsplit(".", 1)[1], c.column): msg for c, msg in result.failed}
    assert "human-placed PII tag appeared" in reasons[("stg_customers", "email")]
    assert "column no longer exists" in reasons[("stg_customers", "phone")]
    assert all(msg.startswith("skipped:") for msg in reasons.values())
    assert omd.tag_fqns(STG, "email") == ["PII.NonSensitive"]  # human tag never touched
    assert omd.tag_fqns(STG, "full_name") == ["PII.Sensitive", MARKER_TAG]  # rest applied
    assert omd.tag_fqns(DIM, "email") == ["PII.Sensitive", MARKER_TAG]


def test_a_table_deleted_between_diff_and_apply_fails_only_its_changes() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    del omd.tables[STG]
    result = apply_writeback(diff, source, confirm=True)
    assert {c.node_id for c, _ in result.failed} == {STG}
    assert all("table no longer exists" in msg for _, msg in result.failed)
    assert {c.node_id for c in result.applied} == {DIM}


def test_already_managed_tag_found_by_the_recheck_is_skipped_not_duplicated() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    omd.column(DIM, "email")["tags"] = [label("PII.Sensitive"), label(MARKER_TAG)]
    result = apply_writeback(diff, source, confirm=True)
    skipped = [c for c, msg in result.failed if "already carries" in msg]
    assert [(c.node_id, c.column) for c in skipped] == [(DIM, "email")]
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
    first = ops[0]
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
    assert "not in the table's schema" in change.detail
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


def test_table_entity_without_id_fails_its_changes() -> None:
    omd = FakeOmd()
    source, diff = run_plan(omd)
    del omd.tables[STG]["id"]
    result = apply_writeback(diff, source, confirm=True)
    assert {c.node_id for c, _ in result.failed} == {STG}
    assert "no id" in result.failed[0][1]
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
    assert ops[0]["path"] == "/columns/3/tags"


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
    assert "result: APPLIED — 3 applied, 2 failed" in captured.out
    assert TOKEN not in captured.out + captured.err

    omd.fail_patch_for.clear()
    assert main([*base, "--apply", "--yes"]) == 0
    assert "result: APPLIED — 2 applied, 0 failed" in capsys.readouterr().out
