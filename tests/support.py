"""Shared test support: synthetic OMD catalog, a stateful OMD fake, dbt manifest helpers.

Everything here is synthetic. ``FakeOmd`` serves the tables of
``tests/fixtures/omd`` through ``httpx.MockTransport`` and applies JSON Patch
documents to its own state, so write-back can be exercised end to end.
"""

from __future__ import annotations

import copy
import difflib
import json
from pathlib import Path
from typing import Any

import httpx
import yaml

from sensiflow import Risk, WritebackDiff, diff_writeback, plan_writeback, trace
from sensiflow.sources.dbt import DbtSource
from sensiflow.sources.openmetadata import OpenMetadataSource

FIXTURE_PROJECT = Path(__file__).parent / "fixtures" / "dbt_project"
FIXTURES = Path(__file__).parent / "fixtures" / "omd"
TABLES: list[dict[str, Any]] = json.loads((FIXTURES / "tables.json").read_text())
EDGES: list[dict[str, str]] = json.loads((FIXTURES / "edges.json").read_text())["edges"]
BY_FQN = {t["fullyQualifiedName"]: t for t in TABLES}
PREFIX = "demo.warehouse.crm"
TOKEN = "fake-jwt-token-123"


def lineage_payload(fqn: str) -> dict[str, Any]:
    entity = BY_FQN[fqn]
    ups = [e["from"] for e in EDGES if e["to"] == fqn]
    downs = [e["to"] for e in EDGES if e["from"] == fqn]
    return {
        "entity": {"id": entity["id"], "fullyQualifiedName": fqn, "type": "table"},
        "nodes": [
            {"id": BY_FQN[n]["id"], "fullyQualifiedName": n, "type": "table"} for n in ups + downs
        ],
        "upstreamEdges": [{"fromEntity": BY_FQN[u]["id"], "toEntity": entity["id"]} for u in ups],
        "downstreamEdges": [
            {"fromEntity": entity["id"], "toEntity": BY_FQN[d]["id"]} for d in downs
        ],
    }


def make_source(project: Path) -> DbtSource:
    return DbtSource(project / "manifest.json", project)


def run_diff(project: Path, min_risk: Risk = "LOW") -> tuple[DbtSource, WritebackDiff]:
    source = make_source(project)
    plan = plan_writeback(trace(source.build_graph()), min_risk=min_risk)
    return source, diff_writeback(plan, source)


def removed_lines(before: str, after: str) -> list[str]:
    """Lines present in ``before`` but missing from ``after`` (a line-level unified diff)."""
    return [
        line[1:]
        for line in difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=0)
        if line.startswith("-") and not line.startswith("---")
    ]


def actions(diff: WritebackDiff) -> dict[tuple[str, str], str]:
    """``{(node_id, column): action}`` for every change of a diff."""
    return {(c.node_id, c.column): c.action for c in diff.changes}


def regenerate_manifest(root: Path) -> None:
    """Simulate `dbt parse`: copy every properties file's column entries into the manifest."""
    path = root / "manifest.json"
    manifest = json.loads(path.read_text())
    by_name = {n["name"]: n for n in manifest["nodes"].values()}
    for yml in root.rglob("*.yml"):
        document = yaml.safe_load(yml.read_text()) or {}
        if not isinstance(document, dict):
            continue
        for entry in document.get("models") or []:
            node = by_name.get(entry["name"])
            if node is not None:
                node["columns"] = {
                    c["name"]: {
                        "name": c["name"],
                        "meta": c.get("meta") or {},
                        "tags": c.get("tags") or [],
                    }
                    for c in entry.get("columns") or []
                }
    path.write_text(json.dumps(manifest))


def label(fqn: str) -> dict[str, str]:
    return {
        "tagFQN": fqn,
        "source": "Classification",
        "labelType": "Automated",
        "state": "Suggested",
    }


class PatchTestFailed(Exception):
    """An RFC 6902 ``test`` operation did not match the document."""


def _resolve(document: Any, parts: list[str]) -> Any:
    target = document
    for part in parts:
        target = target[int(part)] if isinstance(target, list) else target[part]
    return target


def apply_json_patch(document: dict[str, Any], ops: list[dict[str, Any]]) -> None:
    """Apply add / replace / test operations (the only ones sensiflow may send)."""
    for op in ops:
        assert op["op"] in ("add", "replace", "test"), op
        *parents, leaf = op["path"].strip("/").split("/")
        if op["op"] == "test":
            if _resolve(document, [*parents, leaf]) != op["value"]:
                raise PatchTestFailed(op["path"])
            continue
        target: Any = _resolve(document, parents)
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
        self.edit_during_patch: set[str] = set()  # table ids modified by "someone else" first
        self.versions: dict[str, int] = {}
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
        fqn = table["fullyQualifiedName"]
        if table["id"] in self.fail_patch_for:
            return httpx.Response(500, json={"message": f"boom {TOKEN}"})
        if table["id"] in self.edit_during_patch:
            self.versions[fqn] = self.versions.get(fqn, 0) + 1
        sent = request.headers.get("if-match")
        if sent is not None and sent != self.etag(fqn):
            return httpx.Response(412, json={"message": "precondition failed"})
        try:
            apply_json_patch(table, json.loads(request.content))
        except PatchTestFailed:
            return httpx.Response(400, json={"message": "JsonPatch test operation failed"})
        self.versions[fqn] = self.versions.get(fqn, 0) + 1
        return httpx.Response(200, json=table, headers={"ETag": self.etag(fqn)})

    def etag(self, fqn: str) -> str:
        return f'"{self.versions.get(fqn, 0)}"'

    def get(self, path: str) -> httpx.Response:
        if path == "/tables":
            return httpx.Response(200, json={"data": list(self.tables.values()), "paging": {}})
        if path.startswith("/tables/name/"):
            fqn = path.removeprefix("/tables/name/")
            if fqn not in self.tables:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.tables[fqn], headers={"ETag": self.etag(fqn)})
        if path.startswith("/lineage/table/name/"):
            return httpx.Response(
                200, json=lineage_payload(path.removeprefix("/lineage/table/name/"))
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
