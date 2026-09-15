# ADR-0002: OpenMetadata connector — thin REST client behind an optional extra

- **Status:** Proposed (awaiting author review)
- **Date:** 2026-08-27
- **Deciders:** Maksim Zolotarev

## Context

The engine and report pipeline work end-to-end against the mock source
(ADR-0001). The next slice is the first real connector: OpenMetadata (OMD).
It must produce a `LineageGraph` — nothing more — via the existing
`LineageSource` protocol: `build_graph(root) -> LineageGraph`.

What the connector needs from OMD (all read-only):

1. **Tables with columns, tags, and owners** — to find PII-tagged columns
   (OMD built-in classification `PII.Sensitive` / `PII.NonSensitive`) and to
   attribute nodes to owners.
2. **Lineage edges** (table-level; column-level where available) — to build
   `Node.upstream`.
3. **Transformation SQL where OMD has it** (view definitions, dbt-ingested
   model SQL) — to enable HIGH/MEDIUM classification; its absence must be
   tolerated (engine degrades per ADR-0001).

Forces:

- **Dependency weight.** The official Python SDK ships inside
  `openmetadata-ingestion` — a heavy package (pydantic model tree for the
  entire OMD schema, many transitive dependencies) whose version is coupled
  to the server release. We need 3–4 GET endpoints.
- **Core install must stay light** (packaging model, PROJECT_CONTEXT §4):
  connectors are optional extras; nothing under `sources/` beyond
  `base`/`mock` may be imported at package import time.
- **Secrets hygiene.** The JWT token comes from the user at runtime and must
  never appear in logs, exceptions, or reports.
- **Offline testability.** CI has no OMD server; the connector must be fully
  testable from recorded API responses.

## Decision

### 1. Thin REST client on `httpx`, not the official SDK

`sources/openmetadata.py` implements a minimal client over the OMD REST API
(`/api/v1/...`) using **`httpx`** as the only extra dependency:

```toml
[project.optional-dependencies]
openmetadata = ["httpx>=0.27"]
```

Rationale: we consume a handful of stable read endpoints; the SDK would add
tens of megabytes and a server-version coupling for zero functional gain.
`httpx` over `requests`: first-class type hints (we are mypy-strict), same
sync API, async available later if ever needed.

Endpoints used (v1, all GET):

| Purpose | Endpoint |
|---------|----------|
| List tables (paginated) | `/api/v1/tables?fields=columns,tags,owners&limit=...&after=...` |
| Single table by FQN | `/api/v1/tables/name/{fqn}?fields=columns,tags,owners` |
| Lineage of a table | `/api/v1/lineage/table/name/{fqn}?upstreamDepth=N&downstreamDepth=N` |

SQL is taken from the table entity itself (`schemaDefinition` /
view definition fields), when present.

### 2. Import guard: the extra is missing → clear error, not ImportError

`sources/openmetadata.py` imports `httpx` lazily inside the class. If the
extra is not installed, raise `SensiflowDependencyError` with the exact fix:
`pip install 'sensiflow[openmetadata]'`. The CLI imports this module only
when `--source openmetadata` is requested — base install stays clean.

### 3. Graph construction: lineage walk from one or more roots, or full scan

`OpenMetadataSource(host, jwt_token, *, timeout=30.0)
    .build_graph(roots=None, *, max_depth=None)`:

- **`roots` given** (one or more table FQNs; decided 2026-09-15 — a list, not
  a single value): BFS over the lineage endpoint from every root at once
  (upstream + downstream), deduplicating shared ancestors/descendants, and
  build the graph from the union of the reached closures. One root is just a
  list of one. This is the recommended, cheap path.
- **`roots=None`**: paginate over all tables, then resolve lineage per table.
  Documented as potentially slow on large catalogs; fine for the demo tier.
- **`max_depth`** (decided 2026-09-15): optional hop limit from the nearest
  root, as a tuning knob for targeted investigation. `None` (default) walks
  to the ends of the graph with cycle protection.

**Warning obligation for truncated graphs.** A depth limit can cut the walk
off *before reaching the PII origins* (per ADR-0001's applicability
precondition, seeds usually live at the far upstream end). A truncated graph
with no seeds inside the horizon classifies everything `NONE` — a false-clean
report. Therefore whenever `max_depth` trimmed at least one edge AND no seed
node made it into the graph, the connector/report must carry an explicit
warning ("graph truncated at depth N; no PII sources within horizon —
findings may be incomplete") rather than silently printing an empty result.
This extends the "no seeds anywhere" reporting rule from ADR-0001.

Note: this changes the `LineageSource` protocol signature from
`build_graph(root: str | None)` to
`build_graph(roots: Sequence[str] | None = None, *, max_depth: int | None = None)`.
`MockSource` accepts and ignores both (its graph is fixed). Acceptable now —
the protocol has no external implementors yet.

Node mapping:

| `Node` field | From OMD |
|--------------|----------|
| `id` | table `fullyQualifiedName` |
| `name` | table `name` |
| `owners` | `owners[].name` (or email when present) |
| `upstream` | lineage edges where this table is the target |
| `sql` | `schemaDefinition` / view SQL, else `None` |
| `declared_pii` | columns carrying a `PII.*` tag (see 4) |

### 4. PII tag mapping — v1 keeps it deliberately simple

- Column tag `PII.Sensitive` → `PiiTag(category="pii", sensitive=True)`
- Column tag `PII.NonSensitive` → `PiiTag(category="pii", sensitive=False)`
- Any other classification is ignored in v1. A configurable tag→category
  mapping (e.g. `PersonalData.Email` → `email`) is future work — noted in
  the backlog, not blocking this slice.

### 5. Secrets hygiene

- The token lives only in the `Authorization: Bearer` header of the client.
- `OpenMetadataSource.__repr__` and all error messages show the host but
  never the token; httpx exceptions are caught and re-raised as
  `SensiflowConnectionError(host, status)` without request headers.
- CLI accepts `--omd-host` / `--omd-token`, falling back to `OMD_HOST` /
  `OMD_TOKEN` env vars (flag wins). A `.env.example` documents both; the CLI
  does not read `.env` itself — loading it is the user's shell's job.

### 6. Testing strategy (no live server anywhere in CI)

- **Contract tests** with recorded JSON fixtures under
  `tests/fixtures/omd/` (synthetic names only, per clean-room rules):
  tables page, single table, lineage response. The httpx transport is
  mocked (`httpx.MockTransport`) — no network, no extra test deps.
- Mapping unit tests: OMD JSON → `Node` fields, PII tag extraction,
  pagination handling, lineage-walk termination on cycles/depth.
- Error-path tests: 401 (bad token — message must not contain the token),
  404 root, malformed JSON.
- **Manual smoke** (not CI): `sensiflow report --source openmetadata
  --omd-host http://localhost:8585 --omd-token ...` against the OMD sandbox
  docker-compose — documented in the ADR follow-up notes, run before the PR
  merges.

### 7. CLI surface after this slice

```
sensiflow report --source mock
sensiflow report --source openmetadata --omd-host H --omd-token T
                 [--root FQN ...] [--max-depth N]
```

`--source` gains the `openmetadata` choice; `--root` is repeatable (each
occurrence adds one root; none = full scan); `--max-depth` caps the walk
distance from the nearest root. Defaults stay unchanged: `mock` remains the
default source so the zero-config demo keeps working.

## Consequences

### Positive

- Base `pip install sensiflow` stays at one dependency (`sqlglot`); the OMD
  extra adds exactly one more (`httpx`).
- No coupling to OMD server releases; we depend on the stable v1 REST paths.
- The whole connector is testable offline; CI needs no secrets and no server.
- Secrets cannot leak through reprs or exceptions by construction.

### Negative / accepted trade-offs

- We own ~200 lines of REST plumbing (pagination, retries-lite, error
  mapping) that the SDK would have provided.
- No column-level lineage in v1 — graph edges are table-level; column
  matching stays name-based (already the engine's assumption per ADR-0001).
- `root=None` full scan is O(tables) API calls; acceptable for small
  catalogs, documented as such.
- v1 PII categories are coarse (`"pii"`), so reports group by column name
  rather than semantic category until the tag-mapping feature lands.

### Follow-ups

- Backlog: configurable tag→category mapping; column-level lineage when OMD
  provides it; retry/backoff policy if real-world usage needs it.
- ADR-0003 candidate (later): write-back semantics (`propagate` command).

## Alternatives considered

1. **Official `openmetadata-ingestion` SDK.** Rejected: dependency weight
   (full pydantic schema tree, many transitives), server-version coupling,
   and it drags ingestion-framework machinery we will never call. Would also
   make the optional extra heavier than the entire core.
2. **`requests` instead of `httpx`.** Nearly equivalent; rejected for weaker
   typing (mypy-strict friction) and no async path later. Low-stakes choice —
   reversible in an afternoon if httpx misbehaves.
3. **OMD search/ElasticSearch API for discovery.** More powerful filtering,
   but a second API surface and response format to maintain; the plain
   tables listing suffices for v1.
4. **Building the graph from column-level lineage edges.** OMD's column
   lineage coverage is inconsistent across ingestion sources; committing to
   it now would make graph shape depend on catalog hygiene. Deferred.
