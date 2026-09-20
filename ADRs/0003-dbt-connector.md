# ADR-0003: dbt connector — manifest.json as a zero-dependency lineage source

- **Status:** Proposed (awaiting author review)
- **Date:** 2026-09-20
- **Deciders:** Maksim Zolotarev

## Context

Backlog item #1 ("dbt as a first-class lineage source") is promoted to the
next slice, ahead of broader testing and the public write-up. Motivation:

1. **Reach.** Every dbt shop has a `manifest.json`; none of them needs a
   running catalog. This makes sensiflow demoable and adoptable with zero
   infrastructure — `sensiflow report --source dbt --dbt-manifest target/manifest.json`
   against any dbt project.
2. **Offline-first fit.** The manifest is a local file: no network, no
   auth, no secrets. It is also the artifact our own propagation prototype
   was originally built on (PROJECT_CONTEXT §5).
3. **The engine does not change.** This slice adds a `LineageSource`
   implementation only. Propagation, risk semantics, and the public model
   stay exactly as accepted in ADR-0001 — explicitly confirmed by the
   author as a constraint for this slice.

What `manifest.json` provides (produced by `dbt compile` / `dbt build`):

- `nodes` (models, seeds, snapshots) and `sources` — the graph vertices;
- `depends_on.nodes` per node — the lineage edges;
- `compiled_code` (post-Jinja SQL) per model — exactly what our sqlglot
  analysis wants; `raw_code` as a weaker fallback;
- per-column `meta` / `tags` — a place teams already annotate PII;
- `meta`/`group`/`config` — ownership hints.

## Decision

### 1. Parse the manifest directly; no dbt dependency, no extra

`sources/dbt.py` reads and maps `manifest.json` with the standard library
only (`json` + dict access). Consequences:

- **The dbt connector ships in the base install** — unlike OMD, there is
  nothing to put behind an extra (`[dbt]` stays unused unless a future
  need appears). The "connectors are optional extras" rule (ADR-0001)
  exists to keep the base light; a zero-dependency connector satisfies its
  *intent* while living in core.
- We do **not** run dbt, import `dbt-core` (huge, version-coupled), or
  require an adapter. The user brings a manifest produced by their own
  toolchain.

### 2. Defensive parsing across manifest schema versions

Manifest schema evolves (v7…v12+), but the fields we touch (`nodes`,
`sources`, `depends_on.nodes`, `compiled_code`, `columns`, `meta`, `tags`)
are long-stable. We read them tolerantly (missing key -> feature absent,
never a crash) and do not pin `metadata.dbt_schema_version`. A manifest
that is not valid JSON or lacks `nodes` entirely raises the new
`SensiflowInputError` ("not a dbt manifest?").

### 3. Node mapping

| `Node` field | From manifest |
|--------------|---------------|
| `id` | `unique_id` (`model.proj.stg_customers`, `source.proj.crm.raw_customers`) |
| `name` | node `name` |
| `upstream` | `depends_on.nodes` (models + sources; other kinds ignored) |
| `sql` | `compiled_code` if non-empty, else `raw_code`, else `None` |
| `owners` | `config.meta.owner` / `meta.owner` (string or list), else `group`, else empty |
| `declared_pii` | from column meta/tags, see §4 |

Included vertices: `nodes` of kind model/seed/snapshot + all `sources`.
Tests, macros, exposures are skipped. `raw_code` is Jinja-flavored SQL and
often won't parse — that is fine by construction: sqlglot failure degrades
the node to presence-based classification (ADR-0001 §3).

### 4. PII seeds from column annotations — two accepted conventions

For each column in a node's `columns`:

- **`meta` keys (primary):** `pii: true` marks the column;
  `pii_category: email` (default `"pii"`) and `pii_sensitive: false`
  (default `true`) refine the tag.
- **Tags (secondary):** a column tag `pii` marks it (category `"pii"`);
  a tag of the form `pii:email` sets the category.

Anything else is not a seed. This mirrors how dbt teams actually annotate
(meta for structured data, tags for quick labels) without inventing a
schema. A configurable mapping stays in the backlog together with the OMD
tag->category mapping — one future mechanism for both connectors.

### 5. Roots and depths: same semantics, in-memory implementation

`DbtSource(manifest_path).build_graph(roots, upstream_depth=...,
downstream_depth=...)` supports the full protocol. Unlike OMD there is no
per-call cost — the whole manifest is already in memory — so scoping is a
**post-filter**: build the full graph, then keep the union of per-direction
closures from the roots, with the same depth semantics (`None` unlimited,
`0` disables) and the same truncation-warning rules as ADR-0002 (hard
warning when the upstream cut leaves no seeds; mild note for a downstream
cut). Roots are `unique_id`s; as a convenience, a bare model/source name is
resolved if unambiguous, else `SensiflowInputError` listing the matches.

The filtering walk is generic graph code (no HTTP): it lives in a small
shared helper so a future connector can reuse it, and the OMD connector's
BFS stays as is (its walk must limit *fetching*, not filter afterwards).

### 6. CLI surface

```
sensiflow report --source dbt --dbt-manifest PATH
                 [--root ID ...] [--upstream-depth N] [--downstream-depth M]
```

`--dbt-manifest` is required with `--source dbt` (no env fallback: it is a
local path, not a secret). Everything else is shared with the other
sources. `mock` remains the default source.

### 7. Errors

New sibling in the hierarchy: `SensiflowInputError(SensiflowError)` — bad
local input (missing file, invalid JSON, not a manifest, ambiguous root).
Kept separate from `SensiflowConnectionError` (remote/catalog problems) so
the CLI can keep a single `except SensiflowError` while messages stay
precise.

### 8. Testing strategy

- A hand-written synthetic `tests/fixtures/dbt/manifest.json` mirroring the
  mock graph (raw sources with PII meta -> staging -> marts incl. a
  JOIN-on-email model), clean-room names only.
- Unit tests: node/edge/SQL/owner mapping; both PII conventions (meta and
  tags); seeds/snapshots included, tests/macros skipped; `compiled_code`
  preferred over `raw_code`.
- Scoping tests: roots closure, per-direction depths, truncation warnings,
  ambiguous and unknown root errors.
- End-to-end: `trace()` over the fixture manifest reproduces the expected
  HIGH/MEDIUM/LOW/NONE picture; CLI test for `--source dbt`.
- Error paths: missing file, invalid JSON, JSON-but-not-a-manifest.

## Consequences

### Positive

- First truly zero-setup path to value: any dbt repo, one command, no
  server, no token. This is the demo for the planned article.
- Base install still has a single dependency (`sqlglot`).
- Engine untouched; the `LineageSource` seam proves itself on a second,
  very different source (local file vs REST API).
- Shared scoping helper turns roots/depths into engine-adjacent
  infrastructure instead of per-connector copy-paste.

### Negative / accepted trade-offs

- Manifest-only means **model-declared PII only**: if a team annotates PII
  nowhere in dbt, there are no seeds (ADR-0001 applicability precondition
  applies; the no-seeds warning fires). The CSV-declarations backlog item
  remains the planned remedy.
- `raw_code` fallback frequently fails to parse (Jinja) — those nodes
  degrade to presence-based classification; documented, not fixed.
- Two annotation conventions are hardcoded; teams with different ones must
  wait for the configurable mapping.
- No `catalog.json` usage in v1 (column types/docs) — not needed for
  propagation.

### Follow-ups

- Configurable annotation->tag mapping shared by dbt and OMD connectors.
- Possible `[dbt]` extra later only if a real dependency appears.
- Article demo script: run against a public sample dbt project (e.g.
  jaffle-shop-style synthetic repo we author ourselves — clean-room).

## Alternatives considered

1. **Depend on `dbt-core` and load the manifest via its classes.** Rejected:
   enormous dependency, tight schema-version coupling, adapters pulled in —
   all to read a JSON file.
2. **Run `dbt compile` for the user.** Rejected: requires their profiles,
   credentials, and environment; breaks "connection details come from the
   user" and offline-first testing.
3. **Support only `compiled_code` (require a compiled manifest).** Rejected:
   `raw_code` fallback costs nothing and degrades gracefully; requiring
   compilation would reject half the manifests people have lying around.
4. **Implement roots/depths by filtering inside the OMD-style BFS walker.**
   Rejected: OMD's walk exists to limit network fetching; for a local file
   a full parse + filter is simpler and the shared helper keeps semantics
   identical.
