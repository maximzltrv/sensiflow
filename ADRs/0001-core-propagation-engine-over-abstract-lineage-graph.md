# ADR-0001: Core propagation engine over an abstract lineage graph

- **Status:** Accepted (amended 2026-09-15: added explicit applicability
  preconditions)
- **Date:** 2026-08-15
- **Deciders:** Maksim Zolotarev

## Context

sensiflow's first functionality is the end-to-end read-only pipeline: seed PII
at declared source nodes, propagate it down the lineage graph, classify how
exposed the PII is at each downstream node, and render a report.

Forces shaping the design:

1. **Catalogs do not do this out of the box.** OpenMetadata stores PII tags,
   lineage, and owners, but does not propagate tags along lineage, and column
   lineage alone cannot distinguish a join key from a pass-through column.
2. **The "how" requires SQL, but SQL is not always available.** Detecting
   `JOIN`/`WHERE` usage needs the transformation SQL of a node. Some catalogs
   provide it, some don't, and some nodes will have SQL that fails to parse.
3. **The core must be testable offline.** A propagation engine that can only be
   exercised against a live catalog cannot be unit-tested, demoed, or trusted.
4. **Multiple future inputs are planned** (OpenMetadata now; dbt
   `manifest.json` and ODCS contracts later). The engine must not be coupled to
   any of them.
5. **Mis-tagging is worse than under-tagging.** Column matching down a lineage
   graph is heuristic (mostly name-based), so results carry uncertainty and
   must never silently mutate the catalog.

## Applicability preconditions (amendment, 2026-09-15)

The tool is applicable **only when seed PII markup already exists at the root
source nodes of the lineage graph** — the first point of lineage where PII
originates. That markup can come from:

- manual (or policy-driven) tagging in the catalog itself (e.g. OMD
  `PII.Sensitive` tags), or
- markup inherited/ingested from the metadata of operational databases
  (PostgreSQL, MySQL, and similar OLTP systems that typically feed the
  warehouse), where the catalog's ingestion carries those annotations in.

Without seed markup at the origins the engine has nothing to propagate: every
node classifies as `NONE` and the report is trivially empty. This is a
precondition, not a failure mode — the tool must state it clearly in docs and,
ideally, detect the "no seeds anywhere" case and say so in the report instead
of printing a silently empty result.

**This constraint is an initial-scope decision, not a permanent one.** Two
planned feature branches relax it later (tracked in the project backlog):

1. **Standalone PII declarations imported from a file** (e.g. CSV/YAML) — an
   alternative seeding channel for catalogs that have lineage but no PII
   markup; sensiflow maps the declared source columns onto the warehouse
   schemas and propagates from there.
2. **Automated markup toward a chosen legal standard** (regional or global:
   GDPR, CCPA/CPRA, PDPL, ...) — a separate future direction where the tool
   itself drives classification to a standard's definitions.

Each of these gets its own ADR when scheduled.

## Decision

### 1. The engine consumes an abstract `LineageGraph`, never a catalog client

`engine.trace(graph) -> TraceResult` operates on plain dataclasses
(`LineageGraph`, `Node`). Connectors implement a `LineageSource` protocol
(`build_graph(root) -> LineageGraph`) and live behind optional extras. The
first shipped source is `sources/mock.py` — an in-memory synthetic graph used
by tests, the demo, and the CLI (`--source mock`).

### 2. Risk classification is a fixed five-level scale

| Risk | Condition |
|------|-----------|
| `ORIGIN` | Node is a declared PII source |
| `HIGH` | PII column used in a `JOIN` condition or `WHERE` clause |
| `MEDIUM` | PII column explicitly projected in `SELECT` |
| `LOW` | PII passed via `SELECT *`, or present via lineage when no SQL is available |
| `NONE` | No PII reaches the node |

Precedence: `HIGH > MEDIUM > LOW`. Propagation runs in topological order with
these invariants:

- A column used **only** in `JOIN`/`WHERE` is `HIGH` on that node but does not
  propagate downstream (it is not in the node's output).
- A column read but dropped does not propagate.
- `SELECT *` inherits all upstream PII columns at `LOW`, names preserved.
- A generic-name denylist (`id`, `name`, `date`, …) suppresses false positives.

### 3. SQL analysis is an enhancer, not a dependency

When a node's SQL is available it is parsed with `sqlglot` (dialect-tolerant,
default `bigquery`) to detect projections, aliases, `SELECT *`, and
`JOIN`/`WHERE` usage — enabling `HIGH`/`MEDIUM` distinctions. When SQL is
missing **or fails to parse**, the node degrades to presence-based
classification from lineage alone. A parse error on one node never aborts the
trace.

### 4. Every finding carries an explicit `confidence`

Name-based matching, aliasing, and `SELECT *` inheritance lower confidence.
The tool surfaces uncertainty instead of hiding it; the human makes the final
call.

### 5. The first slice is strictly read-only

Analysis and reporting never mutate the catalog. Write-back is a future,
separate command (`propagate`), dry-run by default, requiring explicit
confirmation — a propagation bug must never silently mis-tag the graph.

## Consequences

### Positive

- The engine is unit-testable with in-memory fixtures; `pytest` needs no
  network. The mock source doubles as the demo.
- New connectors (dbt, ODCS) add zero changes to the engine.
- Graceful SQL degradation means partial metadata still yields a useful (if
  coarser) report instead of a crash.
- Read-only first slice makes the tool safe to point at a production catalog
  from day one.

### Negative / accepted trade-offs

- Name-based column matching produces false positives/negatives; `confidence`
  mitigates but does not eliminate this. Accepted: exact column-level lineage
  is not generally available across catalogs.
- The abstract graph is a lowest common denominator — catalog-specific riches
  (e.g. OMD column-level lineage edges) must be flattened into it, and some
  fidelity may be lost.
- Without SQL, `HIGH` risk is undetectable; reports from SQL-less catalogs
  understate risk. Documented as a known limitation.

### Follow-ups

- ADR needed later: OpenMetadata connector transport (official Python SDK vs
  thin REST client).
- ADR needed later: write-back semantics (tag ownership, idempotency,
  conflict handling).

## Alternatives considered

1. **Couple the engine to the OpenMetadata SDK directly.** Rejected: kills
   offline testability, blocks future dbt/ODCS inputs, and drags a heavy
   dependency into the core install.
2. **Require SQL for every node (hard `sqlglot` dependency).** Rejected: most
   real catalogs have incomplete SQL coverage; the tool must be useful on
   partial metadata.
3. **Detect PII ourselves (regex/ML column scanning).** Rejected as a
   non-goal: detection is a crowded, separate problem. sensiflow trusts the
   catalog's declared PII tags and focuses on propagation and exposure — the
   gap no one else fills.
4. **Graph library (networkx) for the lineage graph.** Rejected for now: a
   dict of nodes with upstream ids plus one topological sort is ~30 lines of
   stdlib; a dependency is not justified at this size.
