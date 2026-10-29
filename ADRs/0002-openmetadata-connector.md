# ADR-0002: OpenMetadata connector — thin REST client behind an optional extra

- **Status:** Accepted (2026-09-16, after author review; amendments during
  review: multi-root walk, per-direction depth limits, truncation warnings);
  amended 2026-10-29: root selectors (Accepted 2026-10-29, after review:
  lazy pyyaml extra, strict zero-match, `GraphSelection` spec object)
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
- **`upstream_depth` / `downstream_depth`** (decided 2026-09-15, refined from
  a single `max_depth`): two independent hop limits from the nearest root,
  tuning knobs for targeted investigation. `None` (default) walks that
  direction to the end of the graph with cycle protection; `0` disables that
  direction entirely. Direction selection is thus expressed through depths
  (upstream-only = `downstream_depth=0`, and vice versa) — no separate
  direction switch, so no conflicting combinations. Maps 1:1 onto the OMD
  lineage endpoint's own `upstreamDepth`/`downstreamDepth` parameters.

**Warning obligations for truncated graphs — the two directions differ:**

- **Upstream truncation is dangerous.** Seeds usually live at the far
  upstream end (ADR-0001 applicability precondition); cutting upstream can
  exclude every PII origin, classifying everything `NONE` — a false-clean
  report. Whenever the upstream limit trimmed at least one edge AND no seed
  node made it into the graph, the report must carry an explicit warning
  ("upstream truncated at depth N; no PII sources within horizon — findings
  may be incomplete") rather than silently printing an empty result. This
  extends the "no seeds anywhere" reporting rule from ADR-0001.
- **Downstream truncation is coverage-limiting, not correctness-breaking:**
  seeds and classification of the fetched nodes stay valid; consumers below
  the horizon are simply not examined. A milder note suffices ("downstream
  truncated at depth M — consumers below this horizon were not analyzed").

Note: this changes the `LineageSource` protocol signature from
`build_graph(root: str | None)` to
`build_graph(roots: Sequence[str] | None = None, *,
             upstream_depth: int | None = None,
             downstream_depth: int | None = None)`.
`MockSource` accepts and ignores these (its graph is fixed). Acceptable now —
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
                 [--root FQN ...] [--upstream-depth N] [--downstream-depth M]
```

`--source` gains the `openmetadata` choice; `--root` is repeatable (each
occurrence adds one root; none = full scan); `--upstream-depth` /
`--downstream-depth` cap the walk per direction (`0` disables a direction,
omitted = unlimited). Defaults stay unchanged: `mock` remains the default
source so the zero-config demo keeps working.

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

---

## Amendment (2026-10-29): root selectors

- **Status:** Accepted (2026-10-29, after team-lead review)

### Context

§3 made `roots` a list of exact table FQNs. In practice users scope a run to
"everything under this schema" or "every table that carries PII markup", and
typing dozens of FQNs by hand does not scale — nor does falling back to the
full-catalog scan, which §3 documents as expensive. ADR-0003 §5 reuses the
roots/depth semantics for the dbt connector (adding unambiguous bare-name
resolution), so whatever selection mechanism we add must be defined once and
govern **every** `LineageSource`, not just OpenMetadata.

This amendment therefore owns root *selection* for all connectors, present and
future. It deliberately ships before the planned `check` CI-gate command: CI
is the primary consumer of "select roots without enumerating them", and the
gate should land on top of a settled selection model rather than force it.

### Decision

#### A1. Three selector forms

1. **Glob patterns in `--root`.** A `--root` value containing any of the
   fnmatch metacharacters `*`, `?`, `[` is treated as a pattern; a value
   without them keeps today's exact semantics unchanged (OMD: table FQN;
   dbt: `unique_id` or unambiguous bare name per ADR-0003 §5). Matching uses
   `fnmatch.fnmatchcase` (case-sensitive, deterministic across platforms):
   `*` and `?` wildcards, `[seq]`/`[!seq]` classes. There is no path/segment
   awareness — `demo.wh.*` matches the entire subtree at any depth, which is
   the intended reading for lineage scoping.

   A pattern matches a node when it matches the node **id** (FQN /
   `unique_id`) **or** the bare node name — consistent with the bare-name
   convenience ADR-0003 §5 already established for exact roots. So
   `--root 'raw_*'` works on both connectors without knowing FQN prefixes.

   Edge case, accepted: a literal id that itself contains `*`, `?`, or `[`
   cannot be addressed as an exact root (it will be classified as a pattern).
   fnmatch's `[[]` class can escape a literal `[`; ids containing `*`/`?` are
   considered pathological and unsupported in v1.

2. **`--roots-from-seeds`.** Every node that carries declared PII markup
   (non-empty `declared_pii`) becomes a root. This is the natural CI shape:
   "trace everything that originates PII, wherever it is." A useful property:
   since every root is itself a seed, the dangerous upstream-truncation
   warning of §3 can never fire on such runs — the seeds are in the graph by
   construction, and `--upstream-depth 0` becomes a safe, cheap default for
   CI (nodes upstream of seeds cannot contribute findings).

3. **`--roots-file PATH`.** Roots from a YAML file with the fixed, versioned
   schema pinned in A3. The file is the reviewable, checked-in form of a
   team's scoping baseline; `--root` remains the ad-hoc form.

#### A2. Mixing rules

- `--root` (repeatable) and `--roots-file` **combine as a union**: both are
  identity-based selection, and "checked-in baseline plus ad-hoc additions"
  is the natural workflow. Duplicates (one node matched by several selectors)
  are deduplicated after resolution.
- `--roots-from-seeds` is **mutually exclusive** with `--root` and
  `--roots-file` → `SensiflowInputError`. It selects by a *property* of the
  data, not by identity; mixing the two regimes would blur root provenance
  and the error semantics (a "no seeds found" failure could be silently
  masked by an explicit root, and vice versa). A future need to combine them
  can relax this; starting exclusive keeps every run's meaning obvious.
- `--roots-file` is accepted at most once in v1. Making it repeatable (union
  of files) is a trivial future extension; silently letting argparse keep
  the last occurrence would be a footgun, so a repeat is rejected.

#### A3. The roots file: fixed YAML schema, version 1

```yaml
# roots.yaml — sensiflow root selectors
version: 1
roots:
  - id: demo.wh.sales.orders     # exact node id (connector's exact semantics)
  - pattern: "demo.wh.crm.*"     # fnmatch glob against node id and bare name
  - pattern: "raw_*"             # bare-name glob
```

Strict validation — every violation raises `SensiflowInputError` naming the
file and the exact problem:

| Rule | Message gist |
|------|--------------|
| File must exist and be readable | `roots file not found: PATH` |
| Must parse as YAML (`yaml.safe_load`) | `roots file PATH: invalid YAML: <parser error>` |
| Top level must be a mapping with exactly the keys `version` and `roots` | unknown top-level key `X` rejected |
| `version` must be the integer `1` | `unsupported roots-file version: X (supported: 1)` |
| `roots` must be a non-empty list | `'roots' must be a non-empty list` |
| Each entry must be a mapping with exactly one key, `id` or `pattern` | unknown entry key `X` / entry with 0 or 2+ keys rejected |
| Values must be non-empty strings | type and emptiness checked |
| An `id` value must not contain `*`, `?`, `[` | "glob characters in 'id' entry — use 'pattern'" |
| A `pattern` value must contain at least one of `*`, `?`, `[` | "no glob characters in 'pattern' entry — use 'id'" |

The last two rules keep the file lossless: `id` entries map 1:1 onto
`GraphSelection.roots` and `pattern` entries onto `GraphSelection.patterns`
(A4), with no ambiguity about which entry was meant as exact and which as a
pattern. Both kinds fail hard when they resolve to nothing (A6), so the
distinction does not change failure behavior — its value is message
precision ("unknown root id 'X'" vs "root pattern 'X' matched no tables"). There
is deliberately no second way to express anything — no free-form sections, no
per-entry options. Future needs (per-root depths, comments beyond YAML `#`)
require a `version: 2` and a new review, not schema creep.

#### A4. Where resolution lives: a shared selector layer

A new module `src/sensiflow/root_selectors.py` — a sibling of
`graph_scope.py`, i.e. source-adjacent shared infrastructure, invisible to
the engine — owns the selection spec object, the file loader, and the
matching rules, so dbt and OMD cannot drift apart.

**The spec object.** The entire graph-scoping request is one frozen,
keyword-constructed dataclass:

```python
@dataclass(frozen=True)
class GraphSelection:
    roots: tuple[str, ...] = ()        # exact node ids (connector's exact semantics)
    patterns: tuple[str, ...] = ()     # fnmatch globs against node id and bare name
    from_seeds: bool = False           # every PII-seeded node becomes a root
    upstream_depth: int | None = None  # None = unlimited, 0 = direction disabled
    downstream_depth: int | None = None
```

Depths live **inside** the object, deliberately: they describe the same
graph-scoping request as the roots (truncation semantics are defined per
union of roots, §3), and folding every scoping knob into one value is what
makes the method signature permanently stable. Validation happens at
construction (`__post_init__`) — fail early, in exactly one place, shared
by CLI, file loader, and library callers:

- `from_seeds=True` with non-empty `roots`/`patterns` →
  `SensiflowInputError` (the A2 exclusivity rule, enforced at the source of
  truth rather than in the CLI);
- `roots` entries must be non-empty strings without glob metacharacters
  ("use patterns"); `patterns` entries must contain at least one
  metacharacter ("use roots") — the same two rules as the YAML schema (A3);
- depths must be `None` or `>= 0`, and a depth given on an otherwise-empty
  selection is rejected ("depths require roots"): a full scan has no roots
  to measure hops from;
- `GraphSelection()` (all defaults) is valid and means "full scan",
  equivalent to passing `None`.

**The final protocol shape** (the last signature revision after
`build_graph(root)` and `build_graph(roots, *, depths...)` — all three
in-repo sources and the CLI migrate in the same change; the protocol still
has no external implementors, so this is the moment to spend the last cheap
break):

```python
class LineageSource(Protocol):
    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph: ...
```

**The protocol is now shape-stable: future extensions add OPTIONAL fields
(with defaults) to `GraphSelection`, never parameters to `build_graph`.**
Library ergonomics stay terse: `build_graph()` is the full scan,
`build_graph(GraphSelection(roots=("demo.wh.sales.orders",)))` the common
case. `MockSource` accepts and ignores the selection (fixed graph), as it
did with the old parameters.

**Supporting functions** in the same module:

- `load_roots_file(path) -> GraphSelection`: parse + strict validation
  (A3), returning a selection with `roots`/`patterns` populated and every
  other field at its default. The CLI combines it with flag-derived values
  (union of roots and patterns per A2, depths from flags) into the final
  object; no public merge API is promised in v1.
- `resolve_patterns(patterns, candidates) -> list[str]`: fnmatch resolution
  against an iterable of `(id, name)` candidate pairs, producing matched
  node ids; a pattern that matches nothing raises `SensiflowInputError`
  (A6).

CLI flags map 1:1 onto the object: each `--root` value is classified by the
metacharacter test into `roots` or `patterns`, `--roots-file` contributes
via the loader, `--roots-from-seeds` sets `from_seeds`, and the depth flags
set the depth fields. `GraphSelection` is public API, exported from the
package root alongside the model dataclasses.

#### A5. Per-connector resolution cost — stated honestly

- **dbt:** free. The whole manifest is already in memory; candidates are all
  graph vertices, resolution is an in-memory filter, and scoping remains the
  `graph_scope.scope_graph` post-filter of ADR-0003 §5.
- **OpenMetadata:** exact-FQN roots keep today's listing-free path (straight
  to the lineage endpoint). Any pattern selector or `from_seeds=True`
  first requires **one paginated pass over `/api/v1/tables`** to obtain
  candidate FQNs/names (and, for from-seeds, column tags — a heavier payload
  since `fields=columns,tags` must be requested). After resolution, the
  normal multi-root BFS of §3 fetches lineage **only for the matched
  closures**. Cost ordering: exact roots < pattern/from-seeds (one listing
  pass + matched closures) < full scan (listing + lineage for every table).
  This is documented behavior, not an implementation detail: on large
  catalogs the listing pass is O(tables / page size) requests.
- **OMD asymmetry, accepted:** exact (non-glob) roots on OMD remain FQNs
  only — resolving bare names exactly would itself require the listing pass,
  defeating the cheap path. Users who want bare-name addressing on OMD use a
  pattern; dbt keeps its unambiguous bare-name resolution for exact roots.

#### A6. Error and warning semantics

- **Unknown exact root:** error, unchanged (dbt: `SensiflowInputError` with
  the candidate list when ambiguous; OMD: the existing 404 handling).
- **A pattern matching zero nodes:** a hard `SensiflowInputError` ("root
  pattern 'X' matched no tables"), even when other selectors did match.
  Decided strict during review (2026-10-29): a softer warning mode was
  considered and rejected — a silently empty pattern would be dangerous
  under the planned `check` CI gate (a typo could greenlight a pipeline),
  and relaxing an error into a warning later is a cheap, compatible change,
  whereas tightening a warning into an error breaks existing users. No
  leniency debt is taken on without a demonstrated benefit.
- Because every selector must resolve (exact roots must exist, patterns must
  match at least one node), an empty resolved root set cannot occur; in
  particular there is **no fallback to full scan** — silently converting a
  typo into the most expensive possible run would be hostile (see
  alternative 7).
- **`--roots-from-seeds` finds zero seeds:** `SensiflowInputError` stating
  that no PII-seeded tables exist and pointing at the applicability
  precondition of ADR-0001. This is a hard error, not the ADR-0001 "no seeds
  anywhere" report warning: the user explicitly asked for seed-derived
  roots, so an empty result is an unanswerable request, not a valid report.
- **Roots file problems:** `SensiflowInputError` per the A3 table.

#### A7. Depths and truncation: unchanged

`--upstream-depth` / `--downstream-depth` and the truncation-warning
obligations of §3 apply exactly as before, to the **union of resolved
roots** — selectors change only how the root set is produced, never what
walking from it means. ADR-0003 §5's in-memory implementation is unaffected
for the same reason.

#### A8. Dependency: PyYAML behind an optional extra, lazily imported

The roots file needs a YAML parser; the standard library has none. PyYAML
(`pyyaml>=6`) is added as an **optional extra**, mirroring the `httpx`
pattern of §1–§2 of this ADR:

```toml
[project.optional-dependencies]
yaml = ["pyyaml>=6"]
```

The import happens lazily inside the roots-file loader; if PyYAML is not
installed, `--roots-file` raises `SensiflowDependencyError` naming the exact
fix: `pip install 'sensiflow[yaml]'`. The base dependency set stays
unchanged (`sqlglot` only) — the "single-dependency base install"
consequence recorded in this ADR and ADR-0003 continues to hold. Loading
uses `yaml.safe_load` only; `types-PyYAML` joins the dev group for strict
mypy. Glob patterns and `--roots-from-seeds` need no extra — only the file
form pays the install step.

#### A9. CLI surface after this amendment (supersedes §7's listing)

```
sensiflow report --source mock
sensiflow report --source openmetadata --omd-host H --omd-token T
                 [--root FQN_OR_GLOB ...] [--roots-file PATH | --roots-from-seeds]
                 [--upstream-depth N] [--downstream-depth M]
sensiflow report --source dbt --dbt-manifest PATH
                 [--root ID_OR_GLOB ...] [--roots-file PATH | --roots-from-seeds]
                 [--upstream-depth N] [--downstream-depth M]
```

Examples:

```
# everything under one schema (quote the glob — the shell must not expand it)
sensiflow report --source openmetadata --omd-host H --omd-token T \
    --root 'demo.wh.crm.*'

# checked-in baseline plus one ad-hoc root
sensiflow report --source dbt --dbt-manifest target/manifest.json \
    --roots-file roots.yaml --root model.demo.stg_payments

# every PII-seeded table, downstream exposure only
sensiflow report --source dbt --dbt-manifest target/manifest.json \
    --roots-from-seeds --upstream-depth 0

# future-facing (once the `check` command exists) — the intended CI one-liner:
sensiflow check --source dbt --dbt-manifest target/manifest.json \
    --roots-from-seeds --fail-on HIGH
```

The `check` example is documentation of intent, not part of this slice.

### Consequences

Positive:

- Scoping a run no longer requires enumerating FQNs or paying for a full
  scan; `--roots-from-seeds` gives CI a configuration-free root set.
- One shared resolution module keeps selector semantics identical across
  connectors and trivially available to future ones.
- The rigid roots-file schema is reviewable in PRs and versioned from day
  one; schema evolution has an explicit gate (`version: 2`).

Negative / accepted trade-offs:

- `--roots-file` requires an extra install step (`sensiflow[yaml]`); the
  dependency-missing error names the fix (A8).
- Patterns and from-seeds on OMD cost a full table-listing pass; documented,
  and still cheaper than the full scan.
- Strict zero-match semantics (A6) mean multi-environment roots files must
  only contain patterns that match everywhere they are used; a leniency
  mode, if ever justified, is a compatible relaxation.
- fnmatch is case-sensitive and not segment-aware; both are documented
  behaviors rather than options (no new knobs in v1).
- Exact bare-name roots remain dbt-only (A5 asymmetry).
- One more (and final) `build_graph` signature change, spent deliberately on
  the `GraphSelection` object so the protocol never changes shape again;
  all in-repo sources and the CLI migrate in the same change.

### Alternatives considered

1. **Regular expressions instead of globs.** More powerful, but the `.`
   metacharacter is a footgun in a dotted-FQN world (`demo.wh.crm.*` as a
   regex quietly matches more than intended), and shell/dbt users already
   think in globs. A `re:PATTERN` prefix remains the compatible escape hatch
   if globs ever prove insufficient — **rejected for now**, not forever;
   adding it later breaks nothing.
2. **dbt-style graph selectors (`+model+`, `tag:pii`, …).** Expressive, but
   it is a selector mini-language to parse, document, and maintain; its
   graph-walk operators (`+model+`) duplicate what `--upstream-depth` /
   `--downstream-depth` already express; and its tag/package operators are
   connector-specific concepts that would leak through the source-agnostic
   `LineageSource` seam. Revisit only on demonstrated demand.
3. **Plain text roots file (one selector per line).** No versioning, no
   explicit exact-vs-pattern distinction, and an open invitation to grow
   ad-hoc syntax (comments, prefixes) without a schema gate. Rejected.
4. **JSON or TOML instead of YAML for the roots file.** JSON lacks comments —
   unacceptable for a checked-in, reviewed config. TOML (stdlib `tomllib`)
   would avoid the PyYAML dependency but is an unusual choice for list-heavy
   data-engineering config, where YAML is the established convention (dbt,
   catalog ingestion). Rejected in favor of YAML plus the A8 extra.
5. **PyYAML as a core dependency.** Simpler UX (no extra to install for
   `--roots-file`) for a tiny, ubiquitous package — but it breaks the
   single-dependency base install recorded in two accepted ADRs for an
   opt-in convenience feature, and the connector-extra precedent (§1–§2)
   already gives users a well-understood install-hint pattern. Rejected in
   review (2026-10-29) in favor of the lazy-optional extra (A8).
6. **A `seeds:` magic selector string instead of the `from_seeds` field.**
   Rejected: it squats in the id namespace and hides a mode switch inside
   data.
7. **Fallback to full scan when selectors match nothing.** Rejected: it
   converts a typo into the most expensive run the connector can make and
   masks the error.
8. **Keep growing keyword parameters on `build_graph`** (add
   `roots_from_seeds: bool` next to the existing four). Smallest immediate
   diff, but every future scoping feature would change the protocol
   signature again — against every implementor, forever. Rejected in review
   (2026-10-29) in favor of spending one final signature change on the
   `GraphSelection` object (A4), after which extensions are optional fields
   on the object, not method parameters.

### Review notes (2026-10-29)

Resolved during review:

1. PyYAML ships as a lazy-optional extra, not a core dependency (A8,
   alternative 5).
2. Zero-match patterns fail hard from v1 (A6); the warning mode was
   rejected.
3. Case-sensitive matching only in v1 — confirmed.
4. `--roots-file` accepted at most once per invocation — confirmed.
5. The last pre-stability signature change is spent on the `GraphSelection`
   spec object (A4, alternative 8): `build_graph(selection=None)` is the
   final shape. Rationale: upcoming work (CI gate, write-back, deployment
   and agent interfaces) builds on top of this protocol, so it must stop
   moving; from here on, scoping extensions are optional fields on
   `GraphSelection`, never new method parameters.
