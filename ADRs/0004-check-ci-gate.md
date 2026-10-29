# ADR-0004: `check` command — a CI gate with a fixed exit-code contract

- **Status:** Proposed
- **Date:** 2026-10-29
- **Deciders:** Maksim Zolotarev

## Context

The read-only pipeline is complete: three sources (mock, OpenMetadata, dbt)
behind the `LineageSource` protocol, root selection via `GraphSelection`
(ADR-0002 amendment), the propagation engine (ADR-0001), and `sensiflow
report` with text/JSON renderers. The packaging model has always named the
next consumer: *"CI/CD = the CLI in check mode (`check --fail-on HIGH`,
non-zero exit). No separate product."*

A CI gate differs from a report in one essential way: **its primary output is
the process exit code**, and that exit code is a public contract — pipelines
hard-code reactions to it, so it must be fixed before the first release and
never casually changed. Forces:

1. **Exit code 1 must mean exactly one thing.** An unhandled Python traceback
   terminates the process with exit code 1. If 1 also means "PII exposure
   found", a crash in the tool is indistinguishable from a legitimate gate
   trip — and, worse, a crash could be mistaken for a finding (noisy) or a
   finding-handling path could mask a crash (dangerous). The taxonomy must
   separate "the gate tripped" from "the check itself broke".
2. **argparse already owns exit code 2.** `parser.error()` exits with 2 on
   any usage error. Fighting that default means reimplementing argparse error
   handling; aligning with it costs nothing.
3. **Comparable tools set user expectations.** ruff and grep use 0/1/2
   (clean / findings / error); pytest uses 0–5 (adding usage error, internal
   error, empty collection); pip-audit conflates findings and some errors in
   exit 1, which is a documented pain point for its CI users. Shell-reserved
   values (126, 127, 128+N) must be avoided.
4. **CI needs to distinguish transient from permanent failure.** "Catalog
   unreachable" is retryable; "your roots file is invalid" is not. Collapsing
   both into one code forces pipelines to parse stderr to decide whether to
   retry.
5. **Library-first.** The gate decision ("do these results violate this
   policy?") is logic, so it belongs in the library as a pure function —
   importable by scripts and agents without a subprocess. Core code never
   prints and never calls `sys.exit`; only the CLI layer maps outcomes to
   exit codes.
6. **No duplication with `report`.** `check` needs the same source options,
   root selectors, depths, and dialect flag as `report`; defining them twice
   guarantees drift.

## Decision

### 1. Exit-code taxonomy — fixed, CLI-wide, versioned with the tool

| Code | Name | Meaning | Produced by |
|------|------|---------|-------------|
| `0` | clean | Run completed; no findings at or above the threshold (findings *below* it may exist) | successful `check` below threshold; successful `report` |
| `1` | gate tripped | Run completed; at least one node at or above `--fail-on` | `check` only |
| `2` | usage / input error | The invocation or its local inputs are invalid: unknown flags, missing required options (argparse native), invalid roots file, unreadable/invalid manifest, bad `--fail-on` value (`SensiflowInputError`) | any command |
| `3` | operational error | The run could not complete for environmental reasons: catalog unreachable or auth failure (`SensiflowConnectionError`), missing optional extra (`SensiflowDependencyError`), or an unexpected internal error | any command |

Rules that make this a contract, not a convention:

- **`1` is reserved exclusively for policy-gate trips.** No error path may
  ever exit 1. To guarantee this, the `check` command wraps its execution:
  `SensiflowError` subclasses map to 2 or 3 per the table, and any unexpected
  exception is printed **with its full traceback to stderr** and mapped to
  exit 3. Swallowing the traceback would hide bugs; letting it propagate
  would corrupt the contract (crash → exit 1 → looks like a finding). Both
  problems are avoided: full diagnostics on stderr, honest exit code.
- The taxonomy applies to **every** sensiflow command, present and future
  (`report` today, `propagate` later), so pipelines learn one mapping.
  `report` has no gate and therefore never exits 1. Its current behavior
  (exit 1 on any `SensiflowError`) is aligned to this table in the same
  slice — a breaking change that is cheap now, pre-release, and impossible
  later.
- Exit codes stay in 0–3: no sysexits.h values, nothing at or above 126.
- Changing the meaning of an existing code is a major-version event. New
  codes may be added (4+) only for genuinely new outcome classes.

The code constants live in the CLI layer (an `IntEnum` in `cli.py`): exit
codes are process contract, not library semantics, and keeping them out of
the core preserves the "library never exits" rule.

### 2. The gate decision is a pure library function

A new module `src/sensiflow/gate.py`:

```python
GateRisk = Literal["LOW", "MEDIUM", "HIGH"]

@dataclass(frozen=True)
class GateOutcome:
    fail_on: GateRisk
    tripped: bool
    violations: tuple[NodeResult, ...]   # nodes at/above threshold, most exposed first

def evaluate_gate(result: TraceResult, *, fail_on: GateRisk) -> GateOutcome: ...
```

- `evaluate_gate` validates the threshold (`SensiflowInputError` for anything
  outside `LOW`/`MEDIUM`/`HIGH`) and selects violating nodes via the existing
  `TraceResult.by_risk` ordering (a node violates when its `max_risk` ranks
  at or above the threshold).
- **`ORIGIN` and `NONE` are not valid thresholds and `ORIGIN` never trips the
  gate.** An `ORIGIN` node is the declared seed — the applicability
  precondition of ADR-0001, not an exposure. `NONE` as a threshold would trip
  on every graph. In the existing `RISK_RANK` ordering `ORIGIN` ranks below
  `LOW`, so `by_risk("LOW")` already excludes pure origins; this decision
  pins that as intended gate semantics, not an accident of ranking.
- The function is pure: no printing, no exit codes, no I/O. Library users and
  AI agents get the identical gate semantics via
  `evaluate_gate(trace(graph), fail_on="HIGH")`.
- `GateOutcome` and `evaluate_gate` are public API, exported from the package
  root alongside the model dataclasses.

### 3. CLI surface and plumbing sharing

```
sensiflow check --fail-on {LOW|MEDIUM|HIGH}
                [--source mock|openmetadata|dbt] [--format text|json]
                [--dialect D]
                [--omd-host H --omd-token T] [--dbt-manifest PATH]
                [--root ID_OR_GLOB ...] [--roots-file PATH | --roots-from-seeds]
                [--upstream-depth N] [--downstream-depth M]
```

- **`--fail-on` is required in v1 — no default.** A gate whose policy is
  implicit is a gate nobody reviewed; forcing the flag makes every CI config
  self-documenting. The asymmetry argument (same reasoning as the strict
  zero-match decision in the ADR-0002 amendment): adding a default later is a
  compatible relaxation, while removing or changing a default breaks existing
  pipelines silently. Threshold values are accepted case-insensitively and
  normalized to upper case.
- **Shared flags are defined once** via an argparse parent parser
  (`add_help=False`) holding everything `report` and `check` have in common:
  `--source`, the connector options, `--dialect`, and the entire root-selector
  group (`--root`, `--roots-file`, `--roots-from-seeds`, depths). `check`
  adds only `--fail-on` and its own `--format {text|json}`. The existing
  helpers `_make_source` and `_build_selection` are reused unchanged —
  `check` performs the same graph build and `trace()` call as `report`, then
  applies `evaluate_gate`.
- `--source mock` works with `check` like everywhere else, so
  `sensiflow check --source mock --fail-on HIGH` is a network-free,
  self-contained smoke test of the exit-code contract (usable in sensiflow's
  own CI and in demos).

The intended CI one-liner (as previewed in the ADR-0002 amendment):

```
sensiflow check --source dbt --dbt-manifest target/manifest.json \
    --roots-from-seeds --fail-on HIGH
```

### 4. Output: stdout carries the result, format chosen by `--format`

`check` follows the same stream discipline as `report`: the result document
goes to **stdout** in the chosen format; errors and diagnostics go to
**stderr**; the verdict is authoritative in the **exit code**.

- **`--format text` (default)** — a compact gate summary rendered by a new
  `report.render_check_text(result, outcome)`: the threshold, the per-risk
  summary counts, any `TraceResult.warnings`, the violating nodes with their
  at-or-above-threshold findings (column, risk, reason, confidence, origin),
  and a final `PASS`/`FAIL` line. Violations only — `check` does not dump the
  whole graph; that is `report`'s job. Synthetic example:

  ```
  sensiflow check — fail-on=HIGH — 7 nodes analyzed
  summary: HIGH=1  MEDIUM=2  LOW=1  ORIGIN=1  NONE=2
  [HIGH] mart_orders_enriched  (owners: team-sales)
      email        HIGH    used in JOIN condition   conf=0.80  origin=raw_customers
  result: FAIL — 1 node at or above HIGH
  ```

- **`--format json`** — a machine-stable, gate-focused document rendered by
  `report.render_check_json(result, outcome)`; nothing else is written to
  stdout in this mode:

  ```json
  {
    "fail_on": "HIGH",
    "tripped": true,
    "summary": {"HIGH": 1, "MEDIUM": 2, "LOW": 1, "ORIGIN": 1, "NONE": 2},
    "warnings": [],
    "violations": [ ...node objects, identical shape to report --format json... ]
  }
  ```

  Violation entries reuse the exact node serialization of the existing
  `render_json` — one serializer, one shape, no drift between `report` and
  `check` JSON. The document's evolution rule is **additive-only**: new keys
  may appear; existing keys never change meaning or type.

- **Warnings do not affect the exit code in v1.** They are printed in both
  formats (and are structurally present in the JSON) so CI logs surface them,
  but a warned run that finds nothing at threshold exits 0. See open
  question 2 — the upstream-truncation warning is the one case where this
  default is genuinely debatable.

- **Confidence does not affect the gate in v1.** Every finding's confidence
  is displayed in both formats, but a low-confidence HIGH finding trips the
  gate like any other. A `--min-confidence` filter is a compatible future
  addition (see open question 3); shipping without it keeps v1 conservative —
  false positives in a gate are visible and annoying, false negatives are
  invisible and dangerous.

## Consequences

### Positive

- CI pipelines get a one-line PII gate with an exit contract that cleanly
  separates "exposure found" (1) from "fix your invocation" (2) from "retry
  later / fix the environment" (3).
- The gate decision is importable (`evaluate_gate`) — scripts, notebooks, and
  future agent interfaces get identical semantics without subprocess parsing.
- Zero new dependencies; zero engine changes; zero `LineageSource` changes
  (the shape-stable protocol from the ADR-0002 amendment is consumed as-is).
- Shared parent parser means `report` and `check` cannot drift apart on
  sources, selectors, or depths.
- `--source mock` gives a network-free end-to-end test of every exit path.

### Negative / accepted trade-offs

- The taxonomy is a forever contract: four codes, documented, frozen.
  Flexibility is deliberately spent now, before the first release, because
  changing exit codes later breaks CI configs invisibly.
- `check` catches broad `Exception` to protect exit code 1. The traceback is
  preserved on stderr, but a purist "let it crash" stack is lost. Accepted:
  contract integrity outranks crash aesthetics in a gate.
- Aligning `report`'s existing error exits (1 → 2/3) is a behavior change for
  anyone already scripting around it. Accepted: pre-release, and the old
  behavior was never documented as a contract.
- Required `--fail-on` adds one mandatory flag to every invocation. Accepted
  for self-documenting CI configs; a default can be added compatibly later if
  usage shows demand.
- Warnings not affecting the exit code means a truncated-upstream run can
  exit 0 while its findings are incomplete; mitigated by prominent warning
  output, revisited in open question 2.

### Follow-ups

- Document the exit-code table in the README/CLI help — it is user-facing
  contract, not internal design.
- Once GitHub Actions CI exists for this repo, add
  `sensiflow check --source mock --fail-on HIGH` (and a below-threshold
  variant) as smoke steps exercising exit codes 1 and 0.
- The future `propagate` command adopts the same taxonomy (0/2/3; whether it
  may use 1 for "plan not empty" in a check-like dry-run mode is decided in
  its own ADR).

## Alternatives considered

### Exit-code taxonomy

1. **ruff/grep-style 0/1/2** (findings=1, every error=2). Smaller contract,
   but it conflates a typo'd flag with a catalog outage — CI retry logic then
   has to parse stderr to decide whether a rerun can help. One extra code
   costs nothing and removes that. Rejected.
2. **pytest-style fine granularity** (separate codes for internal error,
   interruption, "nothing analyzed"). More contract surface to keep stable
   than value delivered: "nothing analyzed" is already an input error (strict
   zero-match selectors) or a warned-but-valid empty report, and internal
   errors fold into 3 with a traceback. Rejected.
3. **sysexits.h codes** (`EX_USAGE=64`, `EX_UNAVAILABLE=69`, ...). Nobody in
   this tool class (ruff, pytest, pip-audit, mypy) uses them, argparse's
   native 2 conflicts with the convention, and the values read as magic
   numbers in CI configs. Rejected.

### Where the gate logic lives

4. **Inline in the CLI** (call `result.by_risk(threshold)` and map to an exit
   code, no library function). Fewest moving parts, but the gate policy
   (threshold validation, ORIGIN exclusion, violation ordering) becomes
   CLI-only — unimportable, and the library-first rule exists precisely so
   that behavior like this is not locked behind a subprocess. Rejected.
5. **A method on `TraceResult`** (`result.gate(fail_on)`). Close call, but
   `TraceResult` is engine output and `model.py` is deliberately policy-free;
   the gate is a *consumer* policy applied to results, like rendering. Keeping
   it in a sibling module preserves that separation and keeps `model.py` from
   accreting verdict logic. Rejected (mild preference, revisitable).

### `check` as a command vs a flag

6. **`report --fail-on HIGH` instead of a separate command.** One subcommand
   fewer, but it would make `report`'s exit code mode-dependent — the same
   command exits 0 or 1 depending on a flag, which is exactly the ambiguity
   the taxonomy exists to kill. It also muddies future divergence (check-only
   flags like `--min-confidence`, report-only formats like HTML). The
   packaging model has treated `check` as a distinct mode from the start.
   Rejected.

### Flag sharing

7. **Duplicate the flag definitions on each subparser.** Trivially simple
   today, guaranteed drift tomorrow (nine shared flags and counting).
   Rejected. (A shared `_add_common_args(subparser)` helper is an acceptable
   implementation-level equivalent of the parent parser; the decision being
   recorded is *single definition*, not the argparse mechanism.)

### Output design

8. **Human summary on stderr, JSON always on stdout.** Attractive for CI
   (`check > findings.json` still shows a summary in the log), but it splits
   one logical result across two streams, invites `2>&1` ordering artifacts,
   and diverges from `report`'s conventions — and stream assignment is itself
   a contract, so switching later would be a breaking change in the wrong
   direction. Rejected in favor of explicit `--format`.
9. **Silent by default — exit code only.** Unix-pure, hostile in practice: a
   red CI job with an empty log forces a local rerun just to see what
   tripped. Rejected.
10. **Full report dump on gate trip** (print everything `report` would).
    Noisy in CI logs and redundant — anyone wanting the full picture runs
    `report`; `check` shows violations only. Rejected.

## Open questions (to resolve at review, before implementation)

1. **`--fail-on` default.** Decided above as *required, no default*;
   recommendation stands on the compatibility asymmetry (adding a default
   later is safe, changing one is not). Confirm, or pick a default
   (`HIGH` would be the candidate) if one-flag-less ergonomics matter more.
2. **Should warnings affect the exit code?** v1 says no. The sharp edge: the
   ADR-0002 upstream-truncation warning flags a possible *false-clean* graph
   — exit 0 on such a run can greenlight a pipeline on incomplete data.
   Options: (a) keep v1 as decided and revisit on evidence; (b) add
   `--strict-warnings` (any warning → non-zero) now; (c) make the
   dangerous-truncation warning specifically trip exit 1. Note that (b)/(c)
   are compatible *tightenings* only if introduced behind a flag; making them
   default later changes passing pipelines to failing ones.
3. **Confidence and the gate.** v1 gates on risk alone. Should a
   `--min-confidence X` filter ship in this slice (low-confidence HIGH
   findings stop tripping CI — lower false-positive cost, higher
   false-negative risk), or stay a backlog item until real usage shows the
   false-positive rate? Recommendation: defer; the flag is a compatible
   addition.
4. **Retroactive alignment of `report`'s error exits** (currently 1 on any
   `SensiflowError`, becoming 2/3 per the table). Decided above as in-scope
   for this slice; confirm, since it technically changes existing observable
   behavior.
