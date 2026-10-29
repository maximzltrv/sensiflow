# ADR-0004: `check` command — a CI gate with a fixed exit-code contract

- **Status:** Accepted (2026-10-29, after review; review decisions:
  `--fail-on` required with no default; warnings do not affect the exit code
  in v1; `--min-confidence` included in this slice with suppressed findings
  surfaced, never hidden; `report` error exits aligned to the taxonomy).
  Amended 2026-10-29 after implementation review — see Amendments A1–A4.
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
    min_confidence: float                # 0.0 = every finding gates (default)
    tripped: bool
    violations: tuple[NodeResult, ...]   # nodes with >=1 gating finding, most exposed first
    suppressed: tuple[tuple[str, Finding], ...]
    # (node_id, finding) pairs at/above fail_on risk but below min_confidence —
    # excluded from gating, surfaced for audit; empty at the default threshold

def evaluate_gate(
    result: TraceResult, *, fail_on: GateRisk, min_confidence: float = 0.0
) -> GateOutcome: ...
```

- `evaluate_gate` validates its policy inputs (`SensiflowInputError` for a
  threshold outside `LOW`/`MEDIUM`/`HIGH` or a `min_confidence` outside
  `[0.0, 1.0]`) and evaluates the gate **per finding**: a finding *gates*
  when its risk ranks at or above `fail_on` **and** its confidence is `>=
  min_confidence`. A node is a violation when it has at least one gating
  finding; violations are ordered as `TraceResult.by_risk` orders nodes
  (most exposed first, then by name). A finding at or above the risk
  threshold whose confidence is below `min_confidence` is *suppressed*:
  collected into `GateOutcome.suppressed` (same ordering: risk descending,
  then node name, then column), never silently dropped. At the default
  `min_confidence=0.0` nothing is ever suppressed and the gate reduces to
  pure risk evaluation. See §5 for the policy rationale.
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
                [--min-confidence X]
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
- **`--min-confidence X` is optional, default `0.0`** (float; valid range
  `0.0`–`1.0`, validated in `evaluate_gate` so library callers get the same
  check; an out-of-range value is a usage error, exit 2). At the default,
  every finding gates — the flag is strictly opt-in, so the out-of-the-box
  gate can never produce a confidence-induced false negative. Semantics and
  output treatment are defined in §5.
- **Shared flags are defined once** via an argparse parent parser
  (`add_help=False`) holding everything `report` and `check` have in common:
  `--source`, the connector options, `--dialect`, and the entire root-selector
  group (`--root`, `--roots-file`, `--roots-from-seeds`, depths). `check`
  adds only `--fail-on`, `--min-confidence`, and its own
  `--format {text|json}`. The existing
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
    "min_confidence": 0.0,
    "tripped": true,
    "summary": {"HIGH": 1, "MEDIUM": 2, "LOW": 1, "ORIGIN": 1, "NONE": 2},
    "warnings": [],
    "violations": [ ...node objects, identical shape to report --format json... ],
    "suppressed": [ ...finding objects plus node identity, see §5; [] by default... ]
  }
  ```

  Violation entries reuse the exact node serialization of the existing
  `render_json` — one serializer, one shape, no drift between `report` and
  `check` JSON. The document's evolution rule is **additive-only**: new keys
  may appear; existing keys never change meaning or type.

- **Warnings do not affect the exit code in v1** (confirmed at review). They
  are printed in both formats (and are structurally present in the JSON) so
  CI logs surface them, but a warned run that finds nothing at threshold
  exits 0. The upstream-truncation warning is the known sharp edge of this
  default — a truncated run can exit 0 on incomplete data; revisit on
  evidence (a `--strict-warnings` flag is a compatible tightening if
  introduced as opt-in).

### 5. Confidence threshold: `--min-confidence` filters the gate, never the eyes

Decided at review (2026-10-29) to ship in this slice rather than defer: the
false-positive cost of a gate is paid on every red pipeline, so the control
must exist from day one — but it is designed so that using it never hides
information.

- **Semantics.** A finding gates only when `risk >= fail_on` **and**
  `confidence >= min_confidence` (inclusive on both). Filtering is
  per-finding, not per-node: a node whose low-confidence HIGH finding is
  suppressed still violates if it has another gating finding. The comparison
  is against the finding's own `confidence` as produced by the engine
  (ADR-0001 §4); the gate adds no confidence model of its own.
- **Default `0.0` — no filtering.** The flag is opt-in. The out-of-the-box
  gate therefore cannot miss a real exposure because of a confidence
  heuristic; teams that raise the threshold do so explicitly, in a reviewable
  CI config line.
- **Suppressed findings are always shown, never silently dropped.** Silent
  suppression in a gate is dangerous: a passing pipeline must be auditable.
  Every at-or-above-risk finding whose confidence fell below the threshold is
  surfaced:
  - in `GateOutcome.suppressed` (the library truth);
  - in `--format json` under the `suppressed` key — finding objects in the
    same shape as report findings, each extended with `node_id` and node
    `name`;
  - in `--format text` as a dedicated section after the violations, e.g.:

    ```
    suppressed by --min-confidence 0.75 (not gating): 1 finding
    [HIGH] mart_customer_dump.email   conf=0.56  origin=raw_customers
    ```

  - and the verdict line states the count whenever it is non-zero:
    `result: PASS — no findings at or above HIGH with confidence >= 0.75
    (1 suppressed below confidence)`. A pass that depended on suppression is
    thus visibly different from a clean pass in the log, even though both
    exit 0.
- **Filtering lives in `evaluate_gate`** (§2), keeping it pure and identical
  for CLI and library callers; the renderers only display what the outcome
  already contains, and the CLI maps `tripped` to the exit code as before.
- **Explicit warning — the false-negative trade.** Confidence is lowered
  exactly on the heuristic detection paths (pure name matches, aliasing,
  `SELECT *` inheritance). A non-zero `min-confidence` therefore
  preferentially suppresses the findings the engine is least certain about —
  which includes real exposures that merely traveled a heuristic path. The
  filter trades invisible-by-default false negatives for fewer false alarms;
  the suppressed section exists so the trade is auditable, and the
  recommended practice (to be stated in user docs) is to keep `0.0` until a
  concrete false-positive rate justifies raising it.

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
  output, revisited on evidence (opt-in `--strict-warnings` is the compatible
  escape hatch).
- A non-zero `--min-confidence` makes the gate blind to real exposures whose
  detection was heuristic — a deliberate, user-chosen false-negative risk
  (§5). Mitigated by the opt-in `0.0` default and by always surfacing
  suppressed findings; cannot be eliminated while column matching is
  name-based (ADR-0001 accepted trade-off).

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

### Confidence filtering (§5)

11. **Defer `--min-confidence` to a later release** (ship v1 gating on risk
    alone; the flag is a compatible addition). This was the draft's original
    recommendation — conservative, smallest slice. Rejected at review: the
    false-positive cost of a gate is paid immediately and repeatedly by its
    adopters, and shipping the control with a `0.0` opt-in default keeps the
    conservative behavior as the default anyway, so deferral bought nothing
    but a second release cycle.
12. **Silent suppression** (filtered findings simply absent from output).
    Simplest renderer, dangerous gate: a pipeline passing *because* evidence
    was filtered would be indistinguishable from a clean pass. Rejected —
    suppressed findings are always surfaced (§5).
13. **Node-level filtering** (recompute a node's `max_risk` over
    confidence-eligible findings only, then gate on nodes). Equivalent trip
    behavior, but it redefines a displayed aggregate (`max_risk`) per policy
    run and would make `check` output disagree with `report` for the same
    node. Per-finding filtering leaves all engine outputs untouched.
    Rejected.
14. **A distinct exit code for "passed only due to suppression."** Honest
    idea, but it grows the frozen taxonomy for a state that is already
    visible in both output formats, and CI cannot do anything with it except
    what reading the output achieves. Rejected; revisit only with the
    warnings question if evidence demands a "qualified pass" concept.

## Amendments (2026-10-29, post-implementation review)

Implementation review surfaced four points where the decision text was
silent or ambiguous. The following clarifications are part of the accepted
decision.

### A1. The exception wrapper applies to every command

§1's mechanism paragraph named only `check`, while the taxonomy table says
"any command". The table is authoritative: **every** subcommand (`report`
and `check` today, future commands too) runs inside the same wrapper —
`SensiflowError` subclasses map to 2 or 3 per the table, and any other
exception is printed with its full traceback to stderr and maps to 3.
`report` therefore can never exit 1 under any input, including inputs that
crash the engine.

### A2. Failures to write the result to stdout

The decision made the exit code the authoritative verdict channel but did
not say what happens when writing the stdout document itself fails. The
emission of the result is part of the protected region — a write failure
must never surface as an unhandled exception (which would exit 1 and fake a
gate trip). Two cases, separated by whether anything actually went wrong:

- **`BrokenPipeError` (EPIPE)** after the verdict is computed: the consumer
  stopped reading (`check ... | head`). Nothing failed in the run; the
  verdict stands. The process exits with the computed verdict code (0 or 1),
  suppressing the secondary pipe traceback.
- **Any other write failure** (encoding errors under a constrained locale,
  disk full, I/O error): the result document was not delivered, so the run
  did not complete — exit 3, traceback to stderr (best effort).

Alternatives considered: mapping EPIPE to 3 would turn `check | head -1`
into a false "operational error" and invite pointless CI retries on an
already-decided verdict — rejected. Letting write failures propagate exits 1
and is indistinguishable from a gate trip, which §1 forbids — rejected.

### A3. A cyclic lineage graph is an input error (exit 2)

The engine detects cycles deliberately; a cyclic graph describes impossible
lineage in the user's catalog or manifest — not retryable, not a tool bug.
The engine's cycle error is reclassified from a plain `ValueError` to
`SensiflowInputError`, mapping to exit 2 with a one-line message instead of
exit 3 with a traceback. This amends the "zero engine changes" consequence
by exactly one exception type; propagation logic is untouched.
Alternative — leave it at 3 as an "unexpected internal error": rejected; the
error is neither unexpected (it is explicitly raised) nor environmental.

### A4. The §5 confidence comparison happens at published precision

Engine confidences are products of heuristic factors; the float product of,
e.g., `0.8 * 0.7` is `0.5599999999999999`, which every output channel
publishes as `0.56` (the JSON renderer rounds confidences to 4 decimal
places). A user copying the published value into `--min-confidence` would
see the finding suppressed — a false negative in the gate's dangerous
direction, induced by the tool's own output.

Decision: `evaluate_gate` performs the inclusive comparison at the published
precision — both the finding's confidence and `min_confidence` are rounded
to 4 decimal places (the JSON output precision) before the `>=` comparison.
The range validation of `min_confidence` still applies to the raw value.
Corollary (deliberate, in the safe direction): a finding whose raw
confidence rounds up to the threshold also gates — e.g. confidence 0.99996
gates at `--min-confidence 1.0`, exactly as its published value (1.0)
promises; the rounding can only add gating findings, never suppress one
whose published value meets the threshold.

Alternatives considered:

- **Round confidences in the engine when producing findings.** Makes one
  number true everywhere, but changes core engine output to solve a
  display-precision problem, ripples into `report` output and the ADR-0001
  confidence model, and raises its own design question (round per
  propagation step or only at publication). Rejected as out of proportion
  and out of this slice's scope.
- **Document-only.** Leaves a gate false negative triggered by the tool's
  own published values. Rejected.

Caveat: the text renderer displays confidences at 2 decimal places, so a
threshold copied from text output can still mismatch a finding whose true
confidence has more digits. The JSON document is the machine-precision
channel; user docs should recommend taking thresholds from it. Suppressed
findings remain always visible (§5), so any residual mismatch is auditable.

## Review resolutions (2026-10-29)

The four questions the draft left open were resolved at review:

1. **`--fail-on` is required, no default** — confirmed as drafted
   (compatibility asymmetry: a default can be added later, not removed).
2. **Warnings do not affect the exit code in v1** — confirmed as drafted;
   warnings are displayed prominently in both formats. The
   upstream-truncation false-clean edge is acknowledged and will be revisited
   on evidence; any future tightening (`--strict-warnings` or
   truncation-trips-gate) must arrive as opt-in first.
3. **`--min-confidence` ships in this slice** — the draft's deferral
   recommendation was overruled. Design as specified in §5: per-finding
   filter inside `evaluate_gate`, opt-in default `0.0`, suppressed findings
   always surfaced in both formats, false-negative risk recorded as an
   explicit consequence.
4. **`report` error-exit alignment (1 → 2/3) is in scope for this slice** —
   confirmed as drafted.
