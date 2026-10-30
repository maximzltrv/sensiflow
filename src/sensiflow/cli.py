"""Thin CLI wrapper over the sensiflow library. All logic lives in the library."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from collections.abc import Callable
from enum import IntEnum

from sensiflow.engine import trace
from sensiflow.exceptions import SensiflowError, SensiflowInputError
from sensiflow.gate import evaluate_gate
from sensiflow.model import TraceResult
from sensiflow.report import (
    render_apply_text,
    render_check_json,
    render_check_text,
    render_json,
    render_plan_json,
    render_plan_text,
    render_text,
)
from sensiflow.root_selectors import GraphSelection, has_glob_chars, load_roots_file
from sensiflow.sources.base import LineageSource, WritebackTarget
from sensiflow.sources.mock import MockSource
from sensiflow.writeback import apply_writeback, diff_writeback, plan_writeback


class ExitCode(IntEnum):
    """Process exit contract, CLI-wide (ADR-0004 §1). Fixed; changes are major-version events."""

    OK = 0  # run completed; nothing at or above the threshold
    GATE_TRIPPED = 1  # `check` only; reserved exclusively for policy-gate trips
    INPUT_ERROR = 2  # usage or invalid local input (argparse's native 2 aligns)
    OPERATIONAL_ERROR = 3  # environment: catalog, missing extra, unexpected internal error


_EXIT_CODE_EPILOG = (
    "exit codes: 0 = clean pass, 1 = gate tripped (check only), "
    "2 = usage/input error, 3 = operational error (propagate: incl. failed writes)"
)


def _build_common_parser() -> argparse.ArgumentParser:
    """Flags `report` and `check` share, defined once (ADR-0004 §3: no drift)."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--source",
        choices=["mock", "openmetadata", "dbt"],
        default="mock",
        help="lineage source (default: the built-in mock graph)",
    )
    common.add_argument(
        "--dialect",
        default="bigquery",
        help="SQL dialect for parsing transformation SQL (default: bigquery)",
    )
    common.add_argument(
        "--omd-host",
        help="OpenMetadata host, e.g. http://localhost:8585 (or OMD_HOST env var)",
    )
    common.add_argument(
        "--omd-token",
        help="OpenMetadata JWT token (or OMD_TOKEN env var; prefer the env var)",
    )
    common.add_argument(
        "--dbt-manifest",
        metavar="PATH",
        help="path to a dbt manifest.json (required with --source dbt)",
    )
    common.add_argument(
        "--root",
        action="append",
        dest="roots",
        metavar="ID_OR_GLOB",
        help=(
            "node to walk lineage from: an exact id/FQN, or an fnmatch glob "
            "(*, ?, [) matched against node ids and bare names; repeatable; "
            "omit for a full catalog scan"
        ),
    )
    common.add_argument(
        "--roots-file",
        action="append",
        dest="roots_files",
        metavar="PATH",
        help=(
            "YAML roots file (version 1 schema; id/pattern entries); at most "
            "one occurrence; combines with --root as a union"
        ),
    )
    common.add_argument(
        "--roots-from-seeds",
        action="store_true",
        help=(
            "use every PII-seeded node as a root; mutually exclusive with "
            "--root and --roots-file"
        ),
    )
    common.add_argument(
        "--upstream-depth",
        type=int,
        help="max hops upstream from the nearest root (0 disables; omit for unlimited)",
    )
    common.add_argument(
        "--downstream-depth",
        type=int,
        help="max hops downstream from the nearest root (0 disables; omit for unlimited)",
    )
    return common


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sensiflow",
        description="Propagate PII tags along data lineage and classify exposure risk.",
        epilog=_EXIT_CODE_EPILOG,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    common = _build_common_parser()

    report = subparsers.add_parser(
        "report",
        parents=[common],
        help="analyze lineage and print a risk report",
        epilog=_EXIT_CODE_EPILOG,
    )
    report.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )

    check = subparsers.add_parser(
        "check",
        parents=[common],
        help="CI gate: exit 1 when PII exposure reaches the --fail-on threshold",
        epilog=_EXIT_CODE_EPILOG,
    )
    check.add_argument(
        "--fail-on",
        type=str.upper,
        choices=["LOW", "MEDIUM", "HIGH"],
        required=True,
        help="risk threshold that trips the gate (required; case-insensitive)",
    )
    check.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="X",
        help=(
            "minimum finding confidence to gate on, 0.0-1.0 (default: 0.0 — "
            "every finding gates); filtered findings are reported, never hidden"
        ),
    )
    check.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )

    propagate = subparsers.add_parser(
        "propagate",
        parents=[common],
        help="write derived PII markup back to the source (dry-run unless --apply --yes)",
        epilog=_EXIT_CODE_EPILOG,
    )
    propagate.add_argument(
        "--min-risk",
        type=str.upper,
        choices=["LOW", "MEDIUM", "HIGH"],
        required=True,
        help="lowest risk to write back (required; case-insensitive)",
    )
    propagate.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="X",
        help=(
            "minimum finding confidence to write, 0.0-1.0 (default: 0.0); "
            "filtered findings are reported, never hidden"
        ),
    )
    mode = propagate.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be written, change nothing (the default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="write the pending changes to the source; requires --yes",
    )
    propagate.add_argument(
        "--yes",
        action="store_true",
        help="confirm --apply (there is no interactive prompt)",
    )
    propagate.add_argument(
        "--dbt-project-dir",
        metavar="PATH",
        help="dbt project directory holding the properties YAML files (required with --source dbt)",
    )
    propagate.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    return parser


def _make_source(parser: argparse.ArgumentParser, args: argparse.Namespace) -> LineageSource:
    if args.source == "openmetadata":
        host = args.omd_host or os.environ.get("OMD_HOST")
        token = args.omd_token or os.environ.get("OMD_TOKEN")
        if not host or not token:
            parser.error(
                "--source openmetadata requires --omd-host and --omd-token "
                "(or the OMD_HOST / OMD_TOKEN environment variables)"
            )
        # Imported only on demand: the base install has no httpx.
        from sensiflow.sources.openmetadata import OpenMetadataSource

        return OpenMetadataSource(host, token)
    if args.source == "dbt":
        if not args.dbt_manifest:
            parser.error("--source dbt requires --dbt-manifest PATH")
        project_dir = getattr(args, "dbt_project_dir", None)
        if args.command == "propagate" and not project_dir:
            parser.error(
                "--source dbt with propagate requires --dbt-project-dir PATH "
                "(the properties YAML files are what gets read and edited)"
            )
        from sensiflow.sources.dbt import DbtSource

        return DbtSource(args.dbt_manifest, project_dir)
    return MockSource()


def _build_selection(args: argparse.Namespace) -> GraphSelection:
    """Fold the selector flags into one GraphSelection (validation lives there)."""
    roots: list[str] = []
    patterns: list[str] = []
    if args.roots_files:
        file_selection = load_roots_file(args.roots_files[0])
        roots.extend(file_selection.roots)
        patterns.extend(file_selection.patterns)
    for value in args.roots or []:
        (patterns if has_glob_chars(value) else roots).append(value)
    return GraphSelection(
        roots=tuple(roots),
        patterns=tuple(patterns),
        from_seeds=args.roots_from_seeds,
        upstream_depth=args.upstream_depth,
        downstream_depth=args.downstream_depth,
    )


def _trace_source(source: LineageSource, args: argparse.Namespace) -> TraceResult:
    graph = source.build_graph(_build_selection(args))
    return trace(graph, dialect=args.dialect)


def _run_trace(parser: argparse.ArgumentParser, args: argparse.Namespace) -> TraceResult:
    """The shared pipeline: source -> graph -> trace (identical for report and check)."""
    return _trace_source(_make_source(parser, args), args)


def _error_exit_code(exc: SensiflowError) -> ExitCode:
    """Map library errors to the taxonomy: bad input is 2, everything else is 3."""
    if isinstance(exc, SensiflowInputError):
        return ExitCode.INPUT_ERROR
    return ExitCode.OPERATIONAL_ERROR


def _silence_stdout() -> None:
    """Point fd 1 at devnull so interpreter shutdown cannot hit EPIPE again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass  # no real fd behind sys.stdout (e.g. captured in tests)


def _guarded(compute: Callable[[], tuple[str, ExitCode]]) -> int:
    """Run a command inside the CLI-wide error wrapper (ADR-0004 A1/A2).

    ``compute`` returns the rendered document and the verdict code. Emitting the
    document is part of the protected region: no failure path may exit 1.
    """
    verdict: ExitCode | None = None
    try:
        output, verdict = compute()
        print(output, end="")
        sys.stdout.flush()
    except BrokenPipeError:
        # The reader went away; nothing failed, so the computed verdict stands.
        _silence_stdout()
        return verdict if verdict is not None else ExitCode.OPERATIONAL_ERROR
    except SensiflowError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _error_exit_code(exc)
    except Exception:
        # Exit 1 is reserved for gate trips (ADR-0004 §1): an unexpected crash
        # must never fake one. Full traceback on stderr, honest exit code.
        traceback.print_exc(file=sys.stderr)
        return ExitCode.OPERATIONAL_ERROR
    return verdict


def _run_report(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    def compute() -> tuple[str, ExitCode]:
        result = _run_trace(parser, args)
        if args.format == "json":
            return json.dumps(render_json(result), indent=2) + "\n", ExitCode.OK
        return render_text(result), ExitCode.OK

    return _guarded(compute)


def _run_check(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    def compute() -> tuple[str, ExitCode]:
        result = _run_trace(parser, args)
        outcome = evaluate_gate(result, fail_on=args.fail_on, min_confidence=args.min_confidence)
        if args.format == "json":
            output = json.dumps(render_check_json(result, outcome), indent=2) + "\n"
        else:
            output = render_check_text(result, outcome)
        return output, ExitCode.GATE_TRIPPED if outcome.tripped else ExitCode.OK

    return _guarded(compute)


def _run_propagate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.apply and not args.yes:
        # No interactive prompt (useless in CI): --yes *is* the consent.
        parser.error("--apply requires --yes to confirm that the source will be modified")

    def compute() -> tuple[str, ExitCode]:
        source = _make_source(parser, args)
        if not isinstance(source, WritebackTarget):
            raise SensiflowInputError(
                f"--source {args.source} does not support write-back (propagate)"
            )
        result = _trace_source(source, args)
        plan = plan_writeback(
            result, min_risk=args.min_risk, min_confidence=args.min_confidence
        )
        diff = diff_writeback(plan, source)
        as_json = args.format == "json"
        if not args.apply:
            if as_json:
                document = render_plan_json(diff, target=args.source)
                return json.dumps(document, indent=2) + "\n", ExitCode.OK
            return render_plan_text(diff, target=args.source), ExitCode.OK

        if not as_json:
            # The resolved diff goes out before anything is written.
            print(render_plan_text(diff, target=args.source, applying=True), end="")
            sys.stdout.flush()
        outcome = apply_writeback(diff, source, confirm=True)
        code = ExitCode.OPERATIONAL_ERROR if outcome.failed else ExitCode.OK
        if as_json:
            document = render_plan_json(diff, outcome, target=args.source)
            return json.dumps(document, indent=2) + "\n", code
        return render_apply_text(outcome), code

    return _guarded(compute)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.roots_files and len(args.roots_files) > 1:
        # argparse would silently keep the last occurrence; reject instead.
        parser.error("--roots-file may be given at most once")

    if args.command == "check":
        return _run_check(parser, args)
    if args.command == "propagate":
        return _run_propagate(parser, args)
    return _run_report(parser, args)


if __name__ == "__main__":
    sys.exit(main())
