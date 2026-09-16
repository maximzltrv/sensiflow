"""Thin CLI wrapper over the sensiflow library. All logic lives in the library."""

from __future__ import annotations

import argparse
import json
import os
import sys

from sensiflow.engine import trace
from sensiflow.exceptions import SensiflowError
from sensiflow.report import render_json, render_text
from sensiflow.sources.base import LineageSource
from sensiflow.sources.mock import MockSource


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sensiflow",
        description="Propagate PII tags along data lineage and classify exposure risk.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="analyze lineage and print a risk report")
    report.add_argument(
        "--source",
        choices=["mock", "openmetadata"],
        default="mock",
        help="lineage source (default: the built-in mock graph)",
    )
    report.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    report.add_argument(
        "--dialect",
        default="bigquery",
        help="SQL dialect for parsing transformation SQL (default: bigquery)",
    )
    report.add_argument(
        "--omd-host",
        help="OpenMetadata host, e.g. http://localhost:8585 (or OMD_HOST env var)",
    )
    report.add_argument(
        "--omd-token",
        help="OpenMetadata JWT token (or OMD_TOKEN env var; prefer the env var)",
    )
    report.add_argument(
        "--root",
        action="append",
        dest="roots",
        metavar="FQN",
        help="table FQN to walk lineage from; repeatable; omit for a full catalog scan",
    )
    report.add_argument(
        "--upstream-depth",
        type=int,
        help="max hops upstream from the nearest root (0 disables; omit for unlimited)",
    )
    report.add_argument(
        "--downstream-depth",
        type=int,
        help="max hops downstream from the nearest root (0 disables; omit for unlimited)",
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
    return MockSource()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "report":
        for name in ("upstream_depth", "downstream_depth"):
            value = getattr(args, name)
            if value is not None and value < 0:
                parser.error(f"--{name.replace('_', '-')} must be >= 0")

        source = _make_source(parser, args)
        try:
            graph = source.build_graph(
                args.roots,
                upstream_depth=args.upstream_depth,
                downstream_depth=args.downstream_depth,
            )
        except SensiflowError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        result = trace(graph, dialect=args.dialect)
        if args.format == "json":
            print(json.dumps(render_json(result), indent=2))
        else:
            print(render_text(result), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
