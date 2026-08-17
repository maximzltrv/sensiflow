"""Thin CLI wrapper over the sensiflow library. All logic lives in the library."""

from __future__ import annotations

import argparse
import json
import sys

from sensiflow.engine import trace
from sensiflow.report import render_json, render_text
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
        choices=["mock"],
        default="mock",
        help="lineage source (only the built-in mock graph for now)",
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "report":
        graph = MockSource().build_graph()
        result = trace(graph, dialect=args.dialect)
        if args.format == "json":
            print(json.dumps(render_json(result), indent=2))
        else:
            print(render_text(result), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
