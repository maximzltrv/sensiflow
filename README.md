# sensiflow

Propagate PII tags along data lineage and classify **how exposed** the PII is at
each downstream data product.

> Status: early development. The public API is not stable yet.

## Why

Most catalogs can tell you *whether* a table contains PII. They rarely tell you
*how* that PII is used downstream — and the difference matters. A PII column used
as a `JOIN` key or in a `WHERE` filter is a direct re-identification vector; a
column that merely passes through a projection is not the same risk. Catalogs
like OpenMetadata also do not propagate PII tags along lineage out of the box.

`sensiflow` reads a lineage graph, seeds PII at declared sources, propagates it
downstream, and classifies each node by risk.

## Risk levels

| Risk | Condition |
|------|-----------|
| `ORIGIN` | Node is a declared PII source |
| `HIGH` | PII column used in a `JOIN` condition or `WHERE` clause |
| `MEDIUM` | PII column explicitly projected in `SELECT` |
| `LOW` | PII passed implicitly via `SELECT *`, or present via lineage only |
| `NONE` | No PII reaches the node |

Where transformation SQL is available it is parsed with
[`sqlglot`](https://github.com/tobymao/sqlglot) to detect `JOIN`/`WHERE` usage.
Where it is not, classification degrades gracefully to presence-based analysis.

## Install

```bash
pip install sensiflow                     # core
pip install 'sensiflow[openmetadata]'     # + OpenMetadata connector
pip install 'sensiflow[dbt]'              # + dbt write-back (comment-preserving YAML edits)
```

## Usage

Library first — the core returns structured objects and never prints:

```python
from sensiflow import trace

result = trace(graph)
for node in result.by_risk(minimum="HIGH"):
    print(node.node_id, node.owners)
```

The CLI is a thin wrapper over the same API:

```bash
sensiflow report    --omd-host $OMD_HOST --omd-token $OMD_TOKEN --format text
sensiflow check     --omd-host $OMD_HOST --omd-token $OMD_TOKEN --fail-on HIGH
sensiflow propagate --omd-host $OMD_HOST --omd-token $OMD_TOKEN --min-risk LOW --dry-run
sensiflow propagate --source dbt --dbt-manifest target/manifest.json \
                    --dbt-project-dir . --min-risk MEDIUM --apply --yes
```

Connection details are always supplied at runtime, via flags or the `OMD_HOST` /
`OMD_TOKEN` environment variables. Analysis is read-only; writing tags back to a
catalog is a separate command that is dry-run by default and requires explicit
confirmation to apply (`--apply --yes`).

`propagate` writes the derived PII markup next to a sensiflow marker
(`Sensiflow.Propagated` in OpenMetadata, `meta.sensiflow` in dbt properties files),
so tool-written markup is distinguishable from yours and never re-seeds a later
run. Markup you placed by hand is never overwritten: a contradicting tag is reported
as a conflict and left alone. To adopt a propagated tag as your own declaration,
remove its marker. For dbt, `--dbt-project-dir` is required: the properties YAML
files, not the manifest, are read and edited; models without a properties entry are
reported with a ready-to-paste snippet.

## Development

```bash
poetry install
poetry run pytest
poetry run ruff check .
poetry run mypy
```

## License

MIT
