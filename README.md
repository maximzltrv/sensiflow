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
pip install 'sensiflow[server]'           # + HTTP API server
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
```

Connection details are always supplied at runtime, via flags or the `OMD_HOST` /
`OMD_TOKEN` environment variables. Analysis is read-only; writing tags back to a
catalog is a separate command that is dry-run by default and requires explicit
confirmation to apply.

## HTTP server

`sensiflow serve` runs a read-only HTTP API (`pip install 'sensiflow[server]'`):

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/health` | liveness; never calls the catalog |
| `POST /v1/report` | the `report --format json` document |
| `POST /v1/check` | the `check --format json` document; a tripped gate is still HTTP 200 |

```bash
curl -s localhost:8000/v1/check -H 'Content-Type: application/json' \
  -d '{"source": "mock", "fail_on": "HIGH"}' | jq -e '.tripped | not'
```

Catalog credentials are server-side configuration (`OMD_HOST`, `OMD_TOKEN`) and
never part of a request; use a read-only catalog token. Set `SENSIFLOW_API_TOKEN`
to require `Authorization: Bearer <token>` on `/v1/report` and `/v1/check`
(unset means the API is open, and the server logs a warning at startup; a set
but blank value refuses to start). The token is checked before the request body
is read, and with a token configured the interactive docs (`/docs`, `/openapi.json`)
are not served; without one they are available at `/docs`.

Requests are limited to a 1 MiB body, 1000 `roots` and 100 `patterns`. The server
speaks plain HTTP and has no per-request deadline: terminate TLS, enforce request
timeouts, and add rate limiting at your reverse proxy. `fail_on` is
case-insensitive. Error responses are `{"error": {"kind", "message"}}`; a source
the deployment has not configured (for example `openmetadata` without `OMD_HOST`
and `OMD_TOKEN`) is `503`, and catalog-side failures never echo the catalog address.

### Docker

The image runs the server by default and doubles as a containerized CLI. Tag it
with the package version. Its healthcheck probes port 8000 (the default `CMD`); if
you start the server on another port, override the healthcheck as well:

```bash
docker build -t sensiflow:0.1.0 .

# server mode
docker run --rm -p 8000:8000 \
  -e OMD_HOST -e OMD_TOKEN -e SENSIFLOW_API_TOKEN \
  sensiflow:0.1.0

# CLI mode (same image)
docker run --rm -e OMD_HOST -e OMD_TOKEN \
  sensiflow:0.1.0 check --source openmetadata --fail-on HIGH
```

## Development

```bash
poetry install
poetry run pytest
poetry run ruff check .
poetry run mypy
```

## License

MIT
