# syntax=docker/dockerfile:1

# ---- builder: build the wheel and export the pinned dependency set ----------
FROM python:3.13.18@sha256:f32f0f0e0d159bb11df450a10a84e9fae1ff115d4e67710f082a47d0a139dad9 AS builder

RUN pip install --no-cache-dir poetry==2.4.1 poetry-plugin-export==1.10.1

WORKDIR /build
COPY pyproject.toml poetry.lock README.md LICENSE ./
COPY src ./src

RUN poetry build --format wheel \
 && poetry export --only main --extras "server openmetadata yaml" \
        --format requirements.txt --output requirements.txt

# ---- runtime: no poetry, no compilers, no source tree ------------------------
FROM python:3.13.18-slim@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5

# The wheel and the pinned requirements are bind-mounted from the builder for this
# one step, so they never exist in a runtime layer and need no cleanup.
RUN --mount=type=bind,from=builder,source=/build,target=/build \
    pip install --no-cache-dir -r /build/requirements.txt \
 && pip install --no-cache-dir --no-deps /build/dist/*.whl \
 && pip check \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sensiflow

USER 10001

EXPOSE 8000

# The probe targets port 8000, the image's default. If you override CMD with a
# different --port, the container will report unhealthy: override the healthcheck too.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/v1/health', timeout=3)"]

ENTRYPOINT ["sensiflow"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
