# syntax=docker/dockerfile:1

# ---- builder: build the wheel and export the pinned dependency set ----------
FROM python:3.13 AS builder

RUN pip install --no-cache-dir poetry poetry-plugin-export

WORKDIR /build
COPY pyproject.toml poetry.lock README.md LICENSE ./
COPY src ./src

RUN poetry build --format wheel \
 && poetry export --only main --extras "server openmetadata yaml" \
        --format requirements.txt --output requirements.txt

# ---- runtime: no poetry, no compilers, no source tree ------------------------
FROM python:3.13-slim

COPY --from=builder /build/requirements.txt /build/dist/*.whl /tmp/install/

RUN pip install --no-cache-dir -r /tmp/install/requirements.txt \
 && pip install --no-cache-dir "$(ls /tmp/install/*.whl)[server,openmetadata,yaml]" \
 && rm -rf /tmp/install \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sensiflow

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/v1/health', timeout=3)"]

ENTRYPOINT ["sensiflow"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
