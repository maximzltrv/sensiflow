"""Shared test setup."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _capture_server_logs(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """The server logger does not propagate (ADR-0005), so attach caplog to it directly."""
    logger = logging.getLogger("sensiflow.server")
    logger.addHandler(caplog.handler)
    yield
    logger.removeHandler(caplog.handler)
