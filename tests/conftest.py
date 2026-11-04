"""Shared fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.support import FIXTURE_PROJECT


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A private, writable copy of the synthetic dbt project in tests/fixtures/dbt_project."""
    target = tmp_path / "proj"
    shutil.copytree(FIXTURE_PROJECT, target)
    return target
