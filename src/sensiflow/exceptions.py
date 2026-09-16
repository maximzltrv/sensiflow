"""Sensiflow exception hierarchy.

Kept dependency-free so the CLI (and library users) can catch connector
errors without importing any connector module.
"""

from __future__ import annotations


class SensiflowError(Exception):
    """Base class for all sensiflow errors."""


class SensiflowDependencyError(SensiflowError):
    """An optional extra is required but not installed; message names the fix."""


class SensiflowConnectionError(SensiflowError):
    """Talking to a catalog failed.

    Messages must identify the host and status but never carry credentials
    or request headers (ADR-0002 secrets hygiene).
    """
