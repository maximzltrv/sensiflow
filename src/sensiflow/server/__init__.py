"""HTTP server layer (ADR-0005), shipped behind the ``server`` extra.

Nothing outside this package imports it; the CLI loads it lazily for ``serve``.
"""

from sensiflow.server.app import create_app

__all__ = ["create_app"]
