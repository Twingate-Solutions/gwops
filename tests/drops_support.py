"""Shared expectation for ``DropCounters.snapshot()``."""


def expected_drops(**counts: int) -> dict[str, int]:
    """Every drop reason at zero except the given counts."""
    return {"not_json": 0, "not_allowlisted": 0, "too_long": 0, "spool_failed": 0, **counts}
