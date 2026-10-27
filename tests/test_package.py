"""Smoke test: the gwops package imports and exposes a version."""

import gwops


def test_package_has_version() -> None:
    assert gwops.__version__
