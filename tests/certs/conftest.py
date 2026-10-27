"""Fixtures shared by the certificate store tests."""

from collections.abc import Iterator

import pytest

from tests.store_support import FsProbe


@pytest.fixture
def probe() -> Iterator[FsProbe]:
    """A filesystem probe, not yet started: call ``probe.start()`` after test setup."""
    instance = FsProbe()
    yield instance
    instance.stop()
