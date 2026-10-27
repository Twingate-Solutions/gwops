"""Shared pytest fixtures for the gwops test suite."""

import sys
from collections.abc import Iterator

import structlog
from pytest import MonkeyPatch, fixture

# The live rig under tests/integration/webapp is run by `make integration-webapp`, never by
# `make test`. tests/test_rig_*.py (offline unit tests of its pure pieces) stay collected.
collect_ignore_glob = ["integration/webapp/*"]


@fixture(autouse=True)
def _reset_structlog_after_test() -> Iterator[None]:
    """Undo any `configure_logging()` call made by the test.

    `configure_logging()` binds structlog's global config to whatever `sys.stdout` is
    at call time. Tests that call it inside `capsys` bind to a stream `capsys` tears
    down when the test ends; without a reset, the next test to emit a real log call
    (not just ones under `test_logging.py`) crashes on "I/O operation on closed file".
    """
    yield
    structlog.reset_defaults()


@fixture(autouse=True)
def _windows_leaf_store(monkeypatch: MonkeyPatch) -> None:
    """Give `CertManager` and `Reconciler` a symlink-free store on Windows .

    Windows cannot create symlinks without elevation (WinError 1314), and every
    leaf mint goes through `gwops.certs.store.MaterialStore`. On win32 the manager's
    `MaterialStore` name is replaced by `PlainFileStore`, which has the same interface and
    writes plain files at the same stable paths. This needs `gwops.certs.manager` to import
    the class as `from gwops.certs.store import MaterialStore`. Tests of the real store
    import it from `gwops.certs.store` and skip on win32. Linux is unaffected.
    """
    if sys.platform != "win32":
        return
    from tests.store_support import PlainFileStore

    monkeypatch.setattr("gwops.certs.manager.MaterialStore", PlainFileStore, raising=False)
    # The reconciler's public certificate store is the same class, so the same stand-in.
    monkeypatch.setattr("gwops.reconciler.core.MaterialStore", PlainFileStore, raising=False)
