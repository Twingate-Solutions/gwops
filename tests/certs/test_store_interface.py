"""The store interface `CertManager` relies on, against the real store and its stand-in.

`CertManager` may use only `install`, `stable_paths` and `gc` of the store. This module
runs the same contract against `gwops.certs.store.MaterialStore` (Linux only, it needs
symlinks) and against `tests.store_support.PlainFileStore`, the symlink-free stand-in the
suite substitutes on Windows. If the two ever disagree on what a leaf-minting test
can observe, this module fails on Linux.
"""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.store_support import PlainFileStore, make_pair, read_pair

StoreFactory = Callable[[Path], Any]


def _real_store(root: Path) -> Any:
    from gwops.certs.store import MaterialStore

    return MaterialStore(root)


@pytest.fixture(
    params=[
        pytest.param(
            _real_store,
            id="material_store",
            marks=pytest.mark.skipif(
                sys.platform == "win32",
                reason="creating symlinks needs elevation on Windows (WinError 1314)",
            ),
        ),
        pytest.param(PlainFileStore, id="plain_file_store"),
    ]
)
def make_store(request: pytest.FixtureRequest) -> StoreFactory:
    factory: StoreFactory = request.param
    return factory


def test_install_makes_the_pair_readable_at_the_stable_paths(
    make_store: StoreFactory, tmp_path: Path
) -> None:
    """The stable paths are <root>/<name>/fullchain.pem and privkey.pem and hold the pair."""
    store = make_store(tmp_path)
    pair = make_pair()

    result = store.install("leaf", pair.cert_pem, pair.key_pem)

    cert_path, key_path = store.stable_paths("leaf")
    assert cert_path == tmp_path / "leaf" / "fullchain.pem"
    assert key_path == tmp_path / "leaf" / "privkey.pem"
    assert read_pair(cert_path, key_path) == (pair.cert_pem, pair.key_pem)
    assert result.changed is True
    assert result.generation == pair.generation


def test_an_identical_install_reports_no_change(make_store: StoreFactory, tmp_path: Path) -> None:
    """Re-installing the same pair is reported as unchanged with the same generation."""
    store = make_store(tmp_path)
    pair = make_pair()
    first = store.install("leaf", pair.cert_pem, pair.key_pem)

    second = store.install("leaf", pair.cert_pem, pair.key_pem)

    assert second.changed is False
    assert second.generation == first.generation


def test_a_different_install_replaces_the_pair(make_store: StoreFactory, tmp_path: Path) -> None:
    """New content is reported as changed and is what the stable paths now serve."""
    store = make_store(tmp_path)
    old, new = make_pair("old"), make_pair("new")
    store.install("leaf", old.cert_pem, old.key_pem)

    result = store.install("leaf", new.cert_pem, new.key_pem)

    assert result.changed is True
    assert result.generation == new.generation
    assert read_pair(*store.stable_paths("leaf")) == (new.cert_pem, new.key_pem)


def test_an_identical_install_restores_a_removed_stable_file(
    make_store: StoreFactory, tmp_path: Path
) -> None:
    """The reconciler deletes the leaf cert to force a re-mint; install must put it back."""
    store = make_store(tmp_path)
    pair = make_pair()
    store.install("leaf", pair.cert_pem, pair.key_pem)
    cert_path, key_path = store.stable_paths("leaf")
    cert_path.unlink()

    store.install("leaf", pair.cert_pem, pair.key_pem)

    assert read_pair(cert_path, key_path) == (pair.cert_pem, pair.key_pem)


def test_gc_leaves_the_current_pair_readable(make_store: StoreFactory, tmp_path: Path) -> None:
    """gc never removes what the stable paths serve, and accepts a name or none."""
    store = make_store(tmp_path)
    pair = make_pair()
    store.install("leaf", pair.cert_pem, pair.key_pem)

    store.gc("leaf")
    store.gc()

    assert read_pair(*store.stable_paths("leaf")) == (pair.cert_pem, pair.key_pem)


def test_names_do_not_share_files(make_store: StoreFactory, tmp_path: Path) -> None:
    """Two names under one root are independent."""
    store = make_store(tmp_path)
    one, two = make_pair("one"), make_pair("two")

    store.install("leaf", one.cert_pem, one.key_pem)
    store.install("other", two.cert_pem, two.key_pem)

    assert read_pair(*store.stable_paths("leaf")) == (one.cert_pem, one.key_pem)
    assert read_pair(*store.stable_paths("other")) == (two.cert_pem, two.key_pem)
