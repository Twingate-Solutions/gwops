"""Tests for ``MaterialStore.read_current``: one generation read under the store lock.

``read_current(name)`` returns ``(cert_pem, key_pem, generation)`` read from a single generation
directory while holding the store lock, so a concurrent ``install`` can neither swap generations
between the two file reads nor delete the generation being read: the certificate and key
returned always belong together. A file that vanishes anyway is retried once against the
then-current generation, then raises ``StoreError``. Files are opened with ``O_NOFOLLOW``.

Every test needs real symlinks (``..data``), which the Windows dev host cannot create without
elevation, so the module skips on win32 and runs on Linux (same condition as ``test_store.py``).
Fault injection wraps ``gwops.certs.store._read_generation_file``, the one function that reads
a generation file.
"""

import os
import sys
import threading
from pathlib import Path

import pytest

from gwops.certs import store as store_module
from gwops.certs.store import MaterialStore, StoreError
from tests.store_support import FsProbe, Pair, generation_dirs, make_pair, pair_matches

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating symlinks needs elevation on Windows (WinError 1314); the store runs on Linux",
)

NAME = "web"
JOIN_SECONDS = 0.3  # how long the reader waits to see whether an install got past the lock


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "certs"


@pytest.fixture
def store(root: Path) -> MaterialStore:
    return MaterialStore(root)


@pytest.fixture
def pair_a() -> Pair:
    return make_pair("a")


@pytest.fixture
def pair_b() -> Pair:
    return make_pair("b")


def _current_dir(root: Path) -> Path:
    [only] = generation_dirs(root / NAME)
    return only


class TestReadsTheCurrentPair:
    def test_it_returns_the_installed_pair_and_its_generation(
        self, store: MaterialStore, pair_a: Pair
    ) -> None:
        installed = store.install(NAME, pair_a.cert_pem, pair_a.key_pem)

        assert store.read_current(NAME) == (pair_a.cert_pem, pair_a.key_pem, installed.generation)

    def test_the_generation_is_the_twelve_hex_id_of_the_pair(
        self, store: MaterialStore, pair_a: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)

        current = store.read_current(NAME)

        assert current is not None
        assert current[2] == pair_a.generation
        assert len(current[2]) == 12

    def test_it_agrees_with_what_the_stable_paths_serve(
        self, store: MaterialStore, pair_a: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        cert_path, key_path = store.stable_paths(NAME)

        current = store.read_current(NAME)

        assert current is not None
        assert (current[0], current[1]) == (cert_path.read_bytes(), key_path.read_bytes())

    def test_a_second_install_is_what_the_next_read_returns(
        self, store: MaterialStore, pair_a: Pair, pair_b: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        store.install(NAME, pair_b.cert_pem, pair_b.key_pem)

        assert store.read_current(NAME) == (pair_b.cert_pem, pair_b.key_pem, pair_b.generation)

    def test_the_returned_pair_always_matches(self, store: MaterialStore, pair_a: Pair) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)

        current = store.read_current(NAME)

        assert current is not None
        assert pair_matches(current[0], current[1])

    def test_reading_leaves_the_store_unchanged_and_the_lock_free(
        self, store: MaterialStore, root: Path, pair_a: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        before = sorted(p.name for p in (root / NAME).iterdir())

        store.read_current(NAME)

        assert sorted(p.name for p in (root / NAME).iterdir()) == before
        assert store._lock.locked() is False  # type: ignore[attr-defined]


class TestNothingInstalled:
    def test_an_unknown_name_is_none(self, store: MaterialStore) -> None:
        assert store.read_current(NAME) is None

    def test_a_directory_without_a_data_link_is_none(
        self, store: MaterialStore, root: Path
    ) -> None:
        (root / NAME).mkdir(parents=True)

        assert store.read_current(NAME) is None

    def test_a_data_link_that_is_not_a_generation_name_is_none(
        self, store: MaterialStore, root: Path
    ) -> None:
        (root / NAME).mkdir(parents=True)
        os.symlink("elsewhere", root / NAME / "..data")

        assert store.read_current(NAME) is None

    def test_a_data_link_to_a_wrong_length_generation_is_none(
        self, store: MaterialStore, root: Path
    ) -> None:
        (root / NAME).mkdir(parents=True)
        os.symlink("..abc", root / NAME / "..data")

        assert store.read_current(NAME) is None

    @pytest.mark.parametrize("name", ["", "UPPER", "has space", "a/b", "../x", "x" * 64])
    def test_an_invalid_name_is_a_value_error(self, store: MaterialStore, name: str) -> None:
        with pytest.raises(ValueError, match="invalid store name"):
            store.read_current(name)


class TestOneGenerationUnderTheLock:
    """A concurrent install can never produce a mixed certificate and key."""

    def test_an_install_started_mid_read_waits_and_the_pair_is_not_mixed(
        self,
        store: MaterialStore,
        root: Path,
        pair_a: Pair,
        pair_b: Pair,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        real_read = store_module._read_generation_file
        installer: list[threading.Thread] = []
        blocked: list[bool] = []
        calls: list[Path] = []

        def read_then_race(path: Path) -> bytes:
            data = real_read(path)
            calls.append(path)
            if len(calls) == 1:  # the certificate is read; now an install races the key read
                thread = threading.Thread(
                    target=store.install, args=(NAME, pair_b.cert_pem, pair_b.key_pem)
                )
                thread.start()
                installer.append(thread)
                thread.join(JOIN_SECONDS)
                blocked.append(thread.is_alive())  # still waiting for the store lock
            return data

        monkeypatch.setattr(store_module, "_read_generation_file", read_then_race)

        current = store.read_current(NAME)
        installer[0].join(10)

        assert blocked == [True], "the install ran while read_current held the store lock"
        assert current == (pair_a.cert_pem, pair_a.key_pem, pair_a.generation)
        assert len({p.parent for p in calls}) == 1, "both files come from one generation"
        assert not installer[0].is_alive()
        assert store.read_current(NAME) == (pair_b.cert_pem, pair_b.key_pem, pair_b.generation)

    def test_many_reads_during_repeated_installs_never_see_a_mixed_pair(
        self, store: MaterialStore, root: Path
    ) -> None:
        pairs = [make_pair(f"p{i}") for i in range(4)]
        by_generation = {p.generation: p for p in pairs}
        store.install(NAME, pairs[0].cert_pem, pairs[0].key_pem)
        stop = threading.Event()
        failures: list[str] = []

        def installer() -> None:
            index = 0
            while not stop.is_set():
                index = (index + 1) % len(pairs)
                pair = pairs[index]
                try:
                    store.install(NAME, pair.cert_pem, pair.key_pem)
                except Exception as exc:  # pragma: no cover - reported through `failures`
                    failures.append(f"install: {type(exc).__name__}")
                    return

        thread = threading.Thread(target=installer)
        thread.start()
        try:
            for _ in range(150):
                current = store.read_current(NAME)
                assert current is not None
                cert_pem, key_pem, generation = current
                expected = by_generation[generation]
                if (cert_pem, key_pem) != (expected.cert_pem, expected.key_pem):
                    failures.append(f"mixed pair under generation {generation}")
                    break
        finally:
            stop.set()
            thread.join(10)

        assert failures == []

    def test_the_lock_is_released_when_the_read_fails(
        self, store: MaterialStore, root: Path, pair_a: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        (_current_dir(root) / "privkey.pem").unlink()
        (_current_dir(root) / "privkey.pem").mkdir()  # a directory: not a regular file

        with pytest.raises(StoreError):
            store.read_current(NAME)

        assert store._lock.locked() is False  # type: ignore[attr-defined]
        assert store.gc() == []  # a lock-taking operation still runs


class TestRetryOnAVanishedFile:
    def test_a_file_that_vanishes_is_retried_once_against_the_then_current_generation(
        self,
        store: MaterialStore,
        root: Path,
        pair_a: Pair,
        pair_b: Pair,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        other_process = MaterialStore(root)  # its own lock: stands in for another process
        real_read = store_module._read_generation_file
        calls: list[str] = []

        def swap_before_first_read(path: Path) -> bytes:
            calls.append(path.parent.name)
            if len(calls) == 1:
                # The generation this attempt resolved is deleted by an install it cannot lock out.
                other_process.install(NAME, pair_b.cert_pem, pair_b.key_pem)
            return real_read(path)

        monkeypatch.setattr(store_module, "_read_generation_file", swap_before_first_read)

        current = store.read_current(NAME)

        assert current == (pair_b.cert_pem, pair_b.key_pem, pair_b.generation)
        assert calls[0] == f"..{pair_a.generation}"
        assert calls[1:] == [f"..{pair_b.generation}"] * 2  # attempt two reads both files

    def test_a_generation_that_stays_incomplete_raises_a_store_error_after_one_retry(
        self,
        store: MaterialStore,
        root: Path,
        pair_a: Pair,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        attempts: list[str] = []

        def always_missing(path: Path) -> bytes:
            attempts.append(path.name)
            raise FileNotFoundError(path)

        monkeypatch.setattr(store_module, "_read_generation_file", always_missing)

        with pytest.raises(StoreError) as caught:
            store.read_current(NAME)

        assert attempts == ["fullchain.pem", "fullchain.pem"]  # exactly one retry
        assert pair_a.generation in str(caught.value)
        assert NAME in str(caught.value)
        assert store._lock.locked() is False  # type: ignore[attr-defined]

    def test_the_retry_gives_up_without_leaking_file_contents(
        self,
        store: MaterialStore,
        root: Path,
        pair_a: Pair,
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        (_current_dir(root) / "privkey.pem").unlink()

        with pytest.raises(StoreError) as caught:
            store.read_current(NAME)

        message = str(caught.value)
        assert all(line not in message for line in pair_a.key_body_lines())
        assert "PRIVATE KEY" not in message


class TestRefusedFiles:
    def test_a_symlink_in_place_of_a_generation_file_is_never_followed(
        self, store: MaterialStore, root: Path, tmp_path: Path, pair_a: Pair, pair_b: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        outside = tmp_path / "outside-key.pem"
        outside.write_bytes(pair_b.key_pem)
        key_file = _current_dir(root) / "privkey.pem"
        key_file.unlink()
        os.symlink(outside, key_file)

        with pytest.raises(OSError) as caught:
            store.read_current(NAME)

        assert not isinstance(caught.value, StoreError)
        assert store._lock.locked() is False  # type: ignore[attr-defined]

    def test_a_directory_in_place_of_a_generation_file_is_a_store_error(
        self, store: MaterialStore, root: Path, pair_a: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        cert_file = _current_dir(root) / "fullchain.pem"
        cert_file.unlink()
        cert_file.mkdir()

        with pytest.raises(StoreError, match="not a regular file"):
            store.read_current(NAME)

    def test_an_oversized_generation_file_is_a_store_error(
        self, store: MaterialStore, root: Path, pair_a: Pair
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        big = _current_dir(root) / "fullchain.pem"
        big.chmod(0o644)
        big.write_bytes(b"x" * (store_module._MAX_READ_BYTES + 1))

        with pytest.raises(StoreError, match="bounded size"):
            store.read_current(NAME)

    def test_an_unreadable_file_is_a_raw_os_error_not_a_store_error(
        self, store: MaterialStore, root: Path, pair_a: Pair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)

        def denied(path: Path) -> bytes:
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr(store_module, "_read_generation_file", denied)

        with pytest.raises(PermissionError):
            store.read_current(NAME)

        assert store._lock.locked() is False  # type: ignore[attr-defined]


class TestOpensWithoutFollowingLinks:
    def test_every_generation_file_is_opened_with_o_nofollow(
        self, store: MaterialStore, pair_a: Pair, probe: FsProbe
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        probe.start()

        store.read_current(NAME)

        opened = [
            (path, call)
            for call in probe.named("open")
            if (path := call.path_arg(0)) is not None
            and path.name in {"fullchain.pem", "privkey.pem"}
        ]
        assert [path.name for path, _call in opened] == ["fullchain.pem", "privkey.pem"]
        for path, call in opened:
            flags = call.args[1] if len(call.args) > 1 else call.kwargs["flags"]
            assert flags & os.O_NOFOLLOW
            assert flags & os.O_ACCMODE == os.O_RDONLY
            assert path.parent.name.startswith("..") and path.parent.name != "..data"

    def test_the_stable_symlinks_are_not_used_for_the_read(
        self, store: MaterialStore, pair_a: Pair, probe: FsProbe
    ) -> None:
        store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
        probe.start()

        store.read_current(NAME)

        paths = [c.path_arg(0) for c in probe.named("open") if c.path_arg(0) is not None]
        assert not any(p.parent.name == NAME for p in paths)
