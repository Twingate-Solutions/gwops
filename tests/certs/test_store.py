"""Tests for gwops.certs.store.MaterialStore: the atomic certificate/key store.

Layout under ``<root>/<name>/``::

    ..<sha12>/fullchain.pem (0644), privkey.pem (0600)   generation directories
    ..data -> ..<sha12>                                    relative symlink, current generation
    fullchain.pem -> ..data/fullchain.pem                  stable relative symlinks
    privkey.pem   -> ..data/privkey.pem

``sha12`` is ``sha256(cert_pem + b"\\0" + key_pem).hexdigest()[:12]``. Every test here needs
real symlinks, which the Windows dev machine cannot create without elevation (WinError 1314),
so the whole module skips on win32 and runs on Linux. The interface the rest of the
suite relies on is covered for both platforms in ``test_store_interface.py``.

Fault injection patches ``os.*`` (see ``tests/store_support.py``), so the store must call
``os.symlink``, ``os.replace``, ``os.fsync`` and ``os.open`` as module attributes.
"""

import os
import stat
import sys
import threading
import traceback
from pathlib import Path

import pytest
import structlog

from gwops.certs.store import InstallResult, MaterialStore, StoreError
from tests.store_support import (
    DELETION_CALLS,
    FsCall,
    FsProbe,
    Pair,
    SimulatedCrash,
    generation_dirs,
    generation_id,
    is_inside,
    make_pair,
    pair_matches,
    read_pair,
    stray_temporaries,
    umask,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating symlinks needs elevation on Windows (WinError 1314); "
    "the store is exercised on Linux",
)

NAME = "web"


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


@pytest.fixture
def pair_c() -> Pair:
    return make_pair("c")


def _install(store: MaterialStore, pair: Pair, name: str = NAME) -> InstallResult:
    return store.install(name, pair.cert_pem, pair.key_pem)


def _served(store: MaterialStore, name: str = NAME) -> tuple[bytes, bytes]:
    """Read cert and key through the stable paths, as the gateway does."""
    return read_pair(*store.stable_paths(name))


def _dst_name(call: FsCall) -> str | None:
    dst = call.path_arg(1)
    return dst.name if dst else None


# --- construction, paths, naming -------------------------------------------------------


def test_constructing_a_store_touches_no_files(tmp_path: Path) -> None:
    """The constructor does no I/O, so a store may be built over a root that does not exist."""
    missing = tmp_path / "does" / "not" / "exist"

    MaterialStore(missing)

    assert not (tmp_path / "does").exists()


def test_stable_paths_are_the_cert_then_key_under_the_name_directory(
    store: MaterialStore, root: Path
) -> None:
    """stable_paths is pure: (fullchain.pem, privkey.pem) under root/name, nothing created."""
    cert_path, key_path = store.stable_paths(NAME)

    assert cert_path == root / NAME / "fullchain.pem"
    assert key_path == root / NAME / "privkey.pem"
    assert not root.exists()


@pytest.mark.parametrize(
    "bad_name", ["", ".", "..", "a/b", "../x", "UPPER", "under_score", "dot.ted", "x" * 64]
)
def test_install_rejects_names_that_could_escape_or_collide(
    store: MaterialStore, root: Path, pair_a: Pair, bad_name: str
) -> None:
    """Names follow [a-z0-9-]{1,63}; anything else is refused before any file is created."""
    with pytest.raises(ValueError, match="name"):
        _install(store, pair_a, bad_name)

    assert not root.exists() or list(root.iterdir()) == []


@pytest.mark.parametrize("which", ["cert", "key"])
def test_install_rejects_empty_material(
    store: MaterialStore, root: Path, pair_a: Pair, which: str
) -> None:
    """Empty certificate or key bytes are a ValueError; nothing is created."""
    cert, key = (b"", pair_a.key_pem) if which == "cert" else (pair_a.cert_pem, b"")

    with pytest.raises(ValueError, match="empty"):
        store.install(NAME, cert, key)

    assert not root.exists() or list(root.iterdir()) == []


# --- layout ----------------------------------------------------------------------------


def test_first_install_creates_exactly_the_documented_layout(
    store: MaterialStore, root: Path, pair_a: Pair
) -> None:
    """One generation dir, ..data, and the two stable relative links; nothing else."""
    result = _install(store, pair_a)

    name_dir = root / NAME
    generation = pair_a.generation
    assert {entry.name for entry in name_dir.iterdir()} == {
        "..data",
        f"..{generation}",
        "fullchain.pem",
        "privkey.pem",
    }
    assert os.readlink(name_dir / "..data") == f"..{generation}"
    assert os.readlink(name_dir / "fullchain.pem") == "..data/fullchain.pem"
    assert os.readlink(name_dir / "privkey.pem") == "..data/privkey.pem"
    generation_dir = name_dir / f"..{generation}"
    assert not generation_dir.is_symlink()
    assert sorted(entry.name for entry in generation_dir.iterdir()) == [
        "fullchain.pem",
        "privkey.pem",
    ]
    assert (generation_dir / "fullchain.pem").read_bytes() == pair_a.cert_pem
    assert (generation_dir / "privkey.pem").read_bytes() == pair_a.key_pem
    assert result.generation == generation
    assert result.changed is True
    assert result.previous is None


def test_install_creates_missing_parent_directories(tmp_path: Path, pair_a: Pair) -> None:
    """The root and the name directory are created on demand."""
    store = MaterialStore(tmp_path / "a" / "b" / "certs")

    _install(store, pair_a)

    assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)


def test_generation_id_is_the_first_12_hex_of_sha256_over_cert_nul_key(
    store: MaterialStore, pair_a: Pair
) -> None:
    """The documented content hash, so the id is deterministic across runs."""
    result = _install(store, pair_a)

    assert result.generation == generation_id(pair_a.cert_pem, pair_a.key_pem)
    assert len(result.generation) == 12
    assert result.generation == result.generation.lower()
    int(result.generation, 16)


def test_generation_id_changes_when_only_the_key_or_only_the_cert_changes(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """Both inputs feed the hash: swapping either half yields a different generation."""
    first = store.install(NAME, pair_a.cert_pem, pair_a.key_pem)
    second = store.install(NAME, pair_a.cert_pem, pair_b.key_pem)
    third = store.install(NAME, pair_b.cert_pem, pair_b.key_pem)

    assert len({first.generation, second.generation, third.generation}) == 3
    assert all(result.changed for result in (first, second, third))


def test_names_are_independent_directories_under_one_root(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """Installing for one name never touches another name's generation or links."""
    _install(store, pair_a, "alpha")
    _install(store, pair_b, "beta")
    _install(store, pair_b, "alpha")

    assert _served(store, "beta") == (pair_b.cert_pem, pair_b.key_pem)
    assert _served(store, "alpha") == (pair_b.cert_pem, pair_b.key_pem)
    assert [d.name for d in generation_dirs(root / "beta")] == [f"..{pair_b.generation}"]


# --- permissions -----------------------------------------------------------------------


@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077])
def test_files_are_exactly_0600_and_0644_under_any_umask(
    store: MaterialStore, root: Path, pair_a: Pair, mask: int
) -> None:
    """The key is 0600 and the certificate 0644 whatever the process umask is."""
    with umask(mask):
        _install(store, pair_a)

    generation_dir = root / NAME / f"..{pair_a.generation}"
    assert stat.S_IMODE((generation_dir / "privkey.pem").stat().st_mode) == 0o600
    assert stat.S_IMODE((generation_dir / "fullchain.pem").stat().st_mode) == 0o644
    assert stat.S_IMODE(generation_dir.stat().st_mode) & 0o022 == 0


def test_the_stable_paths_expose_the_same_modes_as_the_generation_files(
    store: MaterialStore, pair_a: Pair
) -> None:
    """stat through the stable symlinks reports the generation files' modes."""
    _install(store, pair_a)
    cert_path, key_path = store.stable_paths(NAME)

    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(cert_path.stat().st_mode) == 0o644


# --- the swap --------------------------------------------------------------------------


def test_a_changed_install_makes_exactly_one_rename_onto_data(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, probe: FsProbe
) -> None:
    """The swap is a single os.replace of a same-directory temporary relative symlink."""
    _install(store, pair_a)
    name_dir = root / NAME
    seen: list[dict[str, object]] = []

    def watch(call: FsCall) -> None:
        if call.name in ("replace", "rename") and _dst_name(call) == "..data":
            src = call.path_arg(0)
            assert src is not None
            seen.append(
                {
                    "src_name": src.name,
                    "src_dir": src.parent,
                    "is_link": os.path.islink(src),
                    "link_target": os.readlink(src) if os.path.islink(src) else None,
                }
            )

    probe.before(watch)
    probe.start()
    result = _install(store, pair_b)

    renames = probe.named("replace", "rename")
    onto_data = [call for call in renames if _dst_name(call) == "..data"]
    assert len(onto_data) == 1
    [info] = seen
    assert str(info["src_name"]).startswith("..data.tmp")
    assert info["src_dir"] == name_dir
    assert info["is_link"] is True
    assert info["link_target"] == f"..{pair_b.generation}"
    assert result.changed is True


def test_the_very_first_install_also_swaps_with_one_rename_onto_data(
    store: MaterialStore, pair_a: Pair, probe: FsProbe
) -> None:
    """An empty store goes through the same single rename; there is no special first path."""
    probe.start()

    _install(store, pair_a)

    onto_data = [c for c in probe.named("replace", "rename") if _dst_name(c) == "..data"]
    assert len(onto_data) == 1


def test_a_changed_install_serves_the_new_pair_through_the_stable_paths(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """After the swap the same stable paths read the new generation; ..data points at it."""
    _install(store, pair_a)

    result = _install(store, pair_b)

    assert _served(store) == (pair_b.cert_pem, pair_b.key_pem)
    assert os.readlink(root / NAME / "..data") == f"..{pair_b.generation}"
    assert result.generation == pair_b.generation
    assert result.changed is True


# --- previous generation ---------------------------------------------------------------


def test_the_previous_generation_is_gone_after_a_successful_install(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """Exactly one generation remains: the gateway's reloader needs the old files unlinked."""
    _install(store, pair_a)

    result = _install(store, pair_b)

    name_dir = root / NAME
    assert not (name_dir / f"..{pair_a.generation}").exists()
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{pair_b.generation}"]
    assert result.previous == pair_a.generation
    assert stray_temporaries(name_dir) == []


def test_the_previous_generation_is_deleted_only_after_the_swap(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, probe: FsProbe
) -> None:
    """At the swap the old generation is intact; at its first deletion ..data already moved."""
    _install(store, pair_a)
    name_dir = root / NAME
    previous = name_dir / f"..{pair_a.generation}"
    seen: dict[str, object] = {}

    def watch(call: FsCall) -> None:
        if call.name == "replace" and _dst_name(call) == "..data":
            seen["previous_intact_at_swap"] = (previous / "fullchain.pem").is_file() and (
                previous / "privkey.pem"
            ).is_file()
        if call.name in DELETION_CALLS and is_inside(call.path_arg(0), previous):
            seen.setdefault("data_at_first_deletion", os.readlink(name_dir / "..data"))

    probe.before(watch)
    probe.start()
    _install(store, pair_b)

    assert seen.get("previous_intact_at_swap") is True
    assert seen.get("data_at_first_deletion") == f"..{pair_b.generation}", (
        "the previous generation must be deleted after, never before, the swap"
    )


def test_reinstalling_an_earlier_pair_builds_a_fresh_generation(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """A -> B -> A is three changes; the old A directory was deleted, so A is rewritten."""
    _install(store, pair_a)
    _install(store, pair_b)

    result = _install(store, pair_a)

    assert result.changed is True
    assert result.previous == pair_b.generation
    assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)
    assert [d.name for d in generation_dirs(root / NAME)] == [f"..{pair_a.generation}"]


# --- identical content -----------------------------------------------------------------


def test_an_identical_install_is_a_no_op(
    store: MaterialStore, root: Path, pair_a: Pair, probe: FsProbe
) -> None:
    """No new generation, no swap, no deletion; the result says nothing changed."""
    first = _install(store, pair_a)
    name_dir = root / NAME
    generation_dir = name_dir / f"..{pair_a.generation}"
    before = (
        os.lstat(name_dir / "..data").st_ino,
        os.lstat(name_dir / "..data").st_mtime_ns,
        generation_dir.stat().st_ino,
        generation_dir.stat().st_mtime_ns,
        (generation_dir / "privkey.pem").stat().st_mtime_ns,
    )
    succeeded: list[str] = []
    probe.after(lambda call: succeeded.append(call.name))
    probe.start()

    second = _install(store, pair_a)

    mutating = {"replace", "rename", "symlink", *DELETION_CALLS}
    assert [name for name in succeeded if name in mutating] == []
    assert second.changed is False
    assert second.generation == first.generation
    assert second.previous is None
    after = (
        os.lstat(name_dir / "..data").st_ino,
        os.lstat(name_dir / "..data").st_mtime_ns,
        generation_dir.stat().st_ino,
        generation_dir.stat().st_mtime_ns,
        (generation_dir / "privkey.pem").stat().st_mtime_ns,
    )
    assert after == before


def test_an_identical_install_restores_stable_links_that_went_missing(
    store: MaterialStore, root: Path, pair_a: Pair
) -> None:
    """A removed stable link is recreated without a new generation (the leaf-vanished path)."""
    _install(store, pair_a)
    name_dir = root / NAME
    (name_dir / "fullchain.pem").unlink()
    (name_dir / "privkey.pem").unlink()

    result = _install(store, pair_a)

    assert result.changed is False
    assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)
    assert os.readlink(name_dir / "fullchain.pem") == "..data/fullchain.pem"
    assert os.readlink(name_dir / "privkey.pem") == "..data/privkey.pem"
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{pair_a.generation}"]


def test_a_changed_install_restores_a_stable_link_that_went_missing(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """The reconciler's 'leaf file vanished' case: new content also repairs the links."""
    _install(store, pair_a)
    (root / NAME / "fullchain.pem").unlink()

    _install(store, pair_b)

    assert _served(store) == (pair_b.cert_pem, pair_b.key_pem)


# --- crash safety ----------------------------------------------------------------------

PRE_SWAP_STEPS = ["during_generation_write", "after_generation_files", "after_temp_link"]
POST_SWAP_STEPS = ["after_swap_before_delete"]


def _arm_crash(
    probe: FsProbe, step: str, name_dir: Path, previous_generation: Path
) -> list[FsCall]:
    """Register a hook that raises SimulatedCrash at `step`; returns the list it fills."""
    fired: list[FsCall] = []

    def hook(call: FsCall) -> None:
        if fired:
            return
        hit = (
            (step == "during_generation_write" and call.name == "fsync")
            or (step == "after_generation_files" and call.name == "symlink")
            or (
                step == "after_temp_link"
                and call.name == "replace"
                and _dst_name(call) == "..data"
            )
            or (
                step == "after_swap_before_delete"
                and call.name in DELETION_CALLS
                and is_inside(call.path_arg(0), previous_generation)
            )
        )
        if hit:
            fired.append(call)
            raise SimulatedCrash(step)

    probe.before(hook)
    return fired


@pytest.mark.parametrize("step", PRE_SWAP_STEPS + POST_SWAP_STEPS)
def test_a_crash_at_each_step_leaves_a_readable_matching_pair(
    store: MaterialStore,
    root: Path,
    pair_a: Pair,
    pair_b: Pair,
    pair_c: Pair,
    probe: FsProbe,
    step: str,
) -> None:
    """Whatever step dies, the stable paths read one whole generation (old before the swap,
    new after it), cert and key matching, and the next install converges to one generation.
    """
    _install(store, pair_a)
    name_dir = root / NAME
    fired = _arm_crash(probe, step, name_dir, name_dir / f"..{pair_a.generation}")
    probe.start()

    with pytest.raises(SimulatedCrash):
        _install(store, pair_b)
    probe.stop()

    assert fired, f"the {step} hook point was never reached; the store skips that primitive"
    cert, key = _served(store)
    assert pair_matches(cert, key)
    expected = pair_b if step in POST_SWAP_STEPS else pair_a
    assert (cert, key) == (expected.cert_pem, expected.key_pem)

    _install(store, pair_c)

    assert _served(store) == (pair_c.cert_pem, pair_c.key_pem)
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{pair_c.generation}"]
    assert stray_temporaries(name_dir) == []


@pytest.mark.parametrize("step", PRE_SWAP_STEPS)
def test_retrying_an_install_interrupted_before_the_swap_completes_it(
    store: MaterialStore,
    root: Path,
    pair_a: Pair,
    pair_b: Pair,
    probe: FsProbe,
    step: str,
) -> None:
    """The leftover partial generation for the same content does not block the retry."""
    _install(store, pair_a)
    name_dir = root / NAME
    _arm_crash(probe, step, name_dir, name_dir / f"..{pair_a.generation}")
    probe.start()
    with pytest.raises(SimulatedCrash):
        _install(store, pair_b)
    probe.stop()

    result = _install(store, pair_b)

    assert result.changed is True
    assert result.generation == pair_b.generation
    assert _served(store) == (pair_b.cert_pem, pair_b.key_pem)
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{pair_b.generation}"]


def test_retrying_an_install_that_died_before_deleting_the_previous_removes_the_orphan(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, probe: FsProbe
) -> None:
    """The swap already happened, so the retry is identical content: no swap, but the orphan
    left by the crash is deleted (that unlink is what makes the gateway reload).
    """
    _install(store, pair_a)
    name_dir = root / NAME
    previous = name_dir / f"..{pair_a.generation}"
    _arm_crash(probe, "after_swap_before_delete", name_dir, previous)
    probe.start()
    with pytest.raises(SimulatedCrash):
        _install(store, pair_b)
    probe.stop()
    assert previous.exists()

    result = _install(store, pair_b)

    assert result.changed is False
    assert not previous.exists()
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{pair_b.generation}"]
    assert _served(store) == (pair_b.cert_pem, pair_b.key_pem)


@pytest.mark.parametrize("step", PRE_SWAP_STEPS + POST_SWAP_STEPS)
def test_gc_after_a_crash_leaves_only_the_current_generation(
    store: MaterialStore,
    root: Path,
    pair_a: Pair,
    pair_b: Pair,
    probe: FsProbe,
    step: str,
) -> None:
    """gc removes whatever the crash orphaned and never the generation ..data points at."""
    _install(store, pair_a)
    name_dir = root / NAME
    _arm_crash(probe, step, name_dir, name_dir / f"..{pair_a.generation}")
    probe.start()
    with pytest.raises(SimulatedCrash):
        _install(store, pair_b)
    probe.stop()
    current = pair_b if step in POST_SWAP_STEPS else pair_a

    store.gc(NAME)

    assert [d.name for d in generation_dirs(name_dir)] == [f"..{current.generation}"]
    assert _served(store) == (current.cert_pem, current.key_pem)


# --- no mixed pair is ever observable ---------------------------------------------------


def test_a_reader_sampling_at_every_filesystem_step_never_sees_a_mixed_pair(
    store: MaterialStore, pair_a: Pair, pair_b: Pair, probe: FsProbe
) -> None:
    """Read cert and key through the stable paths before and after every filesystem call an
    install makes: each sample is wholly the old pair or wholly the new one.

    A free-running reader can legitimately straddle a swap between its two opens (the
    gateway tolerates that), so the check is made at the store's own step
    boundaries rather than from a racing thread.
    """
    _install(store, pair_a)
    allowed = {(pair_a.cert_pem, pair_a.key_pem), (pair_b.cert_pem, pair_b.key_pem)}
    samples: list[tuple[bytes, bytes]] = []

    def sample(call: FsCall) -> None:
        served = _served(store)
        samples.append(served)
        if served not in allowed or not pair_matches(*served):
            pytest.fail(f"mixed or unknown pair visible around os.{call.name}")

    probe.before(sample)
    probe.after(sample)
    probe.start()
    _install(store, pair_b)

    assert len(samples) >= 8
    assert samples[0] == (pair_a.cert_pem, pair_a.key_pem)
    assert samples[-1] == (pair_b.cert_pem, pair_b.key_pem)


def test_during_the_first_install_the_pair_is_absent_or_whole_never_partial(
    store: MaterialStore, pair_a: Pair, probe: FsProbe
) -> None:
    """With nothing installed yet a reader sees no file, or the complete matching pair."""
    cert_path, key_path = store.stable_paths(NAME)
    states: list[str] = []

    def sample(call: FsCall) -> None:
        cert_ok, key_ok = cert_path.is_file(), key_path.is_file()
        if cert_ok != key_ok:
            pytest.fail(f"only one of cert/key readable around os.{call.name}")
        if cert_ok:
            served = read_pair(cert_path, key_path)
            if served != (pair_a.cert_pem, pair_a.key_pem):
                pytest.fail(f"partial or foreign pair visible around os.{call.name}")
        states.append("whole" if cert_ok else "absent")

    probe.before(sample)
    probe.after(sample)
    probe.start()
    _install(store, pair_a)

    assert states[-1] == "whole"


# --- stale temporaries and orphans ------------------------------------------------------


@pytest.mark.parametrize("identical", [False, True])
def test_stale_temporaries_from_a_crash_are_cleaned_on_the_next_install(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, identical: bool
) -> None:
    """Leftover ..data.tmp* links and unreferenced partial generations go on every install."""
    _install(store, pair_a)
    name_dir = root / NAME
    os.symlink(f"..{pair_a.generation}", name_dir / "..data.tmp-stale1")
    os.symlink("..000000000000", name_dir / "..data.tmpdangling")
    partial = name_dir / "..aaaaaaaaaaaa"
    partial.mkdir()
    (partial / "privkey.pem").write_bytes(b"half-written")

    survivor = pair_a if identical else pair_b
    result = _install(store, survivor)

    assert result.changed is (not identical)
    assert stray_temporaries(name_dir) == []
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{survivor.generation}"]
    assert _served(store) == (survivor.cert_pem, survivor.key_pem)


def test_cleanup_removes_planted_symlinks_without_following_them(
    store: MaterialStore, root: Path, tmp_path: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """A symlink planted where a temporary or generation would be is unlinked, not followed."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "sentinel").write_bytes(b"keep me")
    (victim / "fullchain.pem").write_bytes(b"keep me too")
    _install(store, pair_a)
    name_dir = root / NAME
    os.symlink(victim, name_dir / "..data.tmpevil")
    os.symlink(victim, name_dir / "..bbbbbbbbbbbb")

    _install(store, pair_b)

    assert sorted(p.name for p in victim.iterdir()) == ["fullchain.pem", "sentinel"]
    assert (victim / "sentinel").read_bytes() == b"keep me"
    assert (victim / "fullchain.pem").read_bytes() == b"keep me too"
    assert not os.path.lexists(name_dir / "..data.tmpevil")
    assert not os.path.lexists(name_dir / "..bbbbbbbbbbbb")


def test_gc_removes_orphan_generations_and_never_the_current_one(
    store: MaterialStore, root: Path, pair_a: Pair
) -> None:
    """Orphans are generation directories ..data does not point at; the return lists them."""
    _install(store, pair_a)
    name_dir = root / NAME
    for orphan_id in ("0123456789ab", "fedcba987654"):
        orphan = name_dir / f"..{orphan_id}"
        orphan.mkdir()
        (orphan / "fullchain.pem").write_bytes(b"old cert")
        (orphan / "privkey.pem").write_bytes(b"old key")

    removed = store.gc(NAME)

    assert sorted(removed) == ["0123456789ab", "fedcba987654"]
    assert [d.name for d in generation_dirs(name_dir)] == [f"..{pair_a.generation}"]
    assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)
    assert store.gc(NAME) == []


def test_gc_with_no_current_generation_removes_every_partial_generation(
    store: MaterialStore, root: Path
) -> None:
    """A first install that died before the swap leaves only orphans; none is current."""
    name_dir = root / NAME
    name_dir.mkdir(parents=True)
    partial = name_dir / "..0123456789ab"
    partial.mkdir()
    (partial / "privkey.pem").write_bytes(b"half")

    removed = store.gc(NAME)

    assert removed == ["0123456789ab"]
    assert generation_dirs(name_dir) == []


def test_gc_leaves_the_links_and_unrelated_entries_alone(
    store: MaterialStore, root: Path, pair_a: Pair
) -> None:
    """Only generation directories are collected: links and foreign files survive."""
    _install(store, pair_a)
    name_dir = root / NAME
    (name_dir / "notes.txt").write_text("operator note", encoding="utf-8")
    (name_dir / "..not-a-generation").mkdir()

    store.gc(NAME)

    assert (name_dir / "notes.txt").read_text(encoding="utf-8") == "operator note"
    assert (name_dir / "..not-a-generation").is_dir()
    assert os.readlink(name_dir / "..data") == f"..{pair_a.generation}"
    assert os.readlink(name_dir / "fullchain.pem") == "..data/fullchain.pem"


def test_gc_of_an_unknown_name_is_empty_and_creates_nothing(
    store: MaterialStore, root: Path
) -> None:
    """Nothing installed under that name: no error, no directory."""
    assert store.gc("never-installed") == []
    assert not (root / "never-installed").exists()


def test_gc_without_a_name_sweeps_store_directories_and_spares_everything_else(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair
) -> None:
    """With the PKI directory as root, gc() must not touch staged/, archive/ or CA files."""
    _install(store, pair_a, "alpha")
    _install(store, pair_b, "beta")
    for name in ("alpha", "beta"):
        orphan = root / name / "..0123456789ab"
        orphan.mkdir()
        (orphan / "privkey.pem").write_bytes(b"x")
    (root / "staged").mkdir()
    (root / "staged" / "x509-ca.crt").write_bytes(b"staged ca")
    (root / "x509-ca.crt").write_bytes(b"the ca")

    removed = store.gc()

    assert sorted(removed) == ["0123456789ab", "0123456789ab"]
    assert generation_dirs(root / "alpha") == [root / "alpha" / f"..{pair_a.generation}"]
    assert generation_dirs(root / "beta") == [root / "beta" / f"..{pair_b.generation}"]
    assert (root / "staged" / "x509-ca.crt").read_bytes() == b"staged ca"
    assert (root / "x509-ca.crt").read_bytes() == b"the ca"


# --- symlink refusal --------------------------------------------------------------------


def test_a_symlink_planted_at_the_generation_path_is_never_followed(
    store: MaterialStore, root: Path, tmp_path: Path, pair_a: Pair
) -> None:
    """If ..<sha12> is a symlink to a foreign directory, no file is written through it.

    The store may refuse (StoreError / OSError) or replace the link with a real directory;
    it must never create files in the link's target.
    """
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "sentinel").write_bytes(b"keep me")
    name_dir = root / NAME
    name_dir.mkdir(parents=True)
    os.symlink(victim, name_dir / f"..{pair_a.generation}")

    try:
        _install(store, pair_a)
    except (StoreError, OSError):
        pass
    else:
        generation_dir = name_dir / f"..{pair_a.generation}"
        assert generation_dir.is_dir() and not generation_dir.is_symlink()
        assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)

    assert [p.name for p in victim.iterdir()] == ["sentinel"]
    assert (victim / "sentinel").read_bytes() == b"keep me"


def test_a_symlinked_key_file_inside_a_stale_generation_is_never_written_through(
    store: MaterialStore, root: Path, tmp_path: Path, pair_a: Pair
) -> None:
    """A partial generation holding privkey.pem -> victim file leaves the victim untouched."""
    victim_file = tmp_path / "victim-key"
    victim_file.write_bytes(b"do not overwrite")
    stale = root / NAME / f"..{pair_a.generation}"
    stale.mkdir(parents=True)
    os.symlink(victim_file, stale / "privkey.pem")

    try:
        _install(store, pair_a)
    except (StoreError, OSError):
        pass
    else:
        assert not (root / NAME / f"..{pair_a.generation}" / "privkey.pem").is_symlink()
        assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)

    assert victim_file.read_bytes() == b"do not overwrite"


# --- serialisation ----------------------------------------------------------------------


def test_concurrent_installs_are_serialised(
    store: MaterialStore,
    root: Path,
    pair_a: Pair,
    pair_b: Pair,
    pair_c: Pair,
    probe: FsProbe,
) -> None:
    """While one install is paused mid-swap, a second install does not start its own swap."""
    _install(store, pair_a)
    first_in_swap = threading.Event()
    release = threading.Event()
    second_in_swap = threading.Event()
    first_thread: list[str] = []
    errors: list[BaseException] = []

    def hook(call: FsCall) -> None:
        if call.name != "symlink":
            return
        me = threading.current_thread().name
        if not first_thread:
            first_thread.append(me)
        if me == first_thread[0]:
            first_in_swap.set()
            if not release.wait(10):
                raise RuntimeError("test timed out waiting to release the first install")
        else:
            second_in_swap.set()

    def run(pair: Pair) -> None:
        try:
            _install(store, pair)
        except BaseException as exc:
            errors.append(exc)

    probe.before(hook)
    probe.start()
    one = threading.Thread(target=run, args=(pair_b,), name="installer-one")
    two = threading.Thread(target=run, args=(pair_c,), name="installer-two")
    one.start()
    assert first_in_swap.wait(10)
    two.start()

    interleaved = second_in_swap.wait(0.5)
    release.set()
    one.join(10)
    two.join(10)
    probe.stop()

    assert not interleaved, "a second install entered its swap while the first was mid-install"
    assert errors == []
    assert not one.is_alive() and not two.is_alive()
    assert _served(store) == (pair_c.cert_pem, pair_c.key_pem)
    assert [d.name for d in generation_dirs(root / NAME)] == [f"..{pair_c.generation}"]


# --- no key material in output ------------------------------------------------------------


def test_a_successful_install_logs_no_key_material(
    store: MaterialStore, pair_a: Pair
) -> None:
    """Log events may name the certificate and generation, never key bytes."""
    with structlog.testing.capture_logs() as logs:
        _install(store, pair_a)

    rendered = repr(logs)
    assert all(line not in rendered for line in pair_a.key_body_lines())
    assert "PRIVATE KEY" not in rendered


def test_a_failed_install_leaks_no_key_material_into_the_error_or_logs(
    store: MaterialStore, pair_a: Pair, pair_b: Pair, probe: FsProbe
) -> None:
    """An OSError during the swap surfaces without key bytes in message, chain or logs."""
    _install(store, pair_a)

    def fail(call: FsCall) -> None:
        if call.name == "replace" and _dst_name(call) == "..data":
            raise OSError(28, "simulated: no space left on device")

    probe.before(fail)
    probe.start()
    with structlog.testing.capture_logs() as logs, pytest.raises((OSError, StoreError)) as caught:
        _install(store, pair_b)
    probe.stop()

    text = "".join(traceback.format_exception(caught.value)) + repr(caught.value) + repr(logs)
    assert all(line not in text for line in pair_b.key_body_lines())
    assert "PRIVATE KEY" not in text
    assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)


# --- a failed delete of the previous generation --------------------------------------


def _refuse_removal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every store-side deletion fail the way a read-only or busy filesystem would."""
    import gwops.certs.store as store_module

    def _refuse(path: Path) -> None:
        raise OSError(13, "simulated: permission denied")

    monkeypatch.setattr(store_module, "_remove_entry", _refuse)


def test_a_clean_install_is_not_reload_pending(
    store: MaterialStore, pair_a: Pair, pair_b: Pair
) -> None:
    """reload_pending is False when the previous generation was deleted (and on a first install)."""
    assert _install(store, pair_a).reload_pending is False
    assert _install(store, pair_b).reload_pending is False


def test_a_failed_delete_of_the_previous_generation_is_reload_pending(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The install still succeeds and serves the new pair, but says the gateway has not reloaded."""
    _install(store, pair_a)
    _refuse_removal(monkeypatch)

    with structlog.testing.capture_logs() as logs:
        result = _install(store, pair_b)

    assert result.changed is True
    assert result.reload_pending is True
    assert result.previous is None
    assert result.generation == pair_b.generation
    assert _served(store) == (pair_b.cert_pem, pair_b.key_pem)
    assert len(generation_dirs(root / NAME)) == 2  # the old generation is still on disk
    assert any(e["event"] == "store.previous_generation_not_deleted" for e in logs)


def test_gc_retries_the_pending_delete_once_removal_works_again(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later gc removes the old generation, which is what finally reloads the gateway."""
    _install(store, pair_a)
    with monkeypatch.context() as patch:
        _refuse_removal(patch)
        assert _install(store, pair_b).reload_pending is True
        with pytest.raises(StoreError):
            store.gc(NAME)  # still failing: reported, not swallowed

    assert store.gc(NAME) == [pair_a.generation]
    assert [d.name for d in generation_dirs(root / NAME)] == [f"..{pair_b.generation}"]


def test_an_identical_install_retries_the_pending_delete(
    store: MaterialStore, root: Path, pair_a: Pair, pair_b: Pair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The next pass's install of the same pair sweeps the old generation: no pending, no churn."""
    _install(store, pair_a)
    with monkeypatch.context() as patch:
        _refuse_removal(patch)
        _install(store, pair_b)
        with pytest.raises(StoreError):
            _install(store, pair_b)  # the sweep that runs first cannot delete either

    result = _install(store, pair_b)

    assert result.changed is False
    assert result.reload_pending is False
    assert [d.name for d in generation_dirs(root / NAME)] == [f"..{pair_b.generation}"]


# --- a damaged current generation ----------------------------------------------------


def test_a_damaged_current_generation_is_replaced_without_the_stable_paths_ever_dangling(
    store: MaterialStore, root: Path, pair_a: Pair, probe: FsProbe
) -> None:
    """Rebuilding builds the new generation first and swaps ..data, as the normal path does."""
    _install(store, pair_a)
    name_dir = root / NAME
    cert_path, key_path = store.stable_paths(NAME)
    (name_dir / f"..{pair_a.generation}" / "fullchain.pem").write_bytes(b"damaged on disk")
    samples: list[tuple[bytes, bytes]] = []

    def sample(call: FsCall) -> None:
        assert os.path.lexists(name_dir / "..data"), f"..data missing around os.{call.name}"
        samples.append(read_pair(cert_path, key_path))

    probe.before(sample)
    probe.after(sample)
    probe.start()
    result = _install(store, pair_a)
    probe.stop()

    assert result.changed is True
    assert result.previous == pair_a.generation
    assert result.reload_pending is False
    assert _served(store) == (pair_a.cert_pem, pair_a.key_pem)
    assert len(samples) >= 8
    assert all(served in ((b"damaged on disk", pair_a.key_pem), (pair_a.cert_pem, pair_a.key_pem))
               for served in samples)
    [remaining] = generation_dirs(name_dir)
    assert remaining.name == f"..{result.generation}"
    assert stray_temporaries(name_dir) == []


def test_a_repaired_generation_is_current_so_the_next_identical_install_changes_nothing(
    store: MaterialStore, root: Path, pair_a: Pair
) -> None:
    """The repair's random id is not rebuilt on the next pass: no second swap, no reload."""
    _install(store, pair_a)
    (root / NAME / f"..{pair_a.generation}" / "privkey.pem").write_bytes(b"damaged on disk")
    repaired = _install(store, pair_a)

    again = _install(store, pair_a)

    assert again.changed is False
    assert again.generation == repaired.generation
    assert [d.name for d in generation_dirs(root / NAME)] == [f"..{repaired.generation}"]
