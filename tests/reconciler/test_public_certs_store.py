"""The public-certificate step against the real ``MaterialStore``.

The reconciler installs through the atomic store, so a reader of the stable paths sees one
whole generation of every certificate at every filesystem step of a pass. The store needs
real symlinks, which the Windows dev machine cannot create: this module skips on
win32 and runs on Linux (a ``python:3.12-slim`` container).

The tests drive ``Reconciler._materialize_public_tls`` (the synchronous certificate step) so
that the filesystem probe sees only the step's own calls.
"""

import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gwops.configmodel.loader import load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.reconciler import core
from gwops.reconciler.core import ReconcileResult
from tests.store_support import (
    FsCall,
    FsProbe,
    generation_dirs,
    generation_id,
    pair_matches,
    read_pair,
    stray_temporaries,
)

from .public_certs_support import ROOT, PublicEnv, host, issue

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating symlinks needs elevation on Windows (WinError 1314); runs on Linux",
)

TWO = {"alpha": [host("alpha")], "beta": [host("beta")]}


@pytest.fixture(autouse=True)
def _pin_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "resolve_registered_root", lambda name: ROOT)


@pytest.fixture
def pub(tmp_path: Path, gateway_binary: Callable[..., Path]) -> PublicEnv:
    env = PublicEnv(tmp_path, gateway_binary(), TWO)
    env.write_all()
    return env


def _load(pub: PublicEnv) -> EffectiveState:
    state, _provenance = load_effective_state(pub.env.seed_path, pub.env.store)
    return state


def _step(pub: PublicEnv, state: EffectiveState | None = None) -> tuple[bool, ReconcileResult]:
    """Run the certificate step on its own, as the first half of a reconcile pass."""
    state = state if state is not None else _load(pub)
    result = ReconcileResult(ok=True, trigger="test", started_at=datetime.now(UTC))
    return pub.env.reconciler._materialize_public_tls(state, result), result


def test_the_reconciler_installs_through_the_real_atomic_store(pub: PublicEnv) -> None:
    ok, result = _step(pub)

    assert ok is True and result.errors == []
    for name in TWO:
        cert_file, key_file = pub.env.paths.public_cert_files(name)
        assert cert_file.is_symlink() and key_file.is_symlink()  # stable links via ..data
        issued = pub.written[name]
        assert read_pair(cert_file, key_file) == (issued.cert_pem, issued.key_pem)
        [generation] = generation_dirs(cert_file.parent)
        assert generation.name == ".." + generation_id(issued.cert_pem, issued.key_pem)


def test_a_reader_never_sees_a_mixed_pair_at_any_step_of_a_renewal(pub: PublicEnv) -> None:
    """Sampled before and after every filesystem call of a pass that replaces both pairs."""
    ok, _result = _step(pub)
    assert ok
    old = {name: pub.served(name) for name in TWO}
    probe = FsProbe()
    samples: list[tuple[str, tuple[bytes, bytes]]] = []
    new: dict[str, tuple[bytes, bytes]] = {}
    for name in TWO:  # renew the certificate and the key together
        renewed = pub.write(name, issue(name, new_key=True))
        new[name] = (renewed.cert_pem, renewed.key_pem)

    def sample(call: FsCall) -> None:
        for name in TWO:
            served = pub.served(name)
            samples.append((name, served))
            if not pair_matches(*served):
                pytest.fail(f"cert and key of {name!r} from different generations at {call.name}")

    state = _load(pub)
    probe.before(sample)
    probe.after(sample)
    probe.start()
    try:
        ok, result = _step(pub, state)
    finally:
        probe.stop()

    assert ok is True and result.errors == []
    assert len(samples) >= 16
    assert all(served in (old[name], new[name]) for name, served in samples)
    assert {name: pub.served(name) for name in TWO} == new
    assert any(served == new[name] for name, served in samples)  # the swap was observed


def test_a_failed_pass_changes_nothing_on_disk_at_all(pub: PublicEnv) -> None:
    """One invalid certificate: no generation is written, swapped or deleted for any."""
    ok, _result = _step(pub)
    assert ok
    before = {name: pub.served(name) for name in TWO}
    pub.write("alpha", issue("alpha", new_key=True))  # a valid renewal held back
    pub.source_root.joinpath("beta", "privkey.pem").write_bytes(b"not a key\n")
    probe = FsProbe()
    state = _load(pub)
    probe.start()
    try:
        ok, result = _step(pub, state)
    finally:
        probe.stop()

    assert ok is False
    assert [e for e in result.errors if e.startswith("public certificate 'beta':")]
    assert probe.named("mkdir", "symlink", "replace", "rename", "unlink", "remove", "rmdir") == []
    assert {name: pub.served(name) for name in TWO} == before
    for name in TWO:
        assert len(generation_dirs(pub.env.paths.public_cert_files(name)[0].parent)) == 1


def test_an_unchanged_pass_writes_and_deletes_nothing(pub: PublicEnv) -> None:
    ok, _result = _step(pub)
    assert ok
    probe = FsProbe()
    state = _load(pub)
    probe.start()
    try:
        ok, result = _step(pub, state)
    finally:
        probe.stop()

    assert ok is True
    assert [a for a in result.actions if a.startswith("installed public certificate")] == []
    assert probe.named("mkdir", "symlink", "replace", "rename", "unlink", "remove", "rmdir") == []


def test_the_previous_generation_is_deleted_and_no_temporaries_remain(pub: PublicEnv) -> None:
    ok, _result = _step(pub)
    assert ok
    old_dirs = {
        name: [g.name for g in generation_dirs(pub.env.paths.public_cert_files(name)[0].parent)]
        for name in TWO
    }
    pub.write("alpha", issue("alpha", new_key=True))

    ok, result = _step(pub)

    assert ok is True
    alpha_dir = pub.env.paths.public_cert_files("alpha")[0].parent
    [alpha_generation] = generation_dirs(alpha_dir)
    assert alpha_generation.name not in old_dirs["alpha"]  # the previous one is gone
    assert stray_temporaries(alpha_dir) == []
    assert len(generation_dirs(pub.env.paths.public_cert_files("beta")[0].parent)) == 1
    assert len([a for a in result.actions if a.startswith("installed public certificate")]) == 1


def test_a_failed_delete_of_the_previous_generation_is_a_local_error_and_is_retried(
    pub: PublicEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gateway reloads only when the old generation is unlinked, so a failed delete is
    an error naming the certificate, the status keeps the generation still served, and the next
    pass's install sweeps the old generation."""
    import gwops.certs.store as store_module

    ok, first = _step(pub)
    assert ok is True
    [first_alpha] = [s for s in first.public_certs or [] if s.name == "alpha"]
    pub.write("alpha")  # a renewal

    def _refuse(path: Path) -> None:
        raise OSError(13, "simulated: permission denied")

    with monkeypatch.context() as patch:
        patch.setattr(store_module, "_remove_entry", _refuse)
        ok, result = _step(pub)

    assert ok is False
    assert result.errors == [
        "public certificate 'alpha': installed but previous generation not removed; "
        "gateway has not reloaded"
    ]
    [action] = [a for a in result.actions if a.startswith("installed public certificate 'alpha'")]
    assert "(gateway hot-reloads)" not in action
    assert action.endswith("(previous generation not removed; gateway has not reloaded)")
    [alpha] = [s for s in result.public_certs or [] if s.name == "alpha"]
    assert alpha.state == "invalid"
    assert alpha.generation == first_alpha.generation  # what the gateway still serves
    assert len(generation_dirs(pub.env.paths.public_cert_files("alpha")[0].parent)) == 2

    ok, retry = _step(pub)

    assert ok is True and retry.errors == []
    [alpha] = [s for s in retry.public_certs or [] if s.name == "alpha"]
    assert alpha.state == "ok"
    written = pub.written["alpha"]
    assert alpha.generation == generation_id(written.cert_pem, written.key_pem)
    assert len(generation_dirs(pub.env.paths.public_cert_files("alpha")[0].parent)) == 1
