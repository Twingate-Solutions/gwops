"""Tests for gwops.certs.public reads: ``read_public_material`` and
``read_installed_public_material``.

``read_public_material`` reads a ``source: file`` certificate's files through ``gwops.confined``
rooted at the public-tls source root (rule 6). ``read_installed_public_material`` judges what
the public store holds for a ``source: acme`` certificate: one generation from
``MaterialStore.read_current``, validated against the registered root. Read failures are a
``PublicMaterialError`` naming the certificate and the file, never contents. The validation
itself is covered by ``test_public.py``.
"""

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from gwops.certs.public import (
    PublicCertState,
    PublicMaterial,
    PublicMaterialError,
    read_installed_public_material,
    read_public_material,
)
from gwops.certs.store import MaterialStore, StoreError
from gwops.configmodel.schema import AcmePublicCertificate, FilePublicCertificate
from gwops.confined import MAX_FILE_BYTES
from tests.public_chain_support import (
    NOW,
    ZONES,
    fingerprint,
    key_pem_of,
    other_hierarchy,
    pem_bodies,
    rsa_hierarchy,
)
from tests.public_tls_support import ZONE, public_cert

NAME = "wildcard"


@pytest.fixture
def source_root(tmp_path: Path) -> Path:
    root = tmp_path / "public-tls"
    (root / NAME).mkdir(parents=True)
    return root


@pytest.fixture
def issued():  # type: ignore[no-untyped-def]
    return rsa_hierarchy().issue()


def _entry(cert_file: Path, key_file: Path) -> FilePublicCertificate:
    return FilePublicCertificate.model_validate(
        public_cert(NAME, cert_file=str(cert_file), key_file=str(key_file))
    )


def _read(entry: FilePublicCertificate, root: Path):  # type: ignore[no-untyped-def]
    return read_public_material(
        entry, root, zones=ZONES, root=rsa_hierarchy().root, now=NOW
    )


def _install_files(root: Path, issued) -> tuple[Path, Path]:  # type: ignore[no-untyped-def]
    cert_file = root / NAME / "fullchain.pem"
    key_file = root / NAME / "privkey.pem"
    cert_file.write_bytes(issued.cert_pem)
    key_file.write_bytes(issued.key_pem)
    return cert_file, key_file


class TestReadAndValidate:
    def test_valid_files_are_returned_as_read_with_their_validation(
        self, source_root: Path, issued
    ) -> None:
        cert_file, key_file = _install_files(source_root, issued)

        cert_pem, key_pem, material = _read(_entry(cert_file, key_file), source_root)

        assert cert_pem == issued.cert_pem
        assert key_pem == issued.key_pem
        assert material.state is PublicCertState.OK
        assert material.chain[0] == issued.cert

    def test_a_validation_failure_surfaces_as_the_materials_own_error(
        self, source_root: Path, issued
    ) -> None:
        cert_file, key_file = _install_files(source_root, issued)
        key_file.write_bytes(key_pem_of(other_hierarchy().leaf_key))

        with pytest.raises(PublicMaterialError) as caught:
            _read(_entry(cert_file, key_file), source_root)

        assert caught.value.check == "key_mismatch"
        assert caught.value.certificate == NAME


class TestConfinedReadRefusals:
    def test_a_cert_file_outside_the_root_is_refused_naming_certificate_and_file(
        self, tmp_path: Path, source_root: Path, issued
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "fullchain.pem").write_bytes(issued.cert_pem)
        (outside / "privkey.pem").write_bytes(issued.key_pem)
        entry = _entry(outside / "fullchain.pem", outside / "privkey.pem")

        with pytest.raises(PublicMaterialError) as caught:
            _read(entry, source_root)

        message = str(caught.value)
        assert caught.value.check == "cert_unreadable"
        assert caught.value.file == "cert_file"
        assert repr(NAME) in message and "cert_file" in message
        assert "resolves outside the allowed root" in message

    def test_a_key_file_outside_the_root_is_refused_naming_the_key_file(
        self, tmp_path: Path, source_root: Path, issued
    ) -> None:
        cert_file, _key_file = _install_files(source_root, issued)
        stray_key = tmp_path / "stray.key"
        stray_key.write_bytes(issued.key_pem)

        with pytest.raises(PublicMaterialError) as caught:
            _read(_entry(cert_file, stray_key), source_root)

        assert caught.value.check == "key_unreadable"
        assert caught.value.file == "key_file"
        assert "key_file" in str(caught.value)
        assert "resolves outside the allowed root" in str(caught.value)

    def test_dot_dot_traversal_out_of_the_root_is_refused(
        self, tmp_path: Path, source_root: Path, issued
    ) -> None:
        cert_file, key_file = _install_files(source_root, issued)
        (tmp_path / "escape.pem").write_bytes(issued.cert_pem)
        traversal = source_root / NAME / ".." / ".." / "escape.pem"

        with pytest.raises(PublicMaterialError, match="resolves outside the allowed root"):
            _read(_entry(traversal, key_file), source_root)

        assert cert_file.exists()

    def test_a_symlink_escaping_the_root_is_refused(
        self, tmp_path: Path, source_root: Path, issued
    ) -> None:
        target = tmp_path / "elsewhere.pem"
        target.write_bytes(issued.cert_pem)
        link = source_root / NAME / "fullchain.pem"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            pytest.skip("this host cannot create symlinks (WinError 1314 without elevation)")
        key_file = source_root / NAME / "privkey.pem"
        key_file.write_bytes(issued.key_pem)

        with pytest.raises(PublicMaterialError) as caught:
            _read(_entry(link, key_file), source_root)

        assert caught.value.check == "cert_unreadable"
        assert "resolves outside the allowed root" in str(caught.value)

    @pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
    def test_a_symlink_that_stays_inside_the_root_is_followed(
        self, source_root: Path, issued
    ) -> None:
        real_dir = source_root / "real"
        real_dir.mkdir()
        (real_dir / "fullchain.pem").write_bytes(issued.cert_pem)
        (real_dir / "privkey.pem").write_bytes(issued.key_pem)
        os.symlink(real_dir / "fullchain.pem", source_root / NAME / "fullchain.pem")
        os.symlink(real_dir / "privkey.pem", source_root / NAME / "privkey.pem")
        entry = _entry(source_root / NAME / "fullchain.pem", source_root / NAME / "privkey.pem")

        cert_pem, _key_pem, _material = _read(entry, source_root)

        assert cert_pem == issued.cert_pem

    def test_a_missing_file_is_refused(self, source_root: Path, issued) -> None:
        _cert_file, key_file = _install_files(source_root, issued)
        missing = source_root / NAME / "absent.pem"

        with pytest.raises(PublicMaterialError, match="file not found") as caught:
            _read(_entry(missing, key_file), source_root)

        assert caught.value.file == "cert_file"

    def test_a_directory_is_not_a_regular_file(self, source_root: Path, issued) -> None:
        _cert_file, key_file = _install_files(source_root, issued)
        directory = source_root / NAME / "a-directory"
        directory.mkdir()

        with pytest.raises(PublicMaterialError, match="not a regular file") as caught:
            _read(_entry(directory, key_file), source_root)

        assert caught.value.check == "cert_unreadable"

    def test_a_directory_as_key_file_names_the_key_file(self, source_root: Path, issued) -> None:
        cert_file, _key_file = _install_files(source_root, issued)
        directory = source_root / NAME / "key-directory"
        directory.mkdir()

        with pytest.raises(PublicMaterialError, match="not a regular file") as caught:
            _read(_entry(cert_file, directory), source_root)

        assert caught.value.check == "key_unreadable"
        assert "key_file" in str(caught.value)

    def test_an_oversized_file_is_refused(self, source_root: Path, issued) -> None:
        _cert_file, key_file = _install_files(source_root, issued)
        big = source_root / NAME / "big.pem"
        big.write_bytes(b"x" * (MAX_FILE_BYTES + 1))

        with pytest.raises(PublicMaterialError, match="size limit"):
            _read(_entry(big, key_file), source_root)

    def test_a_path_with_an_embedded_nul_is_refused(self, source_root: Path, issued) -> None:
        _cert_file, key_file = _install_files(source_root, issued)
        bad = f"{source_root / NAME}/full\x00chain.pem"
        entry = FilePublicCertificate.model_validate(
            public_cert(NAME, cert_file=bad, key_file=str(key_file))
        )

        with pytest.raises(PublicMaterialError) as caught:
            _read(entry, source_root)

        assert caught.value.check == "cert_unreadable"


class TestNoContentsInMessages:
    def test_a_refusal_never_carries_file_contents(
        self, tmp_path: Path, source_root: Path, issued
    ) -> None:
        cert_file, _key_file = _install_files(source_root, issued)
        stray_key = tmp_path / "stray.key"
        stray_key.write_bytes(issued.key_pem)

        with pytest.raises(PublicMaterialError) as caught:
            _read(_entry(cert_file, stray_key), source_root)

        message = str(caught.value)
        for body in pem_bodies(issued.cert_pem, issued.key_pem):
            assert body not in message
        assert "BEGIN" not in message and "PRIVATE KEY" not in message

    def test_a_validation_refusal_never_carries_file_contents(
        self, source_root: Path, issued
    ) -> None:
        cert_file, key_file = _install_files(source_root, issued)
        other_key = key_pem_of(other_hierarchy().leaf_key)
        key_file.write_bytes(other_key)

        with pytest.raises(PublicMaterialError) as caught:
            _read(_entry(cert_file, key_file), source_root)

        message = str(caught.value)
        for body in pem_bodies(issued.cert_pem, issued.key_pem, other_key):
            assert body not in message


# --- read_installed_public_material (source: acme) -----------------------------------------

ACME_NAME = "issued"
GENERATION = "0123456789ab"


def _acme_entry() -> AcmePublicCertificate:
    return AcmePublicCertificate.model_validate(
        {"name": ACME_NAME, "names": [f"*.{ZONE}"], "source": "acme"}
    )


class _ScriptedStore:
    """A store whose ``read_current`` returns or raises what the test sets (works on win32)."""

    def __init__(self, outcome: object) -> None:
        self.outcome = outcome
        self.asked: list[str] = []

    def read_current(self, name: str) -> tuple[bytes, bytes, str] | None:
        self.asked.append(name)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome  # type: ignore[return-value]


def _read_installed(store: Any, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {"zones": ZONES, "root": rsa_hierarchy().root, "now": NOW}
    kwargs.update(overrides)
    return read_installed_public_material(_acme_entry(), store, **kwargs)


class TestReadInstalledFromTheStore:
    def test_a_valid_pair_is_returned_with_its_validation_and_generation(self, issued) -> None:  # type: ignore[no-untyped-def]
        store = _ScriptedStore((issued.cert_pem, issued.key_pem, GENERATION))

        result = _read_installed(store)

        assert result is not None
        cert_pem, key_pem, material, generation = result
        assert (cert_pem, key_pem, generation) == (issued.cert_pem, issued.key_pem, GENERATION)
        assert isinstance(material, PublicMaterial)
        assert material.state is PublicCertState.OK
        assert material.chain[0] == issued.cert
        assert store.asked == [ACME_NAME]

    def test_nothing_installed_is_none_not_an_error(self) -> None:
        assert _read_installed(_ScriptedStore(None)) is None

    def test_a_validation_failure_is_the_materials_own_error_naming_the_certificate(
        self, issued  # type: ignore[no-untyped-def]
    ) -> None:
        wrong_key = key_pem_of(other_hierarchy().leaf_key)
        store = _ScriptedStore((issued.cert_pem, wrong_key, GENERATION))

        with pytest.raises(PublicMaterialError) as caught:
            _read_installed(store)

        assert caught.value.check == "key_mismatch"
        assert caught.value.certificate == ACME_NAME

    def test_a_chain_to_another_root_is_refused_like_operator_files(self) -> None:
        foreign = other_hierarchy().issue()
        store = _ScriptedStore((foreign.cert_pem, foreign.key_pem, GENERATION))

        with pytest.raises(PublicMaterialError) as caught:
            _read_installed(store)

        assert caught.value.check == "chain"

    def test_a_missing_root_is_a_type_error_never_a_skipped_chain_check(self, issued) -> None:  # type: ignore[no-untyped-def]
        store = _ScriptedStore((issued.cert_pem, issued.key_pem, GENERATION))

        with pytest.raises(TypeError, match="registered root"):
            _read_installed(store, root=None)


class TestReadInstalledStoreFailures:
    @pytest.mark.parametrize(
        "failure",
        [
            pytest.param(
                PermissionError(13, "Permission denied", "/data/public-tls/x"), id="permission"
            ),
            pytest.param(OSError(5, "Input/output error"), id="io"),
            pytest.param(StoreError(f"generation '{GENERATION}' is missing its files"), id="store"),
        ],
    )
    def test_an_unreadable_store_is_cert_unreadable_with_the_error_type_only(
        self, failure: BaseException
    ) -> None:
        with pytest.raises(PublicMaterialError) as caught:
            _read_installed(_ScriptedStore(failure))

        error = caught.value
        assert error.check == "cert_unreadable"
        assert error.file == "cert_file"
        assert error.certificate == ACME_NAME
        assert f"the store cannot be read ({type(failure).__name__})" in str(error)
        assert error.__cause__ is None  # the original text never rides along
        for leaked in ("Permission denied", "/data/public-tls", "Input/output", GENERATION):
            assert leaked not in str(error)

    def test_other_exceptions_are_not_swallowed(self) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            _read_installed(_ScriptedStore(RuntimeError("boom")))

    def test_an_invalid_store_name_is_not_a_material_error(self) -> None:
        with pytest.raises(ValueError, match="invalid store name"):
            _read_installed(_ScriptedStore(ValueError("invalid store name 'x'")))


@pytest.mark.skipif(sys.platform == "win32", reason="the real store needs symlinks")
class TestReadInstalledFromARealStore:
    def test_what_install_wrote_is_what_is_judged_with_the_same_generation(
        self, tmp_path: Path, issued  # type: ignore[no-untyped-def]
    ) -> None:
        store = MaterialStore(tmp_path / "public-tls")
        installed = store.install(ACME_NAME, issued.cert_pem, issued.key_pem)

        result = _read_installed(store)

        assert result is not None
        assert (result[0], result[1], result[3]) == (
            issued.cert_pem,
            issued.key_pem,
            installed.generation,
        )

    def test_an_empty_store_is_none(self, tmp_path: Path) -> None:
        assert _read_installed(MaterialStore(tmp_path / "public-tls")) is None

    def test_a_replaced_pair_is_read_as_the_new_generation(self, tmp_path: Path, issued) -> None:  # type: ignore[no-untyped-def]
        store = MaterialStore(tmp_path / "public-tls")
        store.install(ACME_NAME, issued.cert_pem, issued.key_pem)
        renewed = rsa_hierarchy().issue()
        second = store.install(ACME_NAME, renewed.cert_pem, renewed.key_pem)

        result = _read_installed(store)

        assert result is not None
        assert result[3] == second.generation
        assert result[2].fingerprint == fingerprint(renewed.cert)
        assert result[2].fingerprint != fingerprint(issued.cert)

    def test_a_generation_missing_a_file_is_cert_unreadable(self, tmp_path: Path, issued) -> None:  # type: ignore[no-untyped-def]
        store = MaterialStore(tmp_path / "public-tls")
        store.install(ACME_NAME, issued.cert_pem, issued.key_pem)
        for generation in (tmp_path / "public-tls" / ACME_NAME).glob("..*"):
            if generation.is_dir() and not generation.is_symlink():
                (generation / "privkey.pem").unlink()

        with pytest.raises(PublicMaterialError) as caught:
            _read_installed(store)

        assert caught.value.check == "cert_unreadable"
        assert "StoreError" in str(caught.value)
