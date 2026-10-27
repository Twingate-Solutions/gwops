"""The reconciler's CA-bundle step and the legacy Kubernetes credential cleanup.

TG sync is off (no client): these tests exercise the local steps only.
"""

import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import structlog
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from gwops.reconciler.core import ReconcileResult
from gwops.renderer.capabilities import Capabilities

from .test_core import Env

_SECRET_SUBJECT = "Subject-That-Must-Not-Be-Echoed"


def _cert_pem(
    *, ca: bool = True, days_valid: int = 365, days_ago: int = 1, cn: str = "corp-root"
) -> bytes:
    """A self-signed certificate, valid relative to the real clock."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    start = now - timedelta(days=days_ago)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _seed(root: Path, *bundles: tuple[str, str], web_apps: bool = True) -> str:
    """A seed with one SSH upstream, optionally one web app, and the given CA bundles."""
    doc: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": "g-1"},
        "ssh_upstreams": [{"name": "web-1", "address": "10.0.0.5:22"}],
    }
    if web_apps:
        doc["web_apps"] = [{"name": "grafana", "address": "grafana.corp.internal"}]
    if bundles:
        doc["web_app_proxy"] = {
            "upstream_ca_bundles": [
                {"name": name, "file": (root / file).as_posix()} for name, file in bundles
            ]
        }
    return yaml.safe_dump(doc, sort_keys=False)


def _env(
    tmp_path: Path,
    binary: Path,
    *bundles: tuple[str, str],
    web_apps: bool = True,
) -> Env:
    root = tmp_path / "webapp-cas-src"
    root.mkdir(exist_ok=True)
    return Env(
        tmp_path,
        _seed(root, *bundles, web_apps=web_apps),
        binary,
        Capabilities(gateway_version="2.0.0"),
        None,
    )


def _write(env: Env, file: str, data: bytes) -> Path:
    path = env.paths.webapp_ca_root / file
    path.write_bytes(data)
    return path


def _rendered_bundles(env: Env) -> list[Path]:
    doc = yaml.safe_load(env.config_path.read_text(encoding="utf-8"))
    return [Path(entry["file"]) for entry in doc.get("upstreamTrustedCABundles", [])]


def _copies(env: Env) -> list[str]:
    directory = env.paths.upstream_ca_dir
    return sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []


def _ca_errors(result: ReconcileResult) -> list[str]:
    return [e for e in result.errors if "CA bundle" in e]


class TestMaterializedCopies:
    async def test_a_valid_bundle_is_copied_to_a_content_addressed_path_and_rendered(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        pem = _cert_pem()
        _write(env, "corp.pem", pem)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert _ca_errors(result) == []
        [rendered] = _rendered_bundles(env)
        assert rendered.parent == env.paths.upstream_ca_dir
        assert rendered.name.startswith("corp-") and rendered.suffix == ".pem"
        assert len(rendered.stem) == len("corp-") + 12
        assert rendered.read_bytes() == pem
        assert _copies(env) == [rendered.name]
        assert any(a.startswith("materialized CA bundle") and "corp" in a for a in result.actions)
        doc = yaml.safe_load(env.config_path.read_text(encoding="utf-8"))
        assert doc["webApp"] == {}
        assert doc["upstreamTrustedCABundles"] == [{"file": rendered.as_posix()}]
        if sys.platform != "win32":
            assert stat.S_IMODE(rendered.stat().st_mode) == 0o644

    async def test_an_unchanged_bundle_makes_no_new_copy_and_no_action(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem())
        await env.reconciler.reconcile("startup")
        before = _copies(env)

        result = await env.reconciler.reconcile("tick")

        assert result.local_ok is True
        assert not any("CA bundle" in a for a in result.actions)
        assert _copies(env) == before
        assert env.process.calls == ["start"]

    async def test_changed_content_changes_the_rendered_path_and_drain_restarts(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem(cn="first"))
        await env.reconciler.reconcile("startup")
        [first] = _rendered_bundles(env)
        assert env.process.calls == ["start"]

        _write(env, "corp.pem", _cert_pem(cn="second"))
        result = await env.reconciler.reconcile("tick")

        assert result.local_ok is True
        [second] = _rendered_bundles(env)
        assert second != first
        assert env.process.calls == ["start", "drain_restart"]

    async def test_a_superseded_copy_is_collected_once_no_config_references_it(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem(cn="first"))
        await env.reconciler.reconcile("startup")
        [first] = _rendered_bundles(env)

        _write(env, "corp.pem", _cert_pem(cn="second"))
        result = await env.reconciler.reconcile("tick")

        assert not first.exists()
        assert any("removed unreferenced CA bundle copy" in a and first.name in a
                   for a in result.actions)
        [second] = _rendered_bundles(env)
        assert _copies(env) == [second.name]

    async def test_a_copy_only_the_last_good_config_references_survives_gc(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        from gwops.supervisor.process import last_good_path

        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem(cn="first"))
        await env.reconciler.reconcile("startup")
        [first] = _rendered_bundles(env)
        last_good_path(env.config_path).write_text(
            env.config_path.read_text(encoding="utf-8"), encoding="utf-8"
        )

        _write(env, "corp.pem", _cert_pem(cn="second"))
        await env.reconciler.reconcile("tick")

        assert first.is_file()
        [second] = _rendered_bundles(env)
        assert second.is_file()

    async def test_removing_the_bundle_from_the_seed_collects_its_copy(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem())
        await env.reconciler.reconcile("startup")
        assert _copies(env)

        env.seed_path.write_text(_seed(env.paths.webapp_ca_root), encoding="utf-8")
        result = await env.reconciler.reconcile("seed")

        assert result.local_ok is True
        assert _copies(env) == []
        assert _rendered_bundles(env) == []

    async def test_two_bundles_render_in_seed_order_with_distinct_files(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("lab", "lab.pem"), ("corp", "corp.pem"))
        _write(env, "lab.pem", _cert_pem(cn="lab"))
        _write(env, "corp.pem", _cert_pem(cn="corp"))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        lab, corp = _rendered_bundles(env)
        assert lab.name.startswith("lab-") and corp.name.startswith("corp-")

    async def test_identical_content_under_two_names_gives_two_distinct_files(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("a", "a.pem"), ("b", "b.pem"))
        pem = _cert_pem()
        _write(env, "a.pem", pem)
        _write(env, "b.pem", pem)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        first, second = _rendered_bundles(env)
        assert first != second


class TestRefusals:
    """Every refusal is a local error before render; nothing is copied; the config is kept."""

    async def _good_then(
        self,
        tmp_path: Path,
        binary: Path,
        bad_name: str,
        bad_data: bytes,
    ) -> tuple[Env, ReconcileResult, str, list[str]]:
        env = _env(tmp_path, binary, ("corp", "corp.pem"), ("extra", bad_name))
        _write(env, "corp.pem", _cert_pem())
        # First pass with two valid bundles, then break the second.
        _write(env, bad_name, _cert_pem(cn="extra"))
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")
        before = _copies(env)
        _write(env, bad_name, bad_data)
        result = await env.reconciler.reconcile("tick")
        return env, result, old_config, before

    @pytest.mark.parametrize(
        ("label", "data", "needle"),
        [
            ("private key block", _key_pem(), "private key"),
            ("junk outside blocks", b"# note\n" + _cert_pem(), "outside"),
            ("CA:FALSE", _cert_pem(ca=False), "not a CA"),
            ("expired", _cert_pem(days_valid=2, days_ago=30), "expired"),
            ("not PEM", b"just text", "no CERTIFICATE"),
            ("empty", b"", "no CERTIFICATE"),
        ],
    )
    async def test_an_invalid_bundle_keeps_the_previous_config_and_writes_no_copy(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        label: str,
        data: bytes,
        needle: str,
    ) -> None:
        env, result, old_config, before = await self._good_then(
            tmp_path, gateway_binary(), "extra.pem", data
        )

        assert result.local_ok is False, label
        [error] = _ca_errors(result)
        assert "extra" in error and needle in error
        assert env.config_path.read_text(encoding="utf-8") == old_config
        assert _copies(env) == before
        assert env.process.calls == ["start"]
        assert any("kept previous gateway config" in a for a in result.actions)

    async def test_a_refused_pass_never_collects_garbage(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem())
        await env.reconciler.reconcile("startup")
        stale = env.paths.upstream_ca_dir / "gone-0123456789ab.pem"
        stale.write_text("old", encoding="utf-8")
        _write(env, "corp.pem", b"broken")

        failed = await env.reconciler.reconcile("tick")

        assert failed.local_ok is False
        assert stale.is_file()

    async def test_one_bad_bundle_blocks_every_copy_of_the_pass(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("good", "good.pem"), ("bad", "bad.pem"))
        _write(env, "good.pem", _cert_pem())
        _write(env, "bad.pem", b"nope")

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert _copies(env) == []
        assert not env.config_path.exists()

    async def test_every_failing_bundle_is_reported(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("one", "one.pem"), ("two", "two.pem"))
        _write(env, "one.pem", b"nope")
        _write(env, "two.pem", _key_pem())

        result = await env.reconciler.reconcile("startup")

        errors = _ca_errors(result)
        assert any("one" in e for e in errors) and any("two" in e for e in errors)

    async def test_a_path_outside_the_root_names_the_root(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "../outside.pem"))
        (tmp_path / "outside.pem").write_bytes(_cert_pem())

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        [error] = _ca_errors(result)
        assert "corp" in error and "outside" in error
        assert str(env.paths.webapp_ca_root) in error
        assert _copies(env) == []

    async def test_an_absolute_path_elsewhere_is_refused(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        stray = tmp_path / "stray.pem"
        stray.write_bytes(_cert_pem())
        env = _env(tmp_path, gateway_binary(), ("corp", stray.as_posix()))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any("outside" in e for e in _ca_errors(result))

    async def test_a_symlink_escaping_the_root_is_refused(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "link.pem"))
        target = tmp_path / "elsewhere.pem"
        target.write_bytes(_cert_pem())
        try:
            (env.paths.webapp_ca_root / "link.pem").symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable here: {exc}")

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any("outside" in e for e in _ca_errors(result))
        assert _copies(env) == []

    async def test_an_oversized_bundle_is_refused_without_reading_it_in(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "big.pem"))
        _write(env, "big.pem", b"X" * (1024 * 1024 + 1))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any("size limit" in e for e in _ca_errors(result))
        assert not any("XXXX" in e for e in result.errors)

    async def test_a_missing_file_is_a_local_error_not_a_skip(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "absent.pem"))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any("not found" in e and "corp" in e for e in _ca_errors(result))

    async def test_an_unexpected_exception_is_a_local_error_naming_the_bundle(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from gwops.access import webapp_policy

        def explode(name: str, data: bytes, now: datetime) -> list[str]:
            raise RuntimeError(f"boom {data.decode('ascii', 'replace')}")

        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem(cn=_SECRET_SUBJECT))
        monkeypatch.setattr(webapp_policy, "pem_violations", explode)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        [error] = _ca_errors(result)
        assert "corp" in error and "RuntimeError" in error
        text = " ".join(result.errors + result.actions)
        assert "BEGIN" not in text and "boom" not in text and _SECRET_SUBJECT not in text
        assert _copies(env) == []
        assert not env.config_path.exists()

    async def test_an_unexpected_exception_while_writing_a_copy_is_a_local_error(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from gwops.reconciler import core

        def explode(*_args: Any, **_kwargs: Any) -> Path:
            raise RuntimeError("boom")

        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem())
        monkeypatch.setattr(core, "write_content_addressed", explode)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        [error] = _ca_errors(result)
        assert "corp" in error and "RuntimeError" in error
        assert _copies(env) == []

    async def test_errors_name_the_bundle_and_never_echo_contents(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", _cert_pem(ca=False, cn=_SECRET_SUBJECT) + _key_pem())

        result = await env.reconciler.reconcile("startup")

        text = " ".join(result.errors + result.actions)
        assert "corp" in text
        assert _SECRET_SUBJECT not in text
        assert "BEGIN" not in text and "PRIVATE" not in text.replace("private key block", "")


class TestWithoutWebApps:
    """Upstream reads bundles only when `webApp` is present, so nothing is published."""

    async def test_a_valid_bundle_without_web_apps_writes_no_copy_and_renders_nothing(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"), web_apps=False)
        _write(env, "corp.pem", _cert_pem())

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert _copies(env) == []
        doc = yaml.safe_load(env.config_path.read_text(encoding="utf-8"))
        assert "webApp" not in doc and "upstreamTrustedCABundles" not in doc
        assert not any("CA bundle" in a for a in result.actions)

    async def test_an_invalid_bundle_without_web_apps_still_fails_loud(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"), web_apps=False)
        _write(env, "corp.pem", b"nope")

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert _ca_errors(result)

    async def test_adding_the_first_web_app_publishes_the_bundle_and_restarts(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"), web_apps=False)
        _write(env, "corp.pem", _cert_pem())
        await env.reconciler.reconcile("startup")

        env.seed_path.write_text(
            _seed(env.paths.webapp_ca_root, ("corp", "corp.pem")), encoding="utf-8"
        )
        result = await env.reconciler.reconcile("seed")

        assert result.local_ok is True
        assert len(_rendered_bundles(env)) == 1
        assert env.process.calls == ["start", "drain_restart"]


class TestLegacyKubernetesCredentialCleanup:
    """The previous release wrote `<k8s_creds_dir>/<cluster>/{token,ca.crt}`."""

    @staticmethod
    def _legacy(
        env: Env, cluster: str = "prod", files: tuple[str, ...] = ("token", "ca.crt")
    ) -> Path:
        directory = env.paths.k8s_creds_dir / cluster
        directory.mkdir(parents=True)
        for name in files:
            (directory / name).write_text("legacy-secret", encoding="utf-8")
        return directory

    async def test_legacy_cluster_directories_are_removed_after_a_successful_pass(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        legacy = self._legacy(env)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert not legacy.exists()
        assert any("legacy" in a and legacy.as_posix() in a for a in result.actions)
        assert "legacy-secret" not in " ".join(result.actions + result.errors)

    async def test_a_subset_of_the_two_files_is_removed(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        only_token = self._legacy(env, "a", ("token",))
        empty = self._legacy(env, "b", ())

        await env.reconciler.reconcile("startup")

        assert not only_token.exists() and not empty.exists()

    async def test_each_removal_is_logged(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        self._legacy(env, "prod")
        self._legacy(env, "stage")

        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("startup")

        removed = [e for e in logs if e["event"] == "confined.legacy_dir_removed"]
        assert sorted(Path(e["path"]).name for e in removed) == ["prod", "stage"]
        assert "legacy-secret" not in repr(logs)

    async def test_a_directory_with_anything_unexpected_is_left_and_warned_about(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        odd = self._legacy(env, "odd", ("token", "notes.txt"))
        nested = self._legacy(env, "nested", ("token",))
        (nested / "sub").mkdir()
        clean = self._legacy(env, "clean")

        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("startup")

        assert (odd / "token").is_file() and (odd / "notes.txt").is_file()
        assert (nested / "token").is_file() and (nested / "sub").is_dir()
        assert not clean.exists()
        kept = [e for e in logs if e["event"] == "confined.legacy_dir_kept"]
        assert sorted(Path(e["path"]).name for e in kept) == ["nested", "odd"]
        assert all(e["log_level"] == "warning" for e in kept)

    async def test_a_symlink_among_the_contents_is_never_followed(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        precious = tmp_path / "precious.txt"
        precious.write_text("keep me", encoding="utf-8")
        directory = env.paths.k8s_creds_dir / "prod"
        directory.mkdir(parents=True)
        try:
            (directory / "token").symlink_to(precious)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable here: {exc}")

        await env.reconciler.reconcile("startup")

        assert precious.read_text(encoding="utf-8") == "keep me"
        assert (directory / "token").is_symlink()

    async def test_a_symlinked_directory_is_never_followed_or_removed(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        target = tmp_path / "elsewhere"
        target.mkdir()
        (target / "token").write_text("not ours", encoding="utf-8")
        env.paths.k8s_creds_dir.mkdir(parents=True)
        link = env.paths.k8s_creds_dir / "prod"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable here: {exc}")

        await env.reconciler.reconcile("startup")

        assert (target / "token").read_text(encoding="utf-8") == "not ours"
        assert link.is_symlink()

    async def test_current_copies_and_unrelated_files_are_untouched(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        env.add_k8s_cluster_overlay()
        legacy = self._legacy(env, "old")

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert not legacy.exists()
        token_copy, ca_copy = env.rendered_k8s_files()
        assert token_copy.is_file() and ca_copy.is_file()

    async def test_a_directory_the_last_good_config_references_is_kept(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        from gwops.supervisor.process import last_good_path

        env = _env(tmp_path, gateway_binary())
        held = self._legacy(env, "prod")
        gone = self._legacy(env, "old")
        last_good = last_good_path(env.config_path)
        last_good.parent.mkdir(parents=True, exist_ok=True)
        last_good.write_text(f"bearerTokenFile: {(held / 'token').as_posix()}\n", encoding="utf-8")

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert (held / "token").is_file() and not gone.exists()

    async def test_nothing_is_removed_when_the_pass_failed_locally(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary(), ("corp", "corp.pem"))
        _write(env, "corp.pem", b"broken")
        legacy = self._legacy(env)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert legacy.is_dir()

    async def test_a_missing_credentials_directory_is_fine(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = _env(tmp_path, gateway_binary())
        assert not env.paths.k8s_creds_dir.exists()

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True

