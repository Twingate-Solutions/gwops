"""Tests for ``gwops.acme.token``: metadata-only checks of the DNS token file.

gwops never opens the token (lego reads it through ``CF_DNS_API_TOKEN_FILE``), so every check
here is a ``stat`` or a path resolution. The autouse ``acme_root`` fixture in ``conftest.py``
points ``gwops.acme.token.ACME_ROOT`` at ``tmp_path/config/acme``; each test builds its token
under that root or beside it. Tests that need a symlink skip where the platform refuses to
create one.
"""

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from gwops.acme import token as token_module
from gwops.acme.token import (
    ResolvedToken,
    resolve_token_file,
    token_file_problem,
    token_file_signature,
)
from gwops.configmodel.schema import AcmeSettings

SECRET = "cfut_SENTINEL_TOKEN_CONTENT_must_never_be_read_0123456789"

_watching = False
_opened: list[str] = []


def _audit(event: str, args: tuple[object, ...]) -> None:
    """Record any in-process ``open`` while a test is watching (the token must never be one)."""
    if _watching and event == "open" and isinstance(args[0], str | bytes | os.PathLike):
        _opened.append(os.fsdecode(args[0]))


sys.addaudithook(_audit)


def settings_for(path: Path) -> AcmeSettings:
    """A valid ``public_tls.acme`` block whose ``token_file`` is `path` (applied unvalidated).

    The seed model confines ``token_file`` lexically to ``/config/acme/``; the tmp path is
    applied with ``model_copy`` so the runtime check under test sees an arbitrary path.
    """
    block = AcmeSettings.model_validate({"email": "ops@example.com", "accept_tos": True})
    return block.model_copy(update={"token_file": str(path)})


def symlink(link: Path, target: Path) -> None:
    """Create `link` -> `target`, skipping the test where symlinks cannot be created."""
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot create symlinks")


@pytest.fixture
def token(acme_root: Path) -> Path:
    """A regular, non-empty token file directly under the root."""
    path = acme_root / "cloudflare-token"
    path.parent.mkdir(parents=True)
    path.write_text(SECRET + "\n")
    return path


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A regular file that is not under the ACME root."""
    path = tmp_path / "elsewhere" / "other-token"
    path.parent.mkdir()
    path.write_text(SECRET + "\n")
    return path


class TestResolveAccepted:
    def test_a_regular_non_empty_file_under_the_root_has_no_problem(self, token: Path) -> None:
        resolved = resolve_token_file(settings_for(token))

        assert resolved == ResolvedToken(os.path.realpath(token), None, False)

    def test_the_path_is_the_resolved_path_not_the_configured_one(self, token: Path) -> None:
        link = token.parent / "alias"
        symlink(link, token)

        resolved = resolve_token_file(settings_for(link))

        assert resolved.path == os.path.realpath(token)
        assert resolved.path != str(link)
        assert resolved.problem is None

    def test_a_link_chain_inside_the_root_resolves_to_the_final_file(
        self, acme_root: Path
    ) -> None:
        """The Kubernetes secret layout: ``token -> ..data/token -> ..<timestamp>/token``."""
        generation = acme_root / "..2026_10_20_12_00_00.123456789"
        generation.mkdir(parents=True)
        (generation / "cloudflare-token").write_text(SECRET)
        symlink(acme_root / "..data", generation)
        symlink(acme_root / "cloudflare-token", Path("..data") / "cloudflare-token")

        resolved = resolve_token_file(settings_for(acme_root / "cloudflare-token"))

        assert resolved.path == os.path.realpath(generation / "cloudflare-token")
        assert resolved.problem is None
        assert resolved.outside_root is False

    def test_a_file_in_a_subdirectory_is_accepted(self, acme_root: Path) -> None:
        nested = acme_root / "dns" / "zone-token"
        nested.parent.mkdir(parents=True)
        nested.write_text("x")

        assert resolve_token_file(settings_for(nested)).problem is None

    def test_one_byte_is_enough(self, token: Path) -> None:
        token.write_text("x")

        assert resolve_token_file(settings_for(token)).problem is None

    def test_an_acme_root_that_is_itself_a_link_still_contains_its_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_root = tmp_path / "real-root"
        real_root.mkdir()
        (real_root / "t").write_text("x")
        link_root = tmp_path / "linked-root"
        symlink(link_root, real_root)
        monkeypatch.setattr(token_module, "ACME_ROOT", link_root)

        resolved = resolve_token_file(settings_for(link_root / "t"))

        assert resolved.problem is None
        assert resolved.outside_root is False


class TestResolveProblems:
    def test_a_missing_file_is_a_problem_but_not_an_escape(self, acme_root: Path) -> None:
        missing = acme_root / "cloudflare-token"
        acme_root.mkdir(parents=True)

        resolved = resolve_token_file(settings_for(missing))

        assert resolved.problem is not None
        assert "does not exist" in resolved.problem
        assert str(missing) in resolved.problem
        assert "/config/acme/" in resolved.problem
        assert resolved.outside_root is False
        assert resolved.path == os.path.realpath(missing)

    def test_an_empty_file_is_a_problem(self, token: Path) -> None:
        token.write_text("")

        resolved = resolve_token_file(settings_for(token))

        assert resolved.problem is not None
        assert "is empty" in resolved.problem
        assert resolved.outside_root is False

    def test_a_directory_is_not_a_regular_file(self, acme_root: Path) -> None:
        directory = acme_root / "a-directory"
        directory.mkdir(parents=True)

        resolved = resolve_token_file(settings_for(directory))

        assert resolved.problem is not None
        assert "not a regular file" in resolved.problem
        assert resolved.outside_root is False

    @pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX named pipe")
    def test_a_named_pipe_is_not_a_regular_file(self, acme_root: Path) -> None:
        pipe = acme_root / "pipe"
        acme_root.mkdir(parents=True)
        os.mkfifo(pipe)

        resolved = resolve_token_file(settings_for(pipe))

        assert resolved.problem is not None
        assert "not a regular file" in resolved.problem

    def test_a_dangling_link_inside_the_root_reports_a_missing_file(
        self, acme_root: Path
    ) -> None:
        link = acme_root / "dangling"
        symlink(link, acme_root / "no-such-target")

        resolved = resolve_token_file(settings_for(link))

        assert resolved.problem is not None
        assert "does not exist" in resolved.problem
        assert resolved.outside_root is False

    def test_a_stat_error_other_than_not_found_names_the_error_type_only(
        self, token: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_stat = os.stat
        target = os.path.realpath(token)

        def selective(path: object, *args: object, **kwargs: object) -> os.stat_result:
            if isinstance(path, str | os.PathLike) and os.fspath(path) == target:
                raise PermissionError(13, "Permission denied", target)
            return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(token_module.os, "stat", selective)

        resolved = resolve_token_file(settings_for(token))

        assert resolved.problem is not None
        assert "cannot be examined (PermissionError)" in resolved.problem
        assert "Permission denied" not in resolved.problem
        assert resolved.outside_root is False

    def test_a_problem_text_names_paths_never_contents(self, token: Path) -> None:
        token.write_text("")
        texts = [resolve_token_file(settings_for(token)).problem or ""]
        token.write_text(SECRET)
        texts.append(resolve_token_file(settings_for(token)).problem or "")

        assert all(SECRET not in text for text in texts)


class TestOutsideTheRoot:
    def test_a_file_outside_the_root_is_an_escape_with_both_paths_named(
        self, acme_root: Path, outside: Path
    ) -> None:
        acme_root.mkdir(parents=True)

        resolved = resolve_token_file(settings_for(outside))

        assert resolved.outside_root is True
        assert resolved.path == os.path.realpath(outside)
        assert resolved.problem is not None
        assert str(outside) in resolved.problem
        assert os.path.realpath(acme_root) in resolved.problem
        assert "outside" in resolved.problem
        assert "mount the token itself" in resolved.problem

    def test_a_link_inside_the_root_that_points_outside_is_an_escape(
        self, token: Path, outside: Path
    ) -> None:
        token.unlink()
        symlink(token, outside)

        resolved = resolve_token_file(settings_for(token))

        assert resolved.outside_root is True
        assert resolved.path == os.path.realpath(outside)
        assert resolved.problem is not None
        assert str(token) in resolved.problem, "the configured path is named too"

    def test_a_dangling_link_that_points_outside_is_still_an_escape(
        self, acme_root: Path, tmp_path: Path
    ) -> None:
        link = acme_root / "cloudflare-token"
        symlink(link, tmp_path / "outside-nowhere" / "token")

        resolved = resolve_token_file(settings_for(link))

        assert resolved.outside_root is True

    def test_a_link_to_a_directory_that_holds_the_file_is_an_escape(
        self, acme_root: Path, outside: Path
    ) -> None:
        """A directory link inside the root does not extend the root."""
        symlink(acme_root / "dir-link", outside.parent)

        resolved = resolve_token_file(settings_for(acme_root / "dir-link" / outside.name))

        assert resolved.outside_root is True

    def test_dot_dot_components_are_resolved_before_the_check(
        self, acme_root: Path, outside: Path
    ) -> None:
        acme_root.mkdir(parents=True)
        sneaky = acme_root / ".." / ".." / outside.parent.name / outside.name

        resolved = resolve_token_file(settings_for(sneaky))

        assert resolved.outside_root is True
        assert resolved.path == os.path.realpath(outside)

    def test_the_root_itself_is_not_a_token_file(self, acme_root: Path) -> None:
        acme_root.mkdir(parents=True)

        resolved = resolve_token_file(settings_for(acme_root))

        assert resolved.outside_root is True

    def test_a_sibling_directory_sharing_the_root_name_as_a_prefix_is_outside(
        self, acme_root: Path
    ) -> None:
        sibling = acme_root.parent / f"{acme_root.name}-other" / "token"
        sibling.parent.mkdir(parents=True)
        sibling.write_text("x")

        resolved = resolve_token_file(settings_for(sibling))

        assert resolved.outside_root is True

    @pytest.mark.skipif(sys.platform != "win32", reason="different drives only exist on Windows")
    def test_a_path_on_another_drive_is_outside_not_an_error(
        self, token: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other_drive = "D:" if token.drive.upper() != "D:" else "E:"
        monkeypatch.setattr(token_module, "ACME_ROOT", Path(other_drive + "\\config\\acme"))

        resolved = resolve_token_file(settings_for(token))

        assert resolved.outside_root is True

    def test_an_escape_is_never_read_either(self, token: Path, outside: Path) -> None:
        global _watching
        token.unlink()
        symlink(token, outside)
        _opened.clear()
        _watching = True
        try:
            resolve_token_file(settings_for(token))
        finally:
            _watching = False

        assert [p for p in _opened if os.path.basename(p) in {token.name, outside.name}] == []


class TestNeverReadsTheContent:
    @pytest.mark.parametrize(
        "call",
        [
            resolve_token_file,
            token_file_problem,
            token_file_signature,
        ],
        ids=["resolve", "problem", "signature"],
    )
    def test_no_function_opens_the_file(
        self, token: Path, call: Callable[[AcmeSettings], object]
    ) -> None:
        global _watching
        _opened.clear()
        _watching = True
        try:
            call(settings_for(token))
        finally:
            _watching = False

        assert [p for p in _opened if os.path.basename(p) == token.name] == []


class TestTokenFileProblem:
    def test_it_is_none_for_a_usable_file(self, token: Path) -> None:
        assert token_file_problem(settings_for(token)) is None

    @pytest.mark.parametrize("case", ["missing", "empty", "directory", "outside"])
    def test_it_is_the_resolve_problem(
        self, case: str, acme_root: Path, outside: Path
    ) -> None:
        acme_root.mkdir(parents=True)
        target = {
            "missing": acme_root / "absent",
            "empty": acme_root / "empty",
            "directory": acme_root / "dir",
            "outside": outside,
        }[case]
        if case == "empty":
            target.write_text("")
        if case == "directory":
            target.mkdir()
        settings = settings_for(target)

        problem = token_file_problem(settings)

        assert problem is not None
        assert problem == resolve_token_file(settings).problem


class TestTokenFileSignature:
    def test_it_is_inode_mtime_and_size_of_the_file(self, token: Path) -> None:
        info = os.stat(token)

        assert token_file_signature(settings_for(token)) == (
            info.st_ino,
            info.st_mtime_ns,
            info.st_size,
        )

    def test_a_missing_file_has_no_signature(self, acme_root: Path) -> None:
        assert token_file_signature(settings_for(acme_root / "absent")) is None

    def test_an_unchanged_file_has_a_stable_signature(self, token: Path) -> None:
        settings = settings_for(token)

        assert token_file_signature(settings) == token_file_signature(settings)

    def test_a_longer_rewritten_file_changes_it(self, token: Path) -> None:
        before = token_file_signature(settings_for(token))

        token.write_text(SECRET * 2)

        assert token_file_signature(settings_for(token)) != before

    def test_a_new_mtime_alone_changes_it(self, token: Path) -> None:
        before = token_file_signature(settings_for(token))
        stamp = os.stat(token).st_mtime_ns + 5_000_000_000

        os.utime(token, ns=(stamp, stamp))

        assert token_file_signature(settings_for(token)) != before

    def test_replacing_the_file_by_rename_changes_it(self, token: Path) -> None:
        """An operator (or a secret mount) swaps the token with the same size and mtime."""
        before = token_file_signature(settings_for(token))
        old = os.stat(token)
        replacement = token.with_name("replacement")
        replacement.write_text(token.read_text())
        os.utime(replacement, ns=(old.st_atime_ns, old.st_mtime_ns))

        os.replace(replacement, token)

        after = token_file_signature(settings_for(token))
        assert after is not None
        assert before is not None
        assert after[1:] == before[1:], "size and mtime were kept the same on purpose"
        if sys.platform != "win32":
            assert after[0] != before[0], "the inode differs"

    def test_it_follows_a_link_to_the_target(self, token: Path) -> None:
        link = token.parent / "alias"
        symlink(link, token)

        assert token_file_signature(settings_for(link)) == token_file_signature(
            settings_for(token)
        )

    def test_retargeting_a_link_changes_it(self, token: Path) -> None:
        other = token.parent / "second-token"
        other.write_text("a different and longer token value")
        link = token.parent / "alias"
        symlink(link, token)
        before = token_file_signature(settings_for(link))

        link.unlink()
        symlink(link, other)

        assert token_file_signature(settings_for(link)) != before

    def test_a_directory_still_has_a_signature_and_never_raises(self, acme_root: Path) -> None:
        """Only the runner's comparison matters; an odd target must not raise."""
        acme_root.mkdir(parents=True)

        assert token_file_signature(settings_for(acme_root)) is not None
