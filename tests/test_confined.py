"""Tests for gwops.confined: the confined-root reader, the content-addressed writer, and GC."""

import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import structlog
import yaml

from gwops import confined
from gwops.confined import (
    MAX_FILE_BYTES,
    ConfinedFileError,
    ConfinedReadError,
    collect_garbage,
    content_address,
    content_digest,
    read_confined,
    remove_legacy_credential_dirs,
    write_content_addressed,
)

_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes / FIFOs are not available on Windows"
)

_SECRET = b"TOP-SECRET-CONTENTS-do-not-log"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "root"
    directory.mkdir()
    return directory


def _symlink_or_skip(link: Path, target: Path) -> None:
    """Create the file symlink `link -> target`, skipping where symlinks cannot be created."""
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable here: {exc}")


def _dir_link_or_skip(link: Path, target: Path) -> None:
    """Create a directory link (a junction on Windows, which needs no privilege), else skip."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except (OSError, NotImplementedError) as exc:
        if sys.platform != "win32":
            pytest.skip(f"symlinks unavailable here: {exc}")
    completed = subprocess.run(  # noqa: S603 - fixed argv, test-controlled paths
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip("neither symlinks nor junctions can be created here")


class TestReadConfined:
    def test_reads_a_file_under_the_root(self, root: Path) -> None:
        (root / "token").write_bytes(b"abc")
        assert read_confined(root / "token", root) == b"abc"

    def test_reads_a_file_in_a_subdirectory(self, root: Path) -> None:
        (root / "prod").mkdir()
        (root / "prod" / "ca.crt").write_bytes(b"PEM")
        assert read_confined(root / "prod" / "ca.crt", root) == b"PEM"

    def test_accepts_a_string_path(self, root: Path) -> None:
        (root / "token").write_bytes(b"abc")
        assert read_confined(str(root / "token"), root) == b"abc"

    def test_path_outside_the_root_is_refused_naming_path_and_root(
        self, tmp_path: Path, root: Path
    ) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_bytes(_SECRET)

        with pytest.raises(ConfinedReadError) as excinfo:
            read_confined(outside, root)

        message = str(excinfo.value)
        assert str(outside) in message
        assert str(root) in message
        assert _SECRET.decode() not in message
        assert excinfo.value.path == outside
        assert excinfo.value.root == root

    def test_sibling_directory_sharing_a_name_prefix_is_outside(
        self, tmp_path: Path, root: Path
    ) -> None:
        # `/x/root-evil` must not pass a string-prefix check against `/x/root`.
        sibling = tmp_path / "root-evil"
        sibling.mkdir()
        (sibling / "token").write_bytes(_SECRET)

        with pytest.raises(ConfinedReadError, match="outside"):
            read_confined(sibling / "token", root)

    def test_dotdot_traversal_out_of_the_root_is_refused(
        self, tmp_path: Path, root: Path
    ) -> None:
        (root / "sub").mkdir()
        (tmp_path / "outside.txt").write_bytes(_SECRET)
        traversal = root / "sub" / ".." / ".." / "outside.txt"

        with pytest.raises(ConfinedReadError) as excinfo:
            read_confined(traversal, root)

        assert _SECRET.decode() not in str(excinfo.value)
        assert str(root) in str(excinfo.value)

    def test_dotdot_that_stays_inside_the_root_is_allowed(self, root: Path) -> None:
        (root / "sub").mkdir()
        (root / "token").write_bytes(b"abc")
        assert read_confined(root / "sub" / ".." / "token", root) == b"abc"

    def test_symlink_escaping_the_root_is_refused(self, tmp_path: Path, root: Path) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_bytes(_SECRET)
        link = root / "innocent.token"
        _symlink_or_skip(link, outside)

        with pytest.raises(ConfinedReadError) as excinfo:
            read_confined(link, root)

        assert _SECRET.decode() not in str(excinfo.value)
        assert "outside" in str(excinfo.value)

    def test_symlinked_directory_escaping_the_root_is_refused(
        self, tmp_path: Path, root: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "token").write_bytes(_SECRET)
        _dir_link_or_skip(root / "dir-link", elsewhere)

        with pytest.raises(ConfinedReadError, match="outside"):
            read_confined(root / "dir-link" / "token", root)

    def test_symlink_that_stays_inside_the_root_is_allowed(self, root: Path) -> None:
        (root / "real.token").write_bytes(b"abc")
        _symlink_or_skip(root / "alias.token", root / "real.token")
        assert read_confined(root / "alias.token", root) == b"abc"

    def test_symlinked_root_is_resolved_before_comparison(
        self, tmp_path: Path, root: Path
    ) -> None:
        (root / "token").write_bytes(b"abc")
        link_to_root = tmp_path / "root-link"
        _dir_link_or_skip(link_to_root, root)
        assert read_confined(link_to_root / "token", link_to_root) == b"abc"
        assert read_confined(root / "token", link_to_root) == b"abc"

    def test_a_directory_is_refused_as_not_a_regular_file(self, root: Path) -> None:
        (root / "adir").mkdir()
        with pytest.raises(ConfinedReadError, match="regular file"):
            read_confined(root / "adir", root)

    @_posix_only
    def test_a_fifo_is_refused_without_blocking(self, root: Path) -> None:
        fifo = root / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(ConfinedReadError, match="regular file"):
            read_confined(fifo, root)

    def test_a_missing_file_is_refused_naming_path_and_root(self, root: Path) -> None:
        missing = root / "nope.token"
        with pytest.raises(ConfinedReadError) as excinfo:
            read_confined(missing, root)
        assert str(missing) in str(excinfo.value)
        assert str(root) in str(excinfo.value)
        assert "not found" in str(excinfo.value)

    def test_a_file_over_the_size_cap_is_refused(self, root: Path) -> None:
        big = root / "big.pem"
        big.write_bytes(b"A" * (MAX_FILE_BYTES + 1))
        with pytest.raises(ConfinedReadError, match="1 MiB|size limit") as excinfo:
            read_confined(big, root)
        assert "AAAA" not in str(excinfo.value)

    def test_a_file_exactly_at_the_size_cap_is_read(self, root: Path) -> None:
        exact = root / "exact.pem"
        exact.write_bytes(b"A" * MAX_FILE_BYTES)
        assert len(read_confined(exact, root)) == MAX_FILE_BYTES

    def test_the_cap_is_a_parameter(self, root: Path) -> None:
        (root / "f").write_bytes(b"12345")
        with pytest.raises(ConfinedReadError):
            read_confined(root / "f", root, max_bytes=4)
        assert read_confined(root / "f", root, max_bytes=5) == b"12345"

    def test_the_read_itself_is_capped_when_the_file_grows_after_the_size_check(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # stat reports a small file but the bytes exceed the cap: the bounded read must refuse.
        big = root / "growing.pem"
        big.write_bytes(b"A" * 64)
        real_fstat = os.fstat

        def _small_fstat(fd: int) -> os.stat_result:
            real = real_fstat(fd)
            fields = list(real)
            fields[stat.ST_SIZE] = 1
            return os.stat_result(fields)

        monkeypatch.setattr(confined.os, "fstat", _small_fstat)
        with pytest.raises(ConfinedReadError, match="size limit"):
            read_confined(big, root, max_bytes=16)

    def test_an_embedded_nul_is_refused_as_an_invalid_path(self, root: Path) -> None:
        with pytest.raises(ConfinedReadError, match="is not a valid path") as excinfo:
            read_confined(str(root / "a\x00b"), root)
        assert isinstance(excinfo.value, ConfinedFileError)

    def test_the_file_is_opened_without_following_links_or_blocking(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (root / "f").write_bytes(b"x")
        seen: list[int] = []
        real_open = os.open

        def _spy(path: object, flags: int, *args: object, **kwargs: object) -> int:
            seen.append(flags)
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(confined.os, "open", _spy)
        assert read_confined(root / "f", root) == b"x"
        [flags] = seen
        for name in ("O_NOFOLLOW", "O_NONBLOCK"):
            assert flags & getattr(os, name, 0) == getattr(os, name, 0), name

    def _swap_after_stat(
        self, monkeypatch: pytest.MonkeyPatch, swap: Callable[[], None]
    ) -> None:
        """Run `swap` once, right before the file is opened (after read_confined's stat)."""
        real_open = os.open

        def _swapping(path: object, flags: int, *args: object, **kwargs: object) -> int:
            swap()
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(confined.os, "open", _swapping)

    def test_a_file_replaced_between_stat_and_open_is_refused(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "f"
        target.write_bytes(b"original")
        other = root / "other"
        other.write_bytes(b"swapped-in")
        self._swap_after_stat(monkeypatch, lambda: os.replace(other, target))

        with pytest.raises(ConfinedReadError, match="changed") as excinfo:
            read_confined(target, root)
        assert "swapped-in" not in str(excinfo.value)

    @_posix_only
    def test_a_fifo_swapped_in_after_stat_is_refused_without_blocking(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "f"
        target.write_bytes(b"original")

        def _swap() -> None:
            target.unlink()
            os.mkfifo(target)

        self._swap_after_stat(monkeypatch, _swap)
        with pytest.raises(ConfinedReadError):
            read_confined(target, root)

    @_posix_only
    def test_a_symlink_swapped_in_after_stat_is_not_followed(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "f"
        target.write_bytes(b"original")
        other = root / "other"
        other.write_bytes(b"swapped-in")

        def _swap() -> None:
            target.unlink()
            target.symlink_to(other)

        self._swap_after_stat(monkeypatch, _swap)
        with pytest.raises(ConfinedReadError) as excinfo:
            read_confined(target, root)
        assert "swapped-in" not in str(excinfo.value)

    def test_errors_are_a_dedicated_type_and_never_carry_contents(
        self, tmp_path: Path, root: Path
    ) -> None:
        assert issubclass(ConfinedReadError, ConfinedFileError)
        outside = tmp_path / "out"
        outside.write_bytes(_SECRET)
        with pytest.raises(ConfinedReadError) as excinfo:
            read_confined(outside, root)
        assert _SECRET.decode() not in repr(excinfo.value)
        assert _SECRET.decode() not in str(excinfo.value.reason)


class TestContentDigest:
    def test_is_twelve_lowercase_hex_chars_and_content_dependent(self) -> None:
        digest = content_digest(b"abc")
        assert re.fullmatch(r"[0-9a-f]{12}", digest)
        assert digest == "ba7816bf8f01"  # sha256("abc")[:12]
        assert content_digest(b"abd") != digest


class TestContentAddress:
    def test_is_pure_and_matches_what_the_writer_produces(self, tmp_path: Path) -> None:
        address = content_address(tmp_path / "out", "corp", b"abc", suffix=".pem")
        assert address == tmp_path / "out" / "corp-ba7816bf8f01.pem"
        assert not (tmp_path / "out").exists()
        assert write_content_addressed(
            tmp_path / "out", "corp", b"abc", suffix=".pem", mode=0o644
        ) == address

    def test_rejects_an_unsafe_stem(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="stem"):
            content_address(tmp_path, "../x", b"abc")


class TestWriteContentAddressed:
    def test_writes_stem_digest_suffix_under_dest_dir(self, tmp_path: Path) -> None:
        dest = tmp_path / "out"
        path = write_content_addressed(dest, "corp-ca", b"abc", suffix=".pem", mode=0o644)
        assert path == dest / "corp-ca-ba7816bf8f01.pem"
        assert path.read_bytes() == b"abc"

    def test_suffix_is_optional(self, tmp_path: Path) -> None:
        path = write_content_addressed(tmp_path, "prod-token", b"abc", mode=0o600)
        assert path.name == "prod-token-ba7816bf8f01"

    @_posix_only
    @pytest.mark.parametrize("mode", [0o600, 0o644])
    def test_applies_the_requested_mode(self, tmp_path: Path, mode: int) -> None:
        path = write_content_addressed(tmp_path, "x", b"abc", mode=mode)
        assert stat.S_IMODE(path.stat().st_mode) == mode

    def test_identical_content_is_not_rewritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = write_content_addressed(tmp_path, "x", b"abc", mode=0o644)
        replaced: list[object] = []
        real_replace = os.replace
        monkeypatch.setattr(
            confined.os, "replace", lambda *a, **k: (replaced.append(a), real_replace(*a, **k))
        )

        second = write_content_addressed(tmp_path, "x", b"abc", mode=0o644)

        assert second == first
        assert replaced == []

    def test_changed_content_gets_a_new_path_and_keeps_the_old_file(
        self, tmp_path: Path
    ) -> None:
        old = write_content_addressed(tmp_path, "x", b"v1", suffix=".pem", mode=0o644)
        new = write_content_addressed(tmp_path, "x", b"v2", suffix=".pem", mode=0o644)
        assert old != new
        assert old.read_bytes() == b"v1"
        assert new.read_bytes() == b"v2"

    def test_no_temporary_file_is_left_behind(self, tmp_path: Path) -> None:
        write_content_addressed(tmp_path, "x", b"abc", mode=0o644)
        assert [p.name for p in tmp_path.iterdir()] == ["x-ba7816bf8f01"]

    def test_a_failed_replace_cleans_up_and_leaves_no_destination(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("disk on fire")

        monkeypatch.setattr(confined.os, "replace", _boom)
        with pytest.raises(OSError, match="disk on fire"):
            write_content_addressed(tmp_path, "x", b"abc", mode=0o644)
        assert list(tmp_path.iterdir()) == []

    def test_the_temporary_file_is_created_exclusively_without_following_links(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[int] = []
        real_open = os.open

        def _spy(path: object, flags: int, *args: object, **kwargs: object) -> int:
            seen.append(flags)
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(confined.os, "open", _spy)
        write_content_addressed(tmp_path, "x", b"abc", mode=0o644)
        [flags] = seen
        assert flags & os.O_CREAT and flags & os.O_EXCL
        assert not flags & os.O_TRUNC
        assert flags & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)

    def test_a_stale_temporary_file_from_a_killed_write_is_replaced(self, tmp_path: Path) -> None:
        stale = tmp_path / "x-ba7816bf8f01.tmp"
        stale.write_bytes(b"half written")

        path = write_content_addressed(tmp_path, "x", b"abc", mode=0o644)

        assert path.read_bytes() == b"abc"
        assert [p.name for p in tmp_path.iterdir()] == ["x-ba7816bf8f01"]

    def test_a_symlink_planted_at_the_temporary_name_is_never_written_through(
        self, tmp_path: Path
    ) -> None:
        precious = tmp_path / "precious"
        precious.write_bytes(b"keep")
        dest_dir = tmp_path / "copies"
        dest_dir.mkdir()
        _symlink_or_skip(dest_dir / "x-ba7816bf8f01.tmp", precious)

        path = write_content_addressed(dest_dir, "x", b"abc", mode=0o644)

        assert precious.read_bytes() == b"keep"
        assert path.read_bytes() == b"abc" and not path.is_symlink()

    def test_creates_the_destination_directory(self, tmp_path: Path) -> None:
        path = write_content_addressed(tmp_path / "a" / "b", "x", b"abc", mode=0o644)
        assert path.is_file()

    @pytest.mark.parametrize("stem", ["", "a/b", "a\\b", "..", ".hidden", "a b", "../x"])
    def test_an_unsafe_stem_is_rejected(self, tmp_path: Path, stem: str) -> None:
        with pytest.raises(ValueError, match="stem"):
            write_content_addressed(tmp_path, stem, b"abc", mode=0o644)

    @pytest.mark.parametrize("suffix", ["pem", ".a/b", "..pem", "."])
    def test_an_unsafe_suffix_is_rejected(self, tmp_path: Path, suffix: str) -> None:
        with pytest.raises(ValueError, match="suffix"):
            write_content_addressed(tmp_path, "x", b"abc", suffix=suffix, mode=0o644)

    def test_a_different_file_already_at_the_address_fails_loud(self, tmp_path: Path) -> None:
        target = tmp_path / "x-ba7816bf8f01"
        target.write_bytes(b"not abc")  # a (practically impossible) digest collision
        with pytest.raises(ConfinedFileError, match="different content"):
            write_content_addressed(tmp_path, "x", b"abc", mode=0o644)
        assert target.read_bytes() == b"not abc"


def _ca_file(directory: Path, stem: str, content: bytes) -> Path:
    return write_content_addressed(directory, stem, content, suffix=".pem", mode=0o644)


class TestCollectGarbage:
    def test_keeps_current_and_last_good_references_and_removes_the_rest(
        self, tmp_path: Path
    ) -> None:
        cas = tmp_path / "upstream-ca"
        current = _ca_file(cas, "corp", b"v3")
        last_good = _ca_file(cas, "corp", b"v2")
        stale = _ca_file(cas, "corp", b"v1")
        config = tmp_path / "config.yaml"
        config.write_text(f"upstreamTrustedCABundles:\n  - file: {current.as_posix()}\n")
        good = tmp_path / "config.yaml.last-good"
        good.write_text(f"upstreamTrustedCABundles:\n  - file: {last_good.as_posix()}\n")

        removed = collect_garbage(cas, [config, good])

        assert removed == [stale]
        assert current.is_file()
        assert last_good.is_file()
        assert not stale.exists()

    def test_a_file_referenced_by_both_configs_is_kept(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        shared = _ca_file(cas, "corp", b"same")
        config = tmp_path / "config.yaml"
        config.write_text(f"file: {shared.as_posix()}\n")
        good = tmp_path / "config.yaml.last-good"
        good.write_text(f"file: {shared.as_posix()}\n")

        assert collect_garbage(cas, [config, good]) == []
        assert shared.is_file()

    def test_a_missing_last_good_is_tolerated(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        current = _ca_file(cas, "corp", b"v2")
        stale = _ca_file(cas, "corp", b"v1")
        config = tmp_path / "config.yaml"
        config.write_text(f"file: {current.as_posix()}\n")

        removed = collect_garbage(cas, [config, tmp_path / "config.yaml.last-good"])

        assert removed == [stale]
        assert current.is_file()

    def test_nothing_is_deleted_when_no_config_can_be_read(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        copy = _ca_file(cas, "corp", b"v1")
        removed = collect_garbage(
            cas, [tmp_path / "config.yaml", tmp_path / "config.yaml.last-good"]
        )
        assert removed == []
        assert copy.is_file()

    def test_nothing_is_deleted_when_a_present_config_is_unreadable(
        self, tmp_path: Path
    ) -> None:
        cas = tmp_path / "ca"
        copy = _ca_file(cas, "corp", b"v1")
        config = tmp_path / "config.yaml"
        config.write_text("file: /elsewhere\n")
        unreadable = tmp_path / "config.yaml.last-good"
        unreadable.mkdir()  # exists but cannot be read as a file

        assert collect_garbage(cas, [config, unreadable]) == []
        assert copy.is_file()

    def test_files_that_are_not_content_addressed_copies_are_never_touched(
        self, tmp_path: Path
    ) -> None:
        cas = tmp_path / "ca"
        cas.mkdir()
        (cas / "notes.txt").write_text("hi")
        (cas / "token").write_text("legacy")
        (cas / "corp-ZZZZZZZZZZZZ.pem").write_text("not hex")
        (cas / "corp-0123456789ab.pem" ).mkdir()  # a directory matching the name pattern
        subdir = cas / "prod"
        subdir.mkdir()
        (subdir / "x-0123456789ab").write_text("nested")
        config = tmp_path / "config.yaml"
        config.write_text("port: 8443\n")

        assert collect_garbage(cas, [config]) == []
        assert sorted(p.name for p in cas.iterdir()) == [
            "corp-0123456789ab.pem",
            "corp-ZZZZZZZZZZZZ.pem",
            "notes.txt",
            "prod",
            "token",
        ]
        assert (subdir / "x-0123456789ab").is_file()

    def test_suffixless_copies_are_collected_too(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        keep = write_content_addressed(creds, "prod-token", b"new", mode=0o600)
        drop = write_content_addressed(creds, "prod-token", b"old", mode=0o600)
        config = tmp_path / "config.yaml"
        config.write_text(f"bearerTokenFile: {keep.as_posix()}\n")

        assert collect_garbage(creds, [config]) == [drop]

    def test_an_orphaned_temporary_file_is_collected(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        keep = write_content_addressed(creds, "prod-token", b"new", mode=0o600)
        orphan = creds / "prod-token-0123456789ab.tmp"
        orphan.write_bytes(b"half written")
        config = tmp_path / "config.yaml"
        config.write_text(f"bearerTokenFile: {keep.as_posix()}\n")

        collect_garbage(creds, [config])

        assert not orphan.exists()
        assert keep.is_file()

    def test_an_orphaned_temporary_file_with_an_extension_is_collected(
        self, tmp_path: Path
    ) -> None:
        cas = tmp_path / "ca"
        keep = write_content_addressed(cas, "corp", b"v1", suffix=".pem", mode=0o644)
        orphan = cas / "corp-0123456789ab.pem.tmp"
        orphan.write_bytes(b"half written")
        unrelated = cas / "corp-0123456789ab.pem.bak"
        unrelated.write_bytes(b"not ours")
        config = tmp_path / "config.yaml"
        config.write_text(f"file: {keep.as_posix()}\n")

        assert collect_garbage(cas, [config]) == [orphan]
        assert keep.is_file() and unrelated.is_file()

    def test_a_missing_directory_is_a_no_op(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("port: 8443\n")
        assert collect_garbage(tmp_path / "does-not-exist", [config]) == []

    def test_a_removal_failure_is_logged_and_the_rest_continue(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cas = tmp_path / "ca"
        a = _ca_file(cas, "a", b"1")
        b = _ca_file(cas, "b", b"2")
        config = tmp_path / "config.yaml"
        config.write_text("port: 8443\n")
        real_unlink = Path.unlink

        def _flaky(self: Path, *args: object, **kwargs: object) -> None:
            if self == a:
                raise PermissionError("nope")
            real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "unlink", _flaky)

        removed = collect_garbage(cas, [config])

        assert removed == [b]
        assert a.is_file()


def _legacy_dir(parent: Path, name: str, files: tuple[str, ...] = ("token", "ca.crt")) -> Path:
    directory = parent / name
    directory.mkdir(parents=True)
    for file in files:
        (directory / file).write_bytes(_SECRET)
    return directory


class TestRemoveLegacyCredentialDirs:
    """Per-cluster `<name>/{token,ca.crt}` directories left by the previous release."""

    def test_removes_directories_holding_only_token_and_ca_crt(self, tmp_path: Path) -> None:
        full = _legacy_dir(tmp_path, "prod")
        token_only = _legacy_dir(tmp_path, "stage", ("token",))
        ca_only = _legacy_dir(tmp_path, "dev", ("ca.crt",))
        empty = _legacy_dir(tmp_path, "empty", ())

        removed = remove_legacy_credential_dirs(tmp_path, [])

        assert removed == [ca_only, empty, full, token_only]
        assert not any(d.exists() for d in removed)

    def test_leaves_top_level_files_alone(self, tmp_path: Path) -> None:
        copy = tmp_path / "prod-token-0123456789ab"
        copy.write_bytes(_SECRET)
        readme = tmp_path / "README"
        readme.write_text("keep")

        assert remove_legacy_credential_dirs(tmp_path, []) == []
        assert copy.is_file() and readme.is_file()

    @pytest.mark.parametrize(
        "extra", ["notes.txt", "token.bak", "ca.crt.old"], ids=str
    )
    def test_a_directory_with_an_unexpected_file_is_left_whole(
        self, tmp_path: Path, extra: str
    ) -> None:
        directory = _legacy_dir(tmp_path, "odd", ("token", extra))

        with structlog.testing.capture_logs() as logs:
            removed = remove_legacy_credential_dirs(tmp_path, [])

        assert removed == []
        assert (directory / "token").is_file() and (directory / extra).is_file()
        [warning] = [e for e in logs if e["event"] == "confined.legacy_dir_kept"]
        assert warning["log_level"] == "warning"
        assert Path(warning["path"]) == directory

    def test_a_nested_directory_inside_is_unexpected(self, tmp_path: Path) -> None:
        directory = _legacy_dir(tmp_path, "nested", ("token",))
        (directory / "ca.crt").mkdir()

        assert remove_legacy_credential_dirs(tmp_path, []) == []
        assert (directory / "token").is_file()
        assert (directory / "ca.crt").is_dir()

    def test_a_symlink_named_like_a_legacy_file_is_not_followed(self, tmp_path: Path) -> None:
        precious = tmp_path / "outside" / "precious"
        precious.parent.mkdir()
        precious.write_bytes(b"keep")
        directory = tmp_path / "creds" / "prod"
        directory.mkdir(parents=True)
        _symlink_or_skip(directory / "token", precious)

        removed = remove_legacy_credential_dirs(tmp_path / "creds", [])

        assert removed == []
        assert precious.read_bytes() == b"keep"
        assert (directory / "token").is_symlink()

    def test_a_linked_directory_is_never_entered_or_removed(self, tmp_path: Path) -> None:
        target = _legacy_dir(tmp_path, "elsewhere")
        creds = tmp_path / "creds"
        creds.mkdir()
        _dir_link_or_skip(creds / "prod", target)

        with structlog.testing.capture_logs() as logs:
            removed = remove_legacy_credential_dirs(creds, [])

        assert removed == []
        assert (target / "token").read_bytes() == _SECRET
        assert (creds / "prod").exists()
        assert any(e["event"] == "confined.legacy_dir_kept" for e in logs)

    def test_each_removal_is_logged_without_contents(self, tmp_path: Path) -> None:
        _legacy_dir(tmp_path, "prod")

        with structlog.testing.capture_logs() as logs:
            remove_legacy_credential_dirs(tmp_path, [])

        [event] = [e for e in logs if e["event"] == "confined.legacy_dir_removed"]
        assert Path(event["path"]) == tmp_path / "prod"
        assert _SECRET.decode() not in repr(logs)

    def test_is_idempotent_and_tolerates_a_missing_directory(self, tmp_path: Path) -> None:
        _legacy_dir(tmp_path, "prod")
        assert len(remove_legacy_credential_dirs(tmp_path, [])) == 1
        assert remove_legacy_credential_dirs(tmp_path, []) == []
        assert remove_legacy_credential_dirs(tmp_path / "absent", []) == []

    def test_a_failed_removal_is_logged_and_the_rest_continue(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad = _legacy_dir(tmp_path, "a-bad")
        good = _legacy_dir(tmp_path, "b-good")
        real_rmdir = os.rmdir

        def _flaky(path: str | os.PathLike[str], *args: object, **kwargs: object) -> None:
            if Path(path) == bad:
                raise PermissionError("nope")
            real_rmdir(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "rmdir", _flaky)

        with structlog.testing.capture_logs() as logs:
            removed = remove_legacy_credential_dirs(tmp_path, [])

        assert removed == [good]
        assert any(e["event"] == "confined.legacy_dir_remove_failed" for e in logs)

    def test_a_directory_named_by_the_last_good_config_is_kept(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        creds.mkdir()
        held = _legacy_dir(creds, "prod")
        gone = _legacy_dir(creds, "stage")
        last_good = tmp_path / "config.yaml.last-good"
        last_good.write_text(f"bearerTokenFile: {(held / 'token').as_posix()}\n")

        with structlog.testing.capture_logs() as logs:
            removed = remove_legacy_credential_dirs(creds, [tmp_path / "config.yaml", last_good])

        assert removed == [gone]
        assert (held / "token").is_file() and (held / "ca.crt").is_file()
        [kept] = [e for e in logs if e["event"] == "confined.legacy_dir_kept"]
        assert Path(kept["path"]) == held and "referenced" in kept["reason"]

    def test_a_directory_path_in_the_current_config_is_kept(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        creds.mkdir()
        held = _legacy_dir(creds, "prod")
        config = tmp_path / "config.yaml"
        config.write_text(f"credentialDir: '{held.as_posix()}'\n")

        assert remove_legacy_credential_dirs(creds, [config]) == []
        assert held.is_dir()

    def test_a_sibling_sharing_a_name_prefix_is_not_a_reference(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        creds.mkdir()
        legacy = _legacy_dir(creds, "prod")
        copy = creds / "prod-token-0123456789ab"
        config = tmp_path / "config.yaml"
        config.write_text(f"bearerTokenFile: {copy.as_posix()}\n")

        assert remove_legacy_credential_dirs(creds, [config]) == [legacy]

    def test_nothing_is_removed_when_a_present_config_is_unreadable(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        creds.mkdir()
        legacy = _legacy_dir(creds, "prod")
        unreadable = tmp_path / "config.yaml.last-good"
        unreadable.mkdir()  # exists but cannot be read as a file

        with structlog.testing.capture_logs() as logs:
            removed = remove_legacy_credential_dirs(creds, [tmp_path / "config.yaml", unreadable])

        assert removed == []
        assert (legacy / "token").is_file()
        assert any(e["event"] == "confined.legacy_cleanup_skipped" for e in logs)

    def test_a_missing_config_is_not_a_reference(self, tmp_path: Path) -> None:
        creds = tmp_path / "k8s-creds"
        creds.mkdir()
        legacy = _legacy_dir(creds, "prod")

        assert remove_legacy_credential_dirs(creds, [tmp_path / "absent.yaml"]) == [legacy]


class TestCleanupFailures:
    """Removal failures and skipped passes are returned, not only logged."""

    def test_a_gc_removal_failure_is_listed_without_exception_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cas = tmp_path / "ca"
        a = _ca_file(cas, "a", b"1")
        b = _ca_file(cas, "b", b"2")
        config = tmp_path / "config.yaml"
        config.write_text("port: 8443\n")
        real_unlink = Path.unlink

        def _flaky(self: Path, *args: object, **kwargs: object) -> None:
            if self == a:
                raise PermissionError("secret-exception-text")
            real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "unlink", _flaky)

        result = collect_garbage(cas, [config])

        assert result == [b]
        [failure] = result.failures
        assert a.name in failure and "PermissionError" in failure
        assert "secret-exception-text" not in failure

    def test_a_clean_gc_has_no_failures(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        _ca_file(cas, "a", b"1")
        config = tmp_path / "config.yaml"
        config.write_text("port: 8443\n")

        assert collect_garbage(cas, [config]).failures == []

    def test_gc_skipped_for_an_unreadable_config_is_a_failure(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        copy = _ca_file(cas, "corp", b"v1")
        unreadable = tmp_path / "config.yaml"
        unreadable.mkdir()

        result = collect_garbage(cas, [unreadable])

        assert result == []
        assert copy.is_file()
        [failure] = result.failures
        assert "skipped" in failure and "config.yaml" in failure

    def test_gc_with_no_readable_config_is_a_failure(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        _ca_file(cas, "corp", b"v1")

        result = collect_garbage(cas, [tmp_path / "config.yaml"])

        assert result == []
        assert len(result.failures) == 1

    def test_gc_skipped_for_an_unparseable_config_removes_nothing(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        copy = _ca_file(cas, "corp", b"v1")
        config = tmp_path / "config.yaml"
        config.write_text("file: [unterminated\n")

        result = collect_garbage(cas, [config])

        assert result == []
        assert copy.is_file()
        assert "not parseable" in result.failures[0]

    def test_a_long_data_dir_path_with_spaces_that_yaml_folds_is_still_referenced(
        self, tmp_path: Path
    ) -> None:
        cas = tmp_path / ("a long data directory name with spaces " * 3).strip() / "upstream-ca"
        keep = _ca_file(cas, "corp", b"v2")
        drop = _ca_file(cas, "corp", b"v1")
        config = tmp_path / "config.yaml"
        text = yaml.safe_dump({"upstreamTrustedCABundles": [{"file": keep.as_posix()}]})
        config.write_text(text, encoding="utf-8")
        assert keep.as_posix() not in text, "the fixture must exercise YAML folding"

        result = collect_garbage(cas, [config])

        assert result == [drop]
        assert keep.is_file()

    def test_a_path_only_in_a_comment_is_not_a_reference(self, tmp_path: Path) -> None:
        cas = tmp_path / "ca"
        copy = _ca_file(cas, "corp", b"v1")
        config = tmp_path / "config.yaml"
        config.write_text(f"# {copy.as_posix()}\nport: 8443\n")

        assert collect_garbage(cas, [config]) == [copy]

    def test_legacy_cleanup_lists_a_failed_removal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad = _legacy_dir(tmp_path, "a-bad")
        _legacy_dir(tmp_path, "b-good")
        real_rmdir = os.rmdir

        def _flaky(path: str | os.PathLike[str], *args: object, **kwargs: object) -> None:
            if Path(path) == bad:
                raise PermissionError("secret-exception-text")
            real_rmdir(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "rmdir", _flaky)

        result = remove_legacy_credential_dirs(tmp_path, [])

        [failure] = result.failures
        assert "a-bad" in failure and "PermissionError" in failure
        assert "secret-exception-text" not in failure

    def test_legacy_cleanup_skipped_for_an_unreadable_config_is_a_failure(
        self, tmp_path: Path
    ) -> None:
        creds = tmp_path / "k8s-creds"
        creds.mkdir()
        _legacy_dir(creds, "prod")
        unreadable = tmp_path / "config.yaml"
        unreadable.mkdir()

        result = remove_legacy_credential_dirs(creds, [unreadable])

        assert result == []
        assert "skipped" in result.failures[0]

    def test_a_folded_reference_keeps_a_legacy_directory(self, tmp_path: Path) -> None:
        creds = tmp_path / ("a long data directory name with spaces " * 3).strip() / "k8s-creds"
        held = _legacy_dir(creds, "prod")
        config = tmp_path / "config.yaml"
        text = yaml.safe_dump({"bearerTokenFile": (held / "token").as_posix()})
        config.write_text(text, encoding="utf-8")
        assert (held / "token").as_posix() not in text, "the fixture must exercise YAML folding"

        assert remove_legacy_credential_dirs(creds, [config]) == []
        assert (held / "token").is_file()
