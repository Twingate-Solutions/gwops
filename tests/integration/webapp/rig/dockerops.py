"""Thin async wrapper over the docker CLI for the rig; never receives or logs a secret."""

import asyncio
import contextlib
import json
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from . import guards, seedgen
from .curlparse import CurlResult, parse_curl_output
from .diagnose import since_arg
from .redact import RunLog

SKEW_MARKER = "token used before issued"
SKEW_WINDOW_MARGIN = timedelta(seconds=2)
COMPOSE_FILE = Path(__file__).resolve().parents[1] / "compose.rig.yaml"
_ABSENT_MARKERS = ("no such object", "no such container")
DEFAULT_COMMAND_TIMEOUT = 180.0
_EXEC_FAILURE_CODES = frozenset({125, 126, 127})
GATORCAST_BUILD_TAG = "gwops-it-gatorcast:local"
GATORCAST_BUILD_TIMEOUT = 900.0
_BUILD_SKIP = shutil.ignore_patterns(
    ".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", "*.pyc"
)


class DockerError(Exception):
    """A docker command failed or timed out; the message holds the command and stderr tail."""


@dataclass(frozen=True)
class CommandResult:
    """Exit code and decoded output of one command."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[Sequence[str], Mapping[str, str], float], Awaitable[CommandResult]]


async def subprocess_runner(
    argv: Sequence[str], env: Mapping[str, str], timeout: float
) -> CommandResult:
    """Run `argv` with exactly `env`; kill it on timeout."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        env=dict(env),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise DockerError(f"timed out after {timeout:.0f}s: {' '.join(argv[:4])}") from None
    return CommandResult(
        process.returncode if process.returncode is not None else -1,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


@dataclass(frozen=True)
class LocalEngine:
    """The active docker context, its endpoint and the gwops image id; for the run log."""

    context: str
    endpoint: str
    image_id: str = ""


async def _docker_output(runner: Runner, env: Mapping[str, str], *args: str) -> str:
    try:
        result = await runner(["docker", *args], env, 60)
    except (OSError, DockerError) as exc:
        raise guards.GuardError(f"docker is not usable: {type(exc).__name__}") from None
    if result.returncode != 0:
        raise guards.GuardError(f"docker {' '.join(args[:3])} failed (exit {result.returncode}).")
    return result.stdout.strip()


async def require_local_engine(
    *, runner: Runner | None = None, environ: Mapping[str, str] | None = None
) -> LocalEngine:
    """Refuse a remote engine: DOCKER_HOST set, or an active context that is not a local socket."""
    runner = runner or subprocess_runner
    env = seedgen.sanitized_child_env(os.environ if environ is None else environ)
    context = await _docker_output(runner, env, "context", "show")
    endpoint = await _docker_output(
        runner, env, "context", "inspect", "-f", "{{.Endpoints.docker.Host}}", context
    )
    guards.require_local_docker(env.get("DOCKER_HOST"), endpoint)
    return LocalEngine(context, endpoint)


async def local_image_id(
    image: str, *, runner: Runner | None = None, environ: Mapping[str, str] | None = None
) -> str:
    """The local image's id; GuardError when the image is not present locally."""
    runner = runner or subprocess_runner
    env = seedgen.sanitized_child_env(os.environ if environ is None else environ)
    try:
        result = await runner(["docker", "image", "inspect", "-f", "{{.Id}}", image], env, 60)
    except (OSError, DockerError) as exc:
        raise guards.GuardError(f"docker is not usable: {type(exc).__name__}") from None
    if result.returncode != 0 or not result.stdout.strip():
        raise guards.GuardError(f"local image {image!r} not found; run `make image` first")
    return result.stdout.strip()


async def build_local_gatorcast(
    source: Path,
    *,
    tag: str = GATORCAST_BUILD_TAG,
    runner: Runner | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Build `tag` from a copy of the Gatorcast tree at `source`; the source is only read."""
    runner = runner or subprocess_runner
    env = seedgen.sanitized_child_env(os.environ if environ is None else environ)
    source = source.resolve()
    if not (source / "Dockerfile").is_file():
        raise guards.GuardError(f"--gatorcast-build: no Dockerfile in {source}")
    with tempfile.TemporaryDirectory(prefix="gwops-it-gc-", ignore_cleanup_errors=True) as tmp:
        context = Path(tmp) / "context"
        await asyncio.to_thread(
            shutil.copytree, source, context, symlinks=True, ignore=_BUILD_SKIP
        )
        try:
            result = await runner(
                ["docker", "build", "-q", "-t", tag, str(context)], env, GATORCAST_BUILD_TIMEOUT
            )
        except (OSError, DockerError) as exc:
            raise guards.GuardError(f"docker build failed: {type(exc).__name__}") from None
    if result.returncode != 0:
        tail = result.stderr.strip()[-400:]
        raise guards.GuardError(
            f"docker build of {source} failed (exit {result.returncode}): {tail}"
        )
    return tag


class Docker:
    """docker and docker compose calls for one project; commands are logged, outputs are not."""

    def __init__(
        self,
        log: RunLog,
        names: seedgen.RigNames,
        compose_file: Path,
        compose_env: Mapping[str, str],
        *,
        runner: Runner | None = None,
        base_env: Mapping[str, str] | None = None,
    ) -> None:
        """Bind a project; the child environment drops every IT_* variable."""
        self._log = log
        self._names = names
        self._compose_file = compose_file
        self._runner = runner or subprocess_runner
        self._base_env = seedgen.sanitized_child_env(os.environ if base_env is None else base_env)
        self._compose_env = dict(compose_env)
        run_dir = self._compose_env.get("RIG_RUN_DIR")
        self._run_dir = Path(run_dir) if run_dir else None

    @property
    def gwops_container(self) -> str:
        """The gwops container name."""
        return f"{self._names.project}-gwops"

    def container(self, service: str) -> str:
        """The container name of a compose service."""
        return f"{self._names.project}-{service}"

    def set_compose_var(self, name: str, value: str) -> None:
        """Set one compose interpolation variable for later compose calls."""
        self._compose_env[name] = value

    async def run(
        self, *args: str, timeout: float = DEFAULT_COMMAND_TIMEOUT, check: bool = True
    ) -> CommandResult:
        """Run `docker <args>`; raise DockerError on a non-zero exit when `check`."""
        argv = ["docker", *args]
        shown = [a if len(a) <= 80 else a[:77] + "..." for a in args[:6]]
        self._log.event("docker", cmd=" ".join(shown))
        result = await self._runner(argv, self._base_env, timeout)
        if check and result.returncode != 0:
            tail = self._log.redactor.redact(result.stderr.strip()[-500:])
            raise DockerError(f"docker {' '.join(args[:4])} exited {result.returncode}: {tail}")
        return result

    async def compose(
        self,
        *args: str,
        profile: str | Sequence[str] | None = None,
        timeout: float = 600.0,
    ) -> CommandResult:
        """Run `docker compose -p <project> -f <file> [--profile p ...] <args>`."""
        base = ["compose", "-p", self._names.project, "-f", str(self._compose_file)]
        profiles = [profile] if isinstance(profile, str) else list(profile or ())
        for name in profiles:
            base += ["--profile", name]
        argv = ["docker", *base, *args]
        self._log.event("docker", cmd=" ".join([*base[:1], *args[:6]]))
        env = {**self._base_env, **self._compose_env}
        result = await self._runner(argv, env, timeout)
        if result.returncode != 0:
            tail = self._log.redactor.redact(result.stderr.strip()[-800:])
            raise DockerError(
                f"docker compose {' '.join(args[:3])} exited {result.returncode}: {tail}"
            )
        return result

    async def hup_gwops(self) -> None:
        """SIGHUP the gwops container (PID 1: a reconcile). Never signals the gateway binary."""
        await self.run("kill", "-s", "HUP", self.gwops_container, timeout=30)

    @contextlib.contextmanager
    def _env_placeholders(self) -> Iterator[None]:
        """Create any missing env file empty (compose parses them) and remove what was created."""
        created: list[Path] = []
        if self._run_dir is not None:
            for name in seedgen.ENV_FILES:
                path = self._run_dir / name
                if not path.exists():
                    path.touch(mode=0o600)
                    created.append(path)
        try:
            yield
        finally:
            for path in created:
                with contextlib.suppress(OSError):
                    path.unlink()

    async def container_state(self, container: str) -> str:
        """`running`, `stopped` or `absent`; any other inspect failure raises DockerError."""
        result = await self.run(
            "inspect", "-f", "{{.State.Running}}", container, timeout=30, check=False
        )
        if result.returncode == 0:
            return "running" if result.stdout.strip() == "true" else "stopped"
        if any(marker in result.stderr.lower() for marker in _ABSENT_MARKERS):
            return "absent"
        raise DockerError(f"cannot inspect {container}: {result.stderr.strip()[-200:]}")

    async def restart(self, container: str) -> None:
        """`docker restart` one container (a short stop timeout; raises DockerError on failure)."""
        await self.run("restart", "-t", "10", container, timeout=120)

    async def _interfaces(self, container: str) -> set[str] | None:
        """Network interface names seen inside `container`, or None when it cannot tell."""
        result = await self.run("exec", container, "cat", "/proc/net/dev", timeout=30, check=False)
        if result.returncode != 0:
            return None
        names = {
            line.partition(":")[0].strip() for line in result.stdout.splitlines() if ":" in line
        }
        return {name for name in names if name}

    async def curl_shares_client_netns(self) -> bool:
        """Whether curl still shares the client's network namespace (mode and interfaces)."""
        client, curl = self.container("client"), self.container("curl")
        client_id = (await self.run("inspect", "-f", "{{.Id}}", client, timeout=30)).stdout.strip()
        mode = (
            await self.run("inspect", "-f", "{{.HostConfig.NetworkMode}}", curl, timeout=30)
        ).stdout.strip()
        if not client_id or mode != f"container:{client_id}":
            return False
        client_interfaces = await self._interfaces(client)
        curl_interfaces = await self._interfaces(curl)
        if client_interfaces is None or curl_interfaces is None:
            return True
        return client_interfaces == curl_interfaces

    async def may_be_running(self, container: str) -> bool:
        """Fail closed: True unless the container is confirmed stopped or absent."""
        try:
            return await self.container_state(container) == "running"
        except DockerError:
            return True

    async def stop_gwops(self) -> bool:
        """Stop gwops (compose stop, then `docker rm -f`); True once confirmed not running."""
        name = self.gwops_container
        try:
            with self._env_placeholders():
                await self.compose("stop", "-t", "30", "gwops", timeout=90)
        except DockerError as exc:
            self._log.event("stop-failed", error=str(exc)[:200])
        if not await self.may_be_running(name):
            return True
        await self.run("rm", "-f", name, timeout=60, check=False)
        return not await self.may_be_running(name)

    async def down_stack(self) -> None:
        """`compose down -v`; secret env files are emptied first, then deleted with the keys."""
        paths = [self._run_dir / n for n in seedgen.ENV_FILES] if self._run_dir else []
        for path in paths:
            if path.exists():
                path.write_text("", encoding="utf-8")
            else:
                path.touch(mode=0o600)
        try:
            await self.compose(
                "down",
                "-v",
                "--remove-orphans",
                "--timeout",
                "20",
                profile=("stage2", seedgen.PROFILE_GATORCAST, seedgen.PROFILE_SSH),
            )
        finally:
            with contextlib.suppress(DockerError, OSError):
                await self.run("rm", "-f", self.container("ssh-client"), timeout=60, check=False)
            for path in paths:
                with contextlib.suppress(OSError):
                    path.unlink()
            self._remove_leaf_keys()

    def _remove_leaf_keys(self) -> None:
        """Delete the throwaway pki/*.key files and the admin token file."""
        if self._run_dir is None:
            return
        for path in (
            *(self._run_dir / "pki").glob("*.key"),
            self._run_dir / seedgen.ADMIN_TOKEN_FILE,
        ):
            with contextlib.suppress(OSError):
                path.unlink()

    async def logs(
        self, container: str, *, tail: int | None = None, since: str | None = None
    ) -> str:
        """stdout and stderr of `container`; "" if absent, DockerError on any other failure."""
        args = ["logs"]
        args += [f"--tail={tail}"] if tail else []
        args += ["--since", since] if since else []
        args.append(container)
        result = await self.run(*args, timeout=60, check=False)
        if result.returncode != 0:
            if any(marker in result.stderr.lower() for marker in _ABSENT_MARKERS):
                return ""
            raise DockerError(f"docker logs {container} exited {result.returncode}")
        return result.stdout + result.stderr

    async def exec_python(
        self, container: str, script: str, *args: str, timeout: float = 60.0
    ) -> str:
        """Run `python -c script args` in `container`; returns stdout, DockerError on failure."""
        result = await self.run("exec", container, "python", "-c", script, *args, timeout=timeout)
        return result.stdout

    async def build_image(self, tag: str, context: Path) -> None:
        """`docker build -t tag context`."""
        await self.run("build", "-q", "-t", tag, str(context), timeout=600, check=True)

    async def run_in_client_netns(
        self, image: str, script: str, *, timeout: float
    ) -> CommandResult:
        """`sh -c script` in a throwaway hardened container sharing the Client's namespace."""
        argv = [
            "run", "--rm", "--name", self.container("ssh-client"),
            "--network", f"container:{self.container('client')}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--read-only", "--tmpfs", "/tmp", "--memory", "128m", "--pids-limit", "64",
            image, "sh", "-c", script,
        ]  # fmt: skip
        return await self.run(*argv, timeout=timeout, check=False)

    async def copy_from(self, container: str, source: str, destination: Path) -> None:
        """`docker cp` a file out of a container."""
        await self.run("cp", f"{container}:{source}", str(destination), timeout=60)

    async def curl(
        self,
        url: str,
        *,
        cacert: bool = False,
        headers: Sequence[str] = (),
        max_time: int = 25,
        verbose: bool = False,
    ) -> CurlResult:
        """One fresh curl process in the client's namespace; no secret ever goes on its argv.

        `verbose` swaps `-i` for `-v` (the exchange lands in the result's `stderr`).
        """
        mode = "-v" if verbose else "-i"
        args = ["exec", self.container("curl"), "curl", "-sS", mode, "--max-time", str(max_time)]
        if cacert:
            args += ["--cacert", "/trust/gwops-ca.pem"]
        for header in headers:
            args += ["-H", header]
        args.append(url)
        result = await self.run(*args, timeout=max_time + 30, check=False)
        if result.returncode in _EXEC_FAILURE_CODES:
            raise DockerError(f"docker exec failed ({result.returncode}): {result.stderr[-300:]}")
        return parse_curl_output(result.returncode, result.stdout, result.stderr.strip())

    async def skew_evidence(self, since: datetime) -> list[str]:
        """gwops log lines stamped at or after `since` that report a token used before issued."""
        text = await self.logs(self.gwops_container, since=since_arg(since))
        floor = since - SKEW_WINDOW_MARGIN
        evidence: list[str] = []
        for line in text.splitlines():
            if SKEW_MARKER not in line.lower():
                continue
            try:
                document = json.loads(line)
                stamp = datetime.fromisoformat(str(document["timestamp"]))
            except (ValueError, KeyError, TypeError):
                continue
            if stamp >= floor:
                evidence.append(line)
        return evidence
