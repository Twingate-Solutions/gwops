"""Shared teardown: stop gwops first, record strays, sweep, re-check, then compose down."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from . import guards
from .dockerops import Docker
from .redact import RunLog
from .tenant import RigTenant, SweepError, SweepReport, recovery_command

SERVICE_ACCOUNT_ONLY = frozenset({"service_account_key", "service_account"})


@dataclass
class TeardownResult:
    """What the teardown did: gwops stopped or not, the sweep report, and every problem."""

    gwops_stopped: bool = False
    report: SweepReport | None = None
    errors: list[str] = field(default_factory=list)
    refused: str | None = None
    swept_clean: bool = False

    @property
    def ok(self) -> bool:
        """True only when gwops stopped, the sweep and inventory check passed, nothing refused."""
        return self.swept_clean and not self.errors and self.refused is None


def _describe(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


async def _stop(docker: Docker, tenant: RigTenant, log: RunLog, result: TeardownResult) -> None:
    try:
        result.gwops_stopped = await docker.stop_gwops()
    except Exception as exc:
        result.errors.append(f"stopping gwops: {_describe(exc)}")
    log.event("gwops-stopped", confirmed=result.gwops_stopped)
    if not result.gwops_stopped:
        result.errors.append(
            "gwops may still be running: only the service account was swept; after it is stopped "
            f"run: {recovery_command(tenant.state_path)}"
        )


async def _sweep(tenant: RigTenant, result: TeardownResult) -> None:
    try:
        await tenant.record_discovered()
    except Exception as exc:
        result.errors.append(f"discovery: {_describe(exc)}")
    try:
        result.report = await tenant.cleanup(
            only_kinds=None if result.gwops_stopped else SERVICE_ACCOUNT_ONLY
        )
        result.swept_clean = result.gwops_stopped
    except SweepError as exc:
        result.errors.extend(exc.errors)
        result.report = exc.report
    except guards.GuardError as exc:
        result.refused = str(exc)
        result.errors.append(f"sweep refused: {exc}")
    except Exception as exc:
        result.errors.append(f"sweep raised {_describe(exc)}")


async def stop_sweep_down(
    tenant: RigTenant,
    docker: Docker,
    log: RunLog,
    *,
    before_sweep: Callable[[], Awaitable[None]] | None = None,
) -> TeardownResult:
    """Stop gwops, record and sweep run objects, then `compose down -v`; no step skips the next."""
    result = TeardownResult()
    try:
        await _stop(docker, tenant, log, result)
        if before_sweep is not None:
            try:
                await before_sweep()
            except Exception as exc:
                log.event("log-dump-failed", error=_describe(exc)[:200])
        await _sweep(tenant, result)
    finally:
        try:
            await docker.down_stack()
        except Exception as exc:
            result.errors.append(f"compose down: {_describe(exc)}")
    return result
