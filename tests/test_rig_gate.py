"""Offline tests for the rig's readiness gate and the SSH retry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.integration.webapp.rig import checks as checks_module
from tests.integration.webapp.rig import gatorcast
from tests.integration.webapp.rig.checks import RigContext
from tests.integration.webapp.rig.dockerops import CommandResult
from tests.integration.webapp.rig.results import CheckFailed, ResultBook
from tests.test_rig_run import NAMES


class FakeCurl:
    """The CurlResult surface the gate and 6b read."""

    def __init__(self, status: int | None, exit_code: int = 0) -> None:
        self.status, self.exit_code = status, exit_code

    def line(self) -> str:
        return f"exit={self.exit_code} status={self.status}"

    def seen_headers(self) -> dict[str, list[str]]:
        return {"x-forwarded-proto": ["https"]}


class FakeHttp:
    """Scripted per-url replies; the last reply repeats."""

    def __init__(self, script: dict[str, list[FakeCurl]]) -> None:
        self.script = script
        self.calls: list[str] = []
        self.waited: list[tuple[str, int, bool]] = []

    async def get(self, url: str, *, cacert: bool = False, **_kw: Any) -> FakeCurl:
        self.calls.append(url)
        replies = self.script.get(url, [FakeCurl(200)])
        return replies.pop(0) if len(replies) > 1 else replies[0]

    async def wait_for(
        self, url: str, want: int, *, cacert: bool = False, **_kw: Any
    ) -> FakeCurl:
        self.waited.append((url, want, cacert))
        return FakeCurl(want)


class FakeLog:
    """Collects events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def event(self, name: str, /, **fields: Any) -> None:
        self.events.append((name, fields))


def _checks(http: Any) -> checks_module.Checks:
    ctx = RigContext(NAMES, None, None, None, http, ResultBook(), FakeLog(), None)  # type: ignore[arg-type]
    return checks_module.Checks(ctx)


def test_the_gate_covers_every_asserted_host() -> None:
    targets = {label: (url, cacert) for label, url, cacert in _checks(None).ready_targets()}
    assert set(targets) == {"plain", "tls", "alias", "vca", "wrongfull", "verifier-a", "verifier-b"}
    assert targets["tls"] == (f"https://{NAMES.tls_host}/", True)
    assert targets["alias"][1] is True and targets["plain"][1] is False


async def test_the_gate_waits_through_resets_and_records_each_hosts_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(checks_module, "READY_POLL_SECONDS", 0.0)
    tls, vca = f"https://{NAMES.tls_host}/", f"http://{NAMES.vca_host}/"
    http = FakeHttp(
        {
            tls: [FakeCurl(None, 35), FakeCurl(None, 56), FakeCurl(502)],
            vca: [FakeCurl(None, 35), FakeCurl(None, 60)],
        }
    )
    checks = _checks(http)
    await checks.wait_hosts_ready()
    assert http.calls.count(tls) == 3 and http.calls.count(vca) == 2
    metrics = checks.c.book.metrics
    assert {f"ready_{label}_s" for label, _u, _c in checks.ready_targets()} == set(metrics)
    assert all(v.isdigit() for v in metrics.values())


async def test_a_host_that_never_routes_is_recorded_and_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(checks_module, "READY_POLL_SECONDS", 0.0)
    url = f"http://{NAMES.plain_host}/"
    checks = _checks(FakeHttp({url: [FakeCurl(None, 35)]}))
    assert await checks.wait_host_ready("plain", url, False, 0.0) is None
    assert checks.c.book.metrics["ready_plain_s"] == "not ready in 0s"


async def test_assertion_6b_polls_instead_of_a_single_shot() -> None:
    http = FakeHttp({})
    await _checks(http).tls13_trusted()
    assert http.waited == [(f"https://{NAMES.tls_host}/", 200, True)]
    assert http.calls == []


@pytest.mark.parametrize(
    ("code", "text", "retry"),
    [
        (255, "kex_exchange_identification: Connection reset by peer", True),
        (255, "Connection reset by 10.0.0.1 port 22", True),
        (255, "client_loop: send disconnect: Connection reset", False),
        (255, "Permission denied", False),
        (1, "kex_exchange_identification: read: Connection reset", False),
    ],
)
def test_only_a_pre_session_connection_reset_is_retried(code: int, text: str, retry: bool) -> None:
    assert gatorcast.ssh_retryable(code, text) is retry


class FakeDocker:
    """Replays command results; the last one repeats."""

    def __init__(self, replies: list[CommandResult]) -> None:
        self.replies = replies
        self.calls: list[str] = []

    async def run_in_client_netns(
        self, _image: str, script: str, *, timeout: float
    ) -> CommandResult:
        self.calls.append(script)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def _evidence(tmp_path: Path, docker: FakeDocker) -> gatorcast.GatorcastEvidence:
    ctx = RigContext(NAMES, docker, None, None, None, ResultBook(), FakeLog(), None)  # type: ignore[arg-type]
    evidence = gatorcast.GatorcastEvidence(ctx, tmp_path / "t.jsonl", ssh_ready=lambda: None)

    async def no_drain() -> None:
        return None

    evidence.drain = no_drain  # type: ignore[method-assign]
    return evidence


RESET = CommandResult(255, "kex_exchange_identification: Connection reset by peer", "")


async def test_ssh_retries_a_reset_up_to_four_times_then_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gatorcast, "SSH_RETRY_SECONDS", 0.0)
    docker = FakeDocker([RESET])
    evidence = _evidence(tmp_path, docker)
    with pytest.raises(CheckFailed, match="after 4 attempt"):
        await evidence.recording_ssh()
    assert len(docker.calls) == 4
    assert evidence.c.book.metrics["ssh_attempts"] == "4"


async def test_ssh_does_not_retry_other_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gatorcast, "SSH_RETRY_SECONDS", 0.0)
    docker = FakeDocker([CommandResult(255, "Permission denied", "")])
    with pytest.raises(CheckFailed, match="after 1 attempt"):
        await _evidence(tmp_path, docker).recording_ssh()
    assert len(docker.calls) == 1


async def test_ssh_continues_after_a_retried_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gatorcast, "SSH_RETRY_SECONDS", 0.0)
    monkeypatch.setattr(gatorcast, "DRAIN_TIMEOUT", 0.0)

    class Echoing(FakeDocker):
        async def run_in_client_netns(
            self, image: str, script: str, *, timeout: float
        ) -> CommandResult:
            await super().run_in_client_netns(image, script, timeout=timeout)
            if len(self.calls) == 1:
                return RESET
            token = script.split("DONE ")[1].split(";")[0]
            return CommandResult(0, f"RIG-SSH-DONE-{token}", "")

    docker = Echoing([RESET])
    evidence = _evidence(tmp_path, docker)
    with pytest.raises(CheckFailed, match="no recording line"):
        await evidence.recording_ssh()
    assert len(docker.calls) == 2 and evidence.c.book.metrics["ssh_attempts"] == "2"


async def test_the_ssh_gate_polls_a_banner_read_until_it_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gatorcast, "SSH_READY_POLL", 0.0)
    fail, ok = CommandResult(1, "", ""), CommandResult(0, "", "")
    docker = FakeDocker([fail, fail, ok])
    ctx = RigContext(NAMES, docker, None, None, None, ResultBook(), FakeLog(), None)  # type: ignore[arg-type]
    assert await gatorcast.wait_ssh_ready(ctx) is not None
    assert len(docker.calls) == 3
    assert NAMES.ssh_host in docker.calls[0] and "SSH-" in docker.calls[0]
    assert ctx.book.metrics["ready_ssh_s"].isdigit()
