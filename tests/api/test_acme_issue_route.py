"""POST /certs/public/{name}/issue: auth, body, every status code, audit, no token leak.

The runner is a stub (`StubAcmeRunner`): the route's job is to map the runner's
`IssueOutcome` and its own pre-checks to HTTP, so each row below picks the outcome. The DNS
token file check (`token_file_problem`) runs for real against a file under `tmp_path`, holding
a sentinel value that must never appear in a response or a log line.
"""

import dataclasses
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import structlog.testing
from fastapi import HTTPException

from gwops.acme import token as token_module
from gwops.acme.runner import IssueOutcome, IssueStatus
from gwops.acme.token import token_file_problem
from gwops.api import routes_actions
from gwops.api.app import create_app
from gwops.api.routes_actions import issue_public_cert
from tests.public_tls_support import ZONE

from .acme_support import (
    ACME_CERT,
    AUTOMATION_TOKEN,
    FILE_CERT,
    StubAcmeRunner,
    acme_bundle,
)
from .conftest import ADMIN_TOKEN, SEED, DepsBundle

SENTINEL = "cfut_SENTINEL-must-never-be-logged-0123456789abcdef"
URL = f"/certs/public/{ACME_CERT}/issue"

Logs = list[dict[str, Any]]


def _point_token_file_at(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Run the real `token_file_problem` against `path` instead of /config/acme/...

    The check requires the resolved file to sit under the ACME mount root, so the root is
    moved to the file's directory for the test.
    """
    monkeypatch.setattr(token_module, "ACME_ROOT", path.parent)

    def check(settings: Any) -> str | None:
        return token_file_problem(settings.model_copy(update={"token_file": str(path)}))

    monkeypatch.setattr(routes_actions, "token_file_problem", check)


@pytest.fixture(autouse=True)
def token_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A usable DNS token file holding the sentinel; the route's check is pointed at it."""
    path = tmp_path / "cloudflare-token"
    path.write_text(SENTINEL + "\n", encoding="utf-8")
    _point_token_file_at(monkeypatch, path)
    return path


@pytest.fixture
def runner() -> StubAcmeRunner:
    return StubAcmeRunner()


@pytest.fixture
def bundle(tmp_path: Path, runner: StubAcmeRunner) -> DepsBundle:
    return acme_bundle(tmp_path, runner)


def _client(bundle: DepsBundle, token: str | None = ADMIN_TOKEN) -> httpx.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers=headers,
    )


@pytest.fixture
async def admin(bundle: DepsBundle) -> AsyncIterator[httpx.AsyncClient]:
    async with _client(bundle) as client:
        yield client


def _events(logs: Logs, name: str) -> Logs:
    return [entry for entry in logs if entry["event"] == name]


class TestAuth:
    async def test_no_token_is_401_and_the_runner_is_not_asked(
        self, bundle: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        async with _client(bundle, None) as client:
            response = await client.post(URL)

        assert response.status_code == 401
        assert response.content == b""
        assert runner.issue_calls == []

    async def test_a_wrong_token_is_401(self, bundle: DepsBundle, runner: StubAcmeRunner) -> None:
        async with _client(bundle, "not-the-token") as client:
            response = await client.post(URL)

        assert response.status_code == 401
        assert runner.issue_calls == []

    async def test_the_automation_token_is_403_and_the_runner_is_not_asked(
        self, bundle: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        async with _client(bundle, AUTOMATION_TOKEN) as client:
            response = await client.post(URL, json={"force": True})

        assert response.status_code == 403
        assert "automation token" in response.json()["detail"]
        assert runner.issue_calls == []

    async def test_the_automation_token_learns_nothing_about_which_names_exist(
        self, bundle: DepsBundle
    ) -> None:
        async with _client(bundle, AUTOMATION_TOKEN) as client:
            known = await client.post(URL)
            unknown = await client.post("/certs/public/nope/issue")

        assert known.status_code == unknown.status_code == 403
        assert known.json() == unknown.json()

    async def test_the_route_itself_refuses_the_automation_principal(
        self, bundle: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        """Second line of defence: reached with the automation principal, the handler refuses."""
        request = SimpleNamespace(
            state=SimpleNamespace(principal="automation"),
            app=SimpleNamespace(state=SimpleNamespace(deps=bundle.deps)),
        )

        with pytest.raises(HTTPException) as caught:
            await issue_public_cert(request, ACME_CERT, None)  # type: ignore[arg-type]

        assert caught.value.status_code == 403
        assert runner.issue_calls == []

    async def test_the_admin_token_is_accepted(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        response = await admin.post(URL)

        assert response.status_code == 202
        assert runner.issue_calls == [(ACME_CERT, False)]


class TestAccepted:
    async def test_the_body_reports_the_certificate_status_force_and_detail(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.ACCEPTED, detail="issuance for 'issued' scheduled"
        )

        response = await admin.post(URL)

        assert response.status_code == 202
        assert response.json() == {
            "certificate": ACME_CERT,
            "status": "scheduled",
            "force": False,
            "detail": "issuance for 'issued' scheduled",
        }

    @pytest.mark.parametrize(
        ("kwargs", "force"),
        [
            pytest.param({}, False, id="no-body"),
            pytest.param({"json": {}}, False, id="empty-object"),
            pytest.param({"json": {"force": False}}, False, id="force-false"),
            pytest.param({"json": {"force": True}}, True, id="force-true"),
        ],
    )
    async def test_force_defaults_to_false_and_is_passed_to_the_runner(
        self,
        admin: httpx.AsyncClient,
        runner: StubAcmeRunner,
        kwargs: dict[str, Any],
        force: bool,
    ) -> None:
        response = await admin.post(URL, **kwargs)

        assert response.status_code == 202
        assert response.json()["force"] is force
        assert runner.issue_calls == [(ACME_CERT, force)]


class TestBodyValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({"json": {"force": "maybe"}}, id="force-not-a-bool"),
            pytest.param({"json": {"force": None}}, id="force-null"),
            pytest.param({"json": {"force": []}}, id="force-a-list"),
            pytest.param({"json": {"force": True, "extra": 1}}, id="unknown-key-beside-force"),
            pytest.param({"json": {"unknown": 1}}, id="unknown-key-alone"),
            pytest.param({"json": []}, id="array-body"),
            pytest.param({"json": "force"}, id="string-body"),
            pytest.param(
                {"content": b"{not json", "headers": {"Content-Type": "application/json"}},
                id="malformed-json",
            ),
        ],
    )
    async def test_an_invalid_body_is_422_and_the_runner_is_not_asked(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner, kwargs: dict[str, Any]
    ) -> None:
        response = await admin.post(URL, **kwargs)

        assert response.status_code == 422
        assert runner.issue_calls == []

    async def test_an_unknown_key_is_named_in_the_error(self, admin: httpx.AsyncClient) -> None:
        response = await admin.post(URL, json={"force": True, "dry_run": True})

        assert response.status_code == 422
        assert "dry_run" in response.text


class TestNotFound:
    async def test_a_name_that_is_not_declared_is_404(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        response = await admin.post("/certs/public/nope/issue")

        assert response.status_code == 404
        assert "nope" in response.json()["detail"]
        assert runner.issue_calls == []

    async def test_a_gateway_without_public_tls_is_404(self, tmp_path: Path) -> None:
        runner = StubAcmeRunner()
        bundle = acme_bundle(tmp_path, runner, seed=SEED)

        async with _client(bundle) as client:
            response = await client.post(URL)

        assert response.status_code == 404
        assert runner.issue_calls == []

    async def test_404_wins_over_an_absent_runner(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None)

        async with _client(bundle) as client:
            response = await client.post("/certs/public/nope/issue")

        assert response.status_code == 404


class TestConflicts:
    def test_the_unavailable_status_is_409(self) -> None:
        assert routes_actions._ACME_UNAVAILABLE_STATUS == 409

    async def test_a_source_file_certificate_is_409_and_the_runner_is_not_asked(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        response = await admin.post(f"/certs/public/{FILE_CERT}/issue")

        assert response.status_code == 409
        assert "source: file" in response.json()["detail"]
        assert runner.issue_calls == []

    async def test_source_file_is_409_even_without_a_runner(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None)

        async with _client(bundle) as client:
            response = await client.post(f"/certs/public/{FILE_CERT}/issue")

        assert response.status_code == 409
        assert "source: file" in response.json()["detail"]

    async def test_no_runner_is_409_with_the_reason(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None)

        async with _client(bundle) as client:
            response = await client.post(URL)

        assert response.status_code == 409
        assert "ACME runner is not running" in response.json()["detail"]

    async def test_a_missing_token_file_is_409_naming_the_path_only(
        self,
        admin: httpx.AsyncClient,
        runner: StubAcmeRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        missing = tmp_path / "absent-token"
        _point_token_file_at(monkeypatch, missing)

        response = await admin.post(URL)

        assert response.status_code == 409
        detail = response.json()["detail"]
        assert str(missing) in detail
        assert "does not exist" in detail
        assert SENTINEL not in response.text
        assert runner.issue_calls == []

    async def test_a_token_path_that_is_not_a_regular_file_is_409(
        self,
        admin: httpx.AsyncClient,
        runner: StubAcmeRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        directory = tmp_path / "token-dir"
        directory.mkdir()
        _point_token_file_at(monkeypatch, directory)

        response = await admin.post(URL)

        assert response.status_code == 409
        assert "not a regular file" in response.json()["detail"]
        assert runner.issue_calls == []

    async def test_issuance_already_running_is_409_with_the_runners_detail(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.ALREADY_RUNNING, detail="issuance for 'issued' is in progress"
        )

        response = await admin.post(URL)

        assert response.status_code == 409
        assert response.json()["detail"] == "issuance for 'issued' is in progress"
        assert "Retry-After" not in response.headers

    async def test_a_declared_certificate_the_runner_does_not_know_yet_is_409(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(IssueStatus.UNKNOWN_CERTIFICATE, detail="internal text")

        response = await admin.post(URL)

        assert response.status_code == 409
        detail = response.json()["detail"]
        assert ACME_CERT in detail
        assert "POST /reconcile" in detail
        assert "internal text" not in detail

    async def test_an_unavailable_runner_is_409_with_the_runners_detail(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.UNAVAILABLE,
            detail="ACME state file is unusable; issuance is refused until it is fixed",
        )

        response = await admin.post(URL)

        assert response.status_code == 409
        assert "state file is unusable" in response.json()["detail"]


class TestBackoff:
    async def test_in_backoff_is_429_with_retry_after_in_seconds(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.IN_BACKOFF,
            retry_after_seconds=900,
            detail="'issued' is in backoff until 2026-10-20T12:15:00+00:00",
        )

        response = await admin.post(URL)

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "900"
        assert response.json()["detail"] == "'issued' is in backoff until 2026-10-20T12:15:00+00:00"

    @pytest.mark.parametrize("seconds", [1, 59, 3600, 86400])
    async def test_retry_after_is_the_runners_whole_seconds(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner, seconds: int
    ) -> None:
        runner.outcome = IssueOutcome(IssueStatus.IN_BACKOFF, retry_after_seconds=seconds)

        response = await admin.post(URL)

        assert response.headers["Retry-After"] == str(seconds)

    @pytest.mark.parametrize("seconds", [None, 0])
    async def test_a_missing_or_zero_wait_is_reported_as_one_second(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner, seconds: int | None
    ) -> None:
        runner.outcome = IssueOutcome(IssueStatus.IN_BACKOFF, retry_after_seconds=seconds)

        response = await admin.post(URL)

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "1"

    async def test_force_does_not_skip_the_backoff(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        """The route forwards `force` and honours the runner's refusal: 429, not 202."""
        runner.outcome = IssueOutcome(IssueStatus.IN_BACKOFF, retry_after_seconds=120)

        response = await admin.post(URL, json={"force": True})

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "120"
        assert runner.issue_calls == [(ACME_CERT, True)]


class TestBackoffBody:
    """The 429 body is ``{detail, reason, error_code}``; ``Retry-After`` carries the seconds."""

    @pytest.mark.parametrize("reason", ["backoff", "force_window", "request_floor"])
    async def test_the_body_carries_the_runners_reason(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner, reason: str
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.IN_BACKOFF,
            retry_after_seconds=600,
            detail=f"held back ({reason})",
            reason=reason,
        )

        response = await admin.post(URL, json={"force": True})

        assert response.status_code == 429
        assert response.json() == {
            "detail": f"held back ({reason})",
            "reason": reason,
            "error_code": None,
        }
        assert response.headers["Retry-After"] == "600"
        assert response.headers["content-type"].startswith("application/json")

    @pytest.mark.parametrize("error_code", ["rate_limited", "dns_auth", "internal", None])
    async def test_the_body_carries_the_recorded_error_class_or_null(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner, error_code: str | None
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.IN_BACKOFF,
            retry_after_seconds=60,
            detail="in backoff",
            reason="backoff",
            error_code=error_code,
        )

        response = await admin.post(URL)

        assert response.json()["error_code"] == error_code

    async def test_a_runner_that_names_no_reason_gives_null_not_a_missing_key(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(IssueStatus.IN_BACKOFF, retry_after_seconds=5, detail="x")

        response = await admin.post(URL)

        assert set(response.json()) == {"detail", "reason", "error_code"}
        assert response.json()["reason"] is None

    async def test_the_reason_error_code_and_wait_are_in_the_audit_log(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner
    ) -> None:
        runner.outcome = IssueOutcome(
            IssueStatus.IN_BACKOFF,
            retry_after_seconds=3600,
            detail="a forced issue is refused",
            reason="force_window",
            error_code="rate_limited",
        )

        with structlog.testing.capture_logs() as logs:
            response = await admin.post(URL, json={"force": True})

        assert response.status_code == 429
        [issued] = _events(logs, "api.acme_issue")
        assert issued["outcome"] == "in_backoff"
        assert issued["reason"] == "force_window"
        assert issued["error_code"] == "rate_limited"
        assert [e["status"] for e in _events(logs, "api.audit")] == [429]

    @pytest.mark.parametrize("outcome_status", [IssueStatus.ACCEPTED, IssueStatus.ALREADY_RUNNING])
    async def test_only_a_429_has_the_reason_body_and_a_retry_after(
        self, admin: httpx.AsyncClient, runner: StubAcmeRunner, outcome_status: IssueStatus
    ) -> None:
        runner.outcome = IssueOutcome(outcome_status, detail="d", reason="backoff")

        response = await admin.post(URL)

        assert "reason" not in response.json()
        assert "Retry-After" not in response.headers

    async def test_the_real_runner_reasons_reach_the_body(self, tmp_path: Path) -> None:
        """A real ``AcmeRunner`` request floor: accept, then the second request inside 60 s."""
        from gwops.acme.runner import AcmeConfig, AcmeRunner
        from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings

        bundle = acme_bundle(tmp_path, None)
        real = AcmeRunner(bundle.deps.settings, store=object())  # type: ignore[arg-type]
        acme_settings = AcmeSettings.model_validate(
            {
                "email": "ops@example.com",
                "accept_tos": True,
                "directory": "staging",
                "token_file": "/config/acme/cloudflare-token",
            }
        )
        cert = AcmePublicCertificate.model_validate(
            {"name": ACME_CERT, "names": [f"*.apps.{ZONE}"], "source": "acme"}
        )
        real.configure(AcmeConfig(acme_settings, (cert,), (ZONE,)))
        bundle.deps = dataclasses.replace(bundle.deps, acme=real)

        async with _client(bundle) as client:
            first = await client.post(URL)
            second = await client.post(URL)

        assert first.status_code == 202
        assert second.status_code == 429
        body = second.json()
        assert body["reason"] == "request_floor"
        assert body["error_code"] is None
        assert 1 <= int(second.headers["Retry-After"]) <= 60


class TestRunnerUnavailableDetail:
    """The 409 for an absent runner says why it could not be built (``deps.acme_unavailable``)."""

    async def test_the_construction_failure_is_in_the_detail(self, tmp_path: Path) -> None:
        bundle = acme_bundle(
            tmp_path, None, acme_unavailable="OSError: cannot create /data/acme"
        )

        async with _client(bundle) as client:
            response = await client.post(URL)

        assert response.status_code == 409
        detail = response.json()["detail"]
        assert "ACME runner is not running" in detail
        assert "(OSError: cannot create /data/acme)" in detail
        assert "check the gwops startup log" in detail

    async def test_without_a_recorded_reason_the_detail_has_no_parenthetical(
        self, tmp_path: Path
    ) -> None:
        bundle = acme_bundle(tmp_path, None)

        async with _client(bundle) as client:
            response = await client.post(URL)

        detail = response.json()["detail"]
        assert "(" not in detail
        assert detail.endswith("check the gwops startup log")

    async def test_the_reason_is_not_offered_when_a_runner_exists(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner()
        bundle = acme_bundle(tmp_path, runner, acme_unavailable="stale text")

        async with _client(bundle) as client:
            response = await client.post(URL)

        assert response.status_code == 202
        assert "stale text" not in response.text

    async def test_the_refusal_is_still_audited_as_runner_absent(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: x")

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                await client.post(URL)

        [refused] = _events(logs, "api.acme_issue_refused")
        assert refused["reason"] == "runner_absent"
        assert refused["status"] == 409

    async def test_a_file_certificate_is_still_a_source_file_409_not_a_runner_one(
        self, tmp_path: Path
    ) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: x")

        async with _client(bundle) as client:
            response = await client.post(f"/certs/public/{FILE_CERT}/issue")

        assert "source: file" in response.json()["detail"]
        assert "OSError" not in response.text


_OUTCOME_CASES = [
    pytest.param(IssueOutcome(IssueStatus.ACCEPTED, detail="ok"), 202, id="accepted"),
    pytest.param(IssueOutcome(IssueStatus.ALREADY_RUNNING, detail="busy"), 409, id="running"),
    pytest.param(
        IssueOutcome(IssueStatus.IN_BACKOFF, retry_after_seconds=30, detail="wait"),
        429,
        id="backoff",
    ),
    pytest.param(IssueOutcome(IssueStatus.UNKNOWN_CERTIFICATE), 409, id="unknown"),
    pytest.param(IssueOutcome(IssueStatus.UNAVAILABLE, detail="down"), 409, id="unavailable"),
]


class TestAudit:
    @pytest.mark.parametrize(("outcome", "status"), _OUTCOME_CASES)
    async def test_a_runner_answer_is_audited_and_logged_with_its_outcome(
        self,
        admin: httpx.AsyncClient,
        runner: StubAcmeRunner,
        outcome: IssueOutcome,
        status: int,
    ) -> None:
        runner.outcome = outcome

        with structlog.testing.capture_logs() as logs:
            response = await admin.post(URL, json={"force": True})

        assert response.status_code == status
        [audit] = _events(logs, "api.audit")
        assert audit["principal"] == "admin"
        assert audit["method"] == "POST"
        assert audit["route"] == URL
        assert audit["status"] == status
        [issued] = _events(logs, "api.acme_issue")
        assert issued["certificate"] == ACME_CERT
        assert issued["force"] is True
        assert issued["outcome"] == outcome.status.value
        assert issued["principal"] == "admin"
        assert _events(logs, "api.acme_issue_refused") == []

    async def test_an_absent_runner_is_logged_as_a_refusal(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None)

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                response = await client.post(URL, json={"force": True})

        assert response.status_code == 409
        [refused] = _events(logs, "api.acme_issue_refused")
        assert refused["certificate"] == ACME_CERT
        assert refused["force"] is True
        assert refused["reason"] == "runner_absent"
        assert refused["status"] == 409
        assert _events(logs, "api.acme_issue") == []
        assert [e["status"] for e in _events(logs, "api.audit")] == [409]

    async def test_an_unusable_token_file_is_logged_as_a_refusal(
        self,
        admin: httpx.AsyncClient,
        runner: StubAcmeRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _point_token_file_at(monkeypatch, tmp_path / "absent-token")

        with structlog.testing.capture_logs() as logs:
            response = await admin.post(URL)

        assert response.status_code == 409
        [refused] = _events(logs, "api.acme_issue_refused")
        assert refused["reason"] == "token_file_unusable"
        assert refused["status"] == 409
        assert refused["force"] is False
        assert _events(logs, "api.acme_issue") == []
        assert runner.issue_calls == []

    @pytest.mark.parametrize(
        ("path", "status"),
        [
            pytest.param("/certs/public/nope/issue", 404, id="undeclared"),
            pytest.param(f"/certs/public/{FILE_CERT}/issue", 409, id="source-file"),
        ],
    )
    async def test_a_pre_runner_refusal_is_audited_but_not_logged_as_an_issue(
        self, admin: httpx.AsyncClient, path: str, status: int
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            response = await admin.post(path)

        assert response.status_code == status
        [audit] = _events(logs, "api.audit")
        assert audit["route"] == path
        assert audit["status"] == status
        assert _events(logs, "api.acme_issue") == []
        assert _events(logs, "api.acme_issue_refused") == []

    async def test_the_automation_token_is_audited_as_automation_with_403(
        self, bundle: DepsBundle
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            async with _client(bundle, AUTOMATION_TOKEN) as client:
                response = await client.post(URL)

        assert response.status_code == 403
        [audit] = _events(logs, "api.audit")
        assert audit["principal"] == "automation"
        assert audit["status"] == 403
        assert _events(logs, "api.acme_issue") == []

    async def test_a_request_without_a_token_is_audited_with_no_principal(
        self, bundle: DepsBundle
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            async with _client(bundle, None) as client:
                response = await client.post(URL)

        assert response.status_code == 401
        [audit] = _events(logs, "api.audit")
        assert audit["principal"] is None
        assert audit["status"] == 401

    async def test_an_invalid_body_is_audited_as_422(self, admin: httpx.AsyncClient) -> None:
        with structlog.testing.capture_logs() as logs:
            response = await admin.post(URL, json={"nope": 1})

        assert response.status_code == 422
        assert [e["status"] for e in _events(logs, "api.audit")] == [422]
        assert _events(logs, "api.acme_issue") == []


class TestNoTokenLeak:
    """The DNS token never reaches a response, a header or a log line."""

    @pytest.mark.parametrize(("outcome", "status"), _OUTCOME_CASES)
    async def test_no_runner_answer_carries_the_token_or_the_admin_token(
        self,
        admin: httpx.AsyncClient,
        runner: StubAcmeRunner,
        outcome: IssueOutcome,
        status: int,
    ) -> None:
        runner.outcome = outcome

        with structlog.testing.capture_logs() as logs:
            response = await admin.post(URL, json={"force": True})

        assert response.status_code == status
        visible = response.text + str(dict(response.headers)) + str(logs)
        assert SENTINEL not in visible
        assert ADMIN_TOKEN not in visible

    @pytest.mark.parametrize("problem", ["missing", "directory", "runner"])
    async def test_the_refusals_name_paths_never_contents(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        problem: str,
    ) -> None:
        runner: StubAcmeRunner | None = StubAcmeRunner()
        if problem == "missing":
            _point_token_file_at(monkeypatch, tmp_path / "absent-token")
        elif problem == "directory":
            _point_token_file_at(monkeypatch, tmp_path)
        else:
            runner = None
        bundle = acme_bundle(tmp_path, runner)

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                response = await client.post(URL)

        assert response.status_code == 409
        visible = response.text + str(dict(response.headers)) + str(logs)
        assert SENTINEL not in visible
        assert ADMIN_TOKEN not in visible

    async def test_the_token_file_is_examined_but_never_opened(
        self,
        admin: httpx.AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        token_file: Path,
    ) -> None:
        opened: list[str] = []
        real_open = Path.open

        def spy(self: Path, *args: Any, **kwargs: Any) -> Any:
            opened.append(str(self))
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", spy)
        monkeypatch.setattr("builtins.open", _spying_open(opened, open))

        response = await admin.post(URL)

        assert response.status_code == 202
        assert str(token_file) not in opened


def _spying_open(opened: list[str], real: Callable[..., Any]) -> Callable[..., Any]:
    def spy(file: Any, *args: Any, **kwargs: Any) -> Any:
        opened.append(str(file))
        return real(file, *args, **kwargs)

    return spy
