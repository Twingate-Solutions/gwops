"""Offline unit tests for the live rig's pure pieces; no tenant, no docker, no network."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from gwops.configmodel.schema import SeedConfig
from gwops.renderer.sans import required_sans
from tests.integration.webapp import run
from tests.integration.webapp.rig import (
    checks,
    diagnose,
    dockerops,
    guards,
    logfilter,
    pki,
    seedgen,
    teardown,
    tenant,
)
from tests.integration.webapp.rig.admin import AdminClient, AdminError
from tests.integration.webapp.rig.curlparse import CurlResult, parse_curl_output
from tests.integration.webapp.rig.dockerops import CommandResult, Docker, DockerError
from tests.integration.webapp.rig.redact import (
    REDACTED,
    Redactor,
    RunLog,
    secret_values_from_env_text,
)
from tests.integration.webapp.rig.results import (
    CheckFailed,
    CheckFinding,
    Outcome,
    ResultBook,
)

RUN_ID = "abc12345"
NAMES = seedgen.build_names(RUN_ID)
API_KEY = "tgk_SECRET-key-0123456789abcdef"
NETWORK = "acme"
REMOTE_NETWORK_ID = "UmVtb3RlTmV0d29yazox"
ADMIN_TOKEN = "admin-token-ZZZZ-9999999999"
GAT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4eCJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
COMPOSE_FILE = Path(run.__file__).resolve().parent / "compose.rig.yaml"
REPO_ROOT = Path(__file__).resolve().parents[1]


def approved_env() -> guards.RigEnv:
    """A rig environment the operator has approved for NETWORK / REMOTE_NETWORK_ID."""
    return guards.RigEnv(
        API_KEY, NETWORK, REMOTE_NETWORK_ID, approved_network=NETWORK,
        approved_remote_network_id=REMOTE_NETWORK_ID,
    )


# --- redaction -------------------------------------------------------------------------------


def test_redactor_masks_registered_secrets_everywhere() -> None:
    redactor = Redactor([API_KEY, ADMIN_TOKEN])
    out = redactor.redact(f"key={API_KEY} and {ADMIN_TOKEN} again {API_KEY}")
    assert API_KEY not in out
    assert ADMIN_TOKEN not in out
    assert out.count(REDACTED) >= 3


def test_redactor_masks_each_line_of_a_multiline_secret() -> None:
    redactor = Redactor(["first-secret-line\nsecond-secret-line"])
    out = redactor.redact("a first-secret-line b second-secret-line c")
    assert "secret-line" not in out


def test_redactor_ignores_trivially_short_values() -> None:
    redactor = Redactor(["ab"])
    assert redactor.redact("about abc") == "about abc"


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: Bearer {GAT}",
        f"authorization: {GAT}",
        f'{{"authorization": "Bearer {GAT}"}}',
        f"curl -H 'X-Debug: Bearer {GAT}'",
        f"token {GAT}",
        "TWINGATE_ACCESS_TOKEN=abcdefghijk",
        "TWINGATE_SERVICE_KEY={'x': 1}",
        '{"refreshToken": "abcdefghijk"}',
        '{"privateKey": "abcdefghijk"}',
        "X-API-KEY: abcdefghijk",
    ],
)
def test_redactor_masks_credential_shaped_text(text: str) -> None:
    out = Redactor().redact(text)
    assert "abcdefghijk" not in out
    assert GAT not in out
    assert "eyJ" not in out


def test_redactor_masks_pem_private_keys() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----"
    out = Redactor().redact(f"before\n{pem}\nafter")
    assert "MIGHAg" not in out
    assert "before" in out
    assert "after" in out


def test_redactor_keeps_benign_log_text() -> None:
    line = "curl url=http://echo-plain.x.rig.test/ result=exit=0 status=200 jti claims typ GAT"
    assert Redactor().redact(line) == line


def test_run_log_redacts_file_and_console(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "run.log"
    log = RunLog(path, Redactor([API_KEY]))
    log.add_secret(ADMIN_TOKEN)
    log.event("probe", key=API_KEY, header=f"Authorization: Bearer {GAT}")
    log.block("tail", f"line one {ADMIN_TOKEN}\nline two")
    written = path.read_text(encoding="utf-8")
    shown = capsys.readouterr().out
    for text in (written, shown):
        assert API_KEY not in text
        assert ADMIN_TOKEN not in text
        assert GAT not in text
    assert "line two" in written


# --- seed rendering --------------------------------------------------------------------------


def _seed(*, phase_two: bool) -> dict[str, Any]:
    text = seedgen.render_seed(
        NAMES,
        network=NETWORK,
        remote_network_id=REMOTE_NETWORK_ID,
        with_bundle=phase_two,
        allow_insecure_host=phase_two,
    )
    document = yaml.safe_load(text)
    assert isinstance(document, dict)
    return document


@pytest.mark.parametrize("phase_two", [False, True])
def test_rig_seed_validates_against_the_gwops_schema(phase_two: bool) -> None:
    seed = SeedConfig.model_validate(_seed(phase_two=phase_two))
    assert seed.twingate.gateway_id is None
    assert seed.twingate.gateway_address == NAMES.gateway_address
    assert seed.twingate.remote_network_id == REMOTE_NETWORK_ID
    assert seed.web_app_proxy.upstream_tls_probe is True


def test_rig_seed_is_mode_b_with_a_per_run_gateway_address() -> None:
    other = seedgen.build_names("def67890")
    assert other.gateway_address != NAMES.gateway_address
    assert NAMES.gateway_address.startswith(NAMES.prefix)
    assert NAMES.gateway_address.endswith(":8443")


def test_rig_seed_names_every_app_with_the_run_prefix() -> None:
    names = [app["name"] for app in _seed(phase_two=False)["web_apps"]]
    assert sorted(names) == sorted(f"{NAMES.prefix}{s}" for s in seedgen.APP_SUFFIXES)


def test_rig_seed_phase_one_has_no_bundle_and_no_insecure_allowlist() -> None:
    proxy = _seed(phase_two=False)["web_app_proxy"]
    assert "upstream_ca_bundles" not in proxy
    assert proxy["plaintext_upstreams"]["dns_suffixes"] == [NAMES.plain_host]


def test_rig_seed_phase_two_lists_the_bundle_and_allowlists_insecure() -> None:
    proxy = _seed(phase_two=True)["web_app_proxy"]
    assert proxy["upstream_ca_bundles"] == [
        {"name": seedgen.BUNDLE_NAME, "file": seedgen.BUNDLE_FILE}
    ]
    assert proxy["plaintext_upstreams"]["dns_suffixes"] == [NAMES.plain_host, NAMES.insecure_host]


def test_rig_seed_trusted_identity_header_is_gateway_wide() -> None:
    proxy = _seed(phase_two=False)["web_app_proxy"]
    assert proxy["request_headers"] == {"X-Twingate-User": "{{username}}"}
    for app in _seed(phase_two=False)["web_apps"]:
        assert "X-Twingate-User" not in app.get("request_headers", {})


def test_rig_seed_never_carries_a_secret_or_existing_object_reference() -> None:
    text = seedgen.render_seed(
        NAMES,
        network=NETWORK,
        remote_network_id=REMOTE_NETWORK_ID,
        with_bundle=True,
        allow_insecure_host=True,
    )
    for word in ("access", "security_policy", "securityPolicy", "gateway_id", "token", "api_key"):
        assert word not in text


def test_rig_seed_leaf_sans_cover_every_client_facing_name() -> None:
    state = SeedConfig.model_validate(_seed(phase_two=False))
    sans = required_sans(state)  # type: ignore[arg-type]
    assert {NAMES.plain_host, NAMES.tls_host, NAMES.alias_host} <= sans


def test_insecure_app_is_only_added_through_the_admin_api() -> None:
    assert not any(
        NAMES.insecure_host in app["address"] for app in _seed(phase_two=True)["web_apps"]
    )
    body = seedgen.insecure_app_body(NAMES)
    assert body["upstream_tls"] == "insecure"
    assert body["address"] == NAMES.insecure_host


def test_echo_leaf_san_is_the_address_only_and_wrong_host_overlaps_nothing() -> None:
    sans = seedgen.pki_sans(NAMES)
    assert sans["echo_sans"] == [NAMES.tls_host]
    assert NAMES.alias_host not in sans["echo_sans"]
    assert not set(sans["wrong_host_sans"]) & set(NAMES.app_hosts())


def test_rewrite_body_adds_one_static_header() -> None:
    body = seedgen.rewrite_body(NAMES)
    assert body["request_headers"]["X-Rig-Rewrite"] == "v2"
    assert body["address"].startswith(NAMES.verifier_a_host)


# --- compose file and environment ------------------------------------------------------------


def _compose_env() -> dict[str, str]:
    return seedgen.compose_env(
        NAMES, run_dir=Path("."), network="net", admin_port=18081, gwops_image="gwops-gateway:dev"
    )


def test_compose_file_variables_are_all_supplied() -> None:
    referenced = set(re.findall(r"\$\{(RIG_[A-Z_]+)", COMPOSE_FILE.read_text(encoding="utf-8")))
    assert referenced
    assert referenced <= set(_compose_env())


def test_compose_third_party_images_are_pinned_by_digest() -> None:
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    refs = re.findall(r"^\s*(?:image:|x-echo-image: &echo-image)\s+(\S+)", text, re.M)
    own = ("${RIG_GWOPS_IMAGE", "${RIG_GATORCAST_IMAGE", "gwops-rig", "*")
    third_party = [ref for ref in refs if not ref.startswith(own)]
    assert len(third_party) == 4
    for ref in third_party:
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), ref
        assert ":latest" not in ref


def test_compose_publishes_only_the_admin_port_on_loopback() -> None:
    document = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    published = {name: svc["ports"] for name, svc in document["services"].items() if "ports" in svc}
    assert list(published) == ["gwops"]
    assert published["gwops"][0].startswith("127.0.0.1:")


def test_compose_carries_no_secret_values() -> None:
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    for word in ("TWINGATE_API_KEY", "GWOPS_ADMIN_TOKEN", "ACCESS_TOKEN", "SERVICE_KEY"):
        assert word not in text


def test_gwops_env_lines_are_literal_and_refuse_a_quote() -> None:
    lines = seedgen.gwops_env_lines("k$ey#1", "tok")
    assert lines == ["TWINGATE_API_KEY='k$ey#1'", "GWOPS_ADMIN_TOKEN='tok'"]
    with pytest.raises(guards.GuardError):
        seedgen.gwops_env_lines("bad'key", "tok")


def test_child_env_drops_every_it_variable() -> None:
    env = seedgen.sanitized_child_env(
        {"PATH": "/bin", "IT_TWINGATE_API_KEY": "x", "it_other": "y"}, {"RIG_PROJECT": "p"}
    )
    assert env == {"PATH": "/bin", "RIG_PROJECT": "p"}


# --- result bookkeeping ----------------------------------------------------------------------


async def test_result_book_records_pass_fail_finding_and_exceptions() -> None:
    book = ResultBook()

    async def ok() -> str:
        return "fine"

    async def fail() -> str:
        raise CheckFailed("no")

    async def finding() -> str:
        raise CheckFinding("unconfirmed")

    async def boom() -> str:
        raise RuntimeError("x")

    assert await book.run("1", "a", ok) is Outcome.PASS
    assert await book.run("2", "b", fail) is Outcome.FAIL
    assert await book.run("3", "c", finding) is Outcome.FINDING
    assert await book.run("4", "d", boom) is Outcome.FAIL
    assert [r.outcome for r in book.results] == [
        Outcome.PASS,
        Outcome.FAIL,
        Outcome.FINDING,
        Outcome.FAIL,
    ]
    assert book.results[3].detail == "RuntimeError: x"


def test_exit_code_is_zero_only_when_everything_passed() -> None:
    book = ResultBook()
    book.record("1", "a", Outcome.PASS)
    assert book.exit_code() == 0
    book.record("2", "b", Outcome.FINDING)
    assert book.exit_code() == 3
    book.record("3", "c", Outcome.FAIL)
    assert book.exit_code() == 1


def test_skipped_and_infrastructure_errors_fail_the_run() -> None:
    book = ResultBook()
    book.record("1", "a", Outcome.PASS)
    book.skip_remaining([("1", "a"), ("2", "b")], "not reached")
    assert [r.number for r in book.results] == ["1", "2"]
    assert book.results[1].outcome is Outcome.SKIPPED
    assert book.exit_code() == 1
    other = ResultBook()
    other.record("1", "a", Outcome.PASS)
    other.infrastructure_errors.append("sweep incomplete")
    assert other.exit_code() == 1


def test_summary_lists_results_in_order_with_retries_and_metrics() -> None:
    book = ResultBook()
    book.record("10a", "x", Outcome.PASS)
    book.record("2a", "y", Outcome.FAIL, "got 200")
    book.skew_retries.append("http://a/")
    book.metrics["rewrite_time_to_apply_s"] = "21"
    lines = book.summary_lines()
    assert lines[1].lstrip().startswith("2a")
    assert any("got 200" in line for line in lines)
    assert "clock-skew retries: 1" in lines
    assert "metric rewrite_time_to_apply_s: 21" in lines
    assert lines[-1].startswith("totals:")


def test_expected_assertions_cover_all_eleven_numbers() -> None:
    numbers = {re.sub(r"[a-z]", "", n) for n, _ in checks.EXPECTED_ASSERTIONS}
    assert numbers == {str(i) for i in range(1, 12)}


# --- curl output parsing ---------------------------------------------------------------------


def test_parse_curl_output_reads_status_headers_and_json_body() -> None:
    body = json.dumps({"headers": [["X-Forwarded-Proto", "https"], ["Host", "h"]]})
    raw = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}"
    result = parse_curl_output(0, raw)
    assert result.status == 200
    assert result.headers["content-type"] == "application/json"
    assert result.seen_headers()["x-forwarded-proto"] == ["https"]


def test_parse_curl_output_skips_interim_responses() -> None:
    raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 502 Bad Gateway\r\nX: y\r\n\r\nbad"
    result = parse_curl_output(0, raw)
    assert (result.status, result.body) == (502, "bad")


def test_parse_curl_output_without_a_response_has_no_status() -> None:
    result = parse_curl_output(60, "", "SSL certificate problem")
    assert result.status is None
    assert result.exit_code == 60


# --- docker wrapper --------------------------------------------------------------------------


class RecordingRunner:
    """Records argv and env of each command and replies from a script."""

    def __init__(
        self,
        events: list[str] | None = None,
        replies: dict[str, CommandResult | list[CommandResult]] | None = None,
    ):
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.events = events if events is not None else []
        self.replies = replies or {}

    async def __call__(
        self, argv: Sequence[str], env: Mapping[str, str], timeout: float
    ) -> CommandResult:
        self.calls.append((list(argv), dict(env)))
        words = list(argv)
        key = "stop" if "stop" in words else "kill" if "kill" in words else words[1]
        self.events.append(f"docker:{key}")
        if "compose" in words and "down" in words:
            self.events.append("compose-down")
        reply = self.replies.get(key, CommandResult(0, "", ""))
        if isinstance(reply, list):
            return reply.pop(0) if len(reply) > 1 else reply[0]
        return reply


def _docker(tmp_path: Path, runner: RecordingRunner) -> Docker:
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    return Docker(
        log,
        NAMES,
        COMPOSE_FILE,
        {"RIG_PROJECT": NAMES.project, "RIG_RUN_DIR": str(tmp_path)},
        runner=runner,
        base_env={"PATH": "/bin", "IT_TWINGATE_API_KEY": API_KEY},
    )


async def test_hup_signals_only_the_gwops_container(tmp_path: Path) -> None:
    runner = RecordingRunner()
    await _docker(tmp_path, runner).hup_gwops()
    argv, _env = runner.calls[0]
    assert argv == ["docker", "kill", "-s", "HUP", f"{NAMES.project}-gwops"]


async def test_commands_never_carry_it_variables_or_secrets(tmp_path: Path) -> None:
    runner = RecordingRunner()
    docker = _docker(tmp_path, runner)
    await docker.compose("up", "-d", "gwops")
    await docker.curl("http://x/", cacert=True, headers=["X-A: b"])
    for argv, env in runner.calls:
        assert API_KEY not in " ".join(argv)
        assert not any(key.startswith("IT_") for key in env)
    compose_argv, compose_env = runner.calls[0]
    assert compose_argv[:6] == ["docker", "compose", "-p", NAMES.project, "-f", str(COMPOSE_FILE)]
    assert compose_env["RIG_PROJECT"] == NAMES.project


async def test_curl_runs_in_the_curl_container_with_a_timeout_and_the_gwops_ca(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner()
    await _docker(tmp_path, runner).curl("https://h/", cacert=True)
    argv, _env = runner.calls[0]
    assert argv[:4] == ["docker", "exec", f"{NAMES.project}-curl", "curl"]
    assert "--max-time" in argv
    assert argv[argv.index("--cacert") + 1] == "/trust/gwops-ca.pem"


# --- clock-skew policy -----------------------------------------------------------------------


class FakeDocker:
    """Scripted curl results and, per request, the skew evidence lines."""

    def __init__(self, results: list[CurlResult], evidence: list[list[str]]) -> None:
        self.results = list(results)
        self.evidence = list(evidence)
        self.curl_calls = 0

    async def skew_evidence(self, since: datetime) -> list[str]:
        return self.evidence.pop(0)

    async def curl(self, url: str, **_kwargs: Any) -> CurlResult:
        self.curl_calls += 1
        return self.results.pop(0)


def _http(tmp_path: Path, fake: FakeDocker) -> tuple[checks.RigHttp, ResultBook]:
    book = ResultBook()
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    return checks.RigHttp(fake, log, book), book  # type: ignore[arg-type]


async def test_a_401_without_a_skew_log_is_never_retried(tmp_path: Path) -> None:
    fake = FakeDocker([CurlResult(0, 401)], [[]])
    http, book = _http(tmp_path, fake)
    result = await http.get("http://x/")
    assert result.status == 401
    assert fake.curl_calls == 1
    assert book.skew_retries == []


async def test_a_401_with_a_new_skew_log_is_retried_once_and_recorded(tmp_path: Path) -> None:
    fake = FakeDocker([CurlResult(0, 401), CurlResult(0, 401)], [["e"]])
    http, book = _http(tmp_path, fake)
    result = await http.get("http://x/")
    assert result.status == 401
    assert fake.curl_calls == 2
    assert book.skew_retries == ["http://x/"]


async def test_a_skew_retry_that_succeeds_returns_the_success(tmp_path: Path) -> None:
    fake = FakeDocker([CurlResult(0, 401), CurlResult(0, 200)], [["e"]])
    http, _book = _http(tmp_path, fake)
    assert (await http.get("http://x/")).status == 200


async def test_wait_for_never_retries_a_401(tmp_path: Path) -> None:
    fake = FakeDocker([CurlResult(0, 401)], [[]])
    http, _book = _http(tmp_path, fake)
    with pytest.raises(CheckFailed, match="never retried"):
        await http.wait_for("http://x/", 200, interval=0)
    assert fake.curl_calls == 1


async def test_wait_for_polls_through_gateway_errors_until_the_status(
    tmp_path: Path, checks_clock: Clock
) -> None:
    results = [CurlResult(0, 502), CurlResult(7), CurlResult(0, 200)]
    fake = ClockedEvidenceDocker(results, evidence_after=None)
    http, _book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    assert (await http.wait_for("http://x/", 200, interval=0)).status == 200
    assert fake.curl_calls == 3


async def test_wait_for_does_not_poll_a_determinate_failure(tmp_path: Path) -> None:
    fake = FakeDocker([CurlResult(60)], [[]])
    http, _book = _http(tmp_path, fake)
    with pytest.raises(CheckFailed):
        await http.wait_for("https://x/", 200, interval=0)
    assert fake.curl_calls == 1


# --- identity-header assertion ---------------------------------------------------------------


class StubHttp:
    """Returns one canned response from get()."""

    def __init__(self, result: CurlResult) -> None:
        self.result = result

    async def get(self, url: str, **_kwargs: Any) -> CurlResult:
        return self.result


def _echo(headers: list[list[str]]) -> CurlResult:
    return CurlResult(0, 200, {}, json.dumps({"headers": headers}))


def _checks(http: Any) -> checks.Checks:
    ctx = SimpleNamespace(names=NAMES, http=http)
    return checks.Checks(ctx)  # type: ignore[arg-type]


async def test_identity_assertion_passes_when_spoofs_are_overwritten() -> None:
    headers = [
        ["X-Twingate-User", "svc-key-id"],
        ["X_twingate_user", "svc-key-id"],
        ["X-Rig-Passthrough", "keep-me"],
    ]
    detail = await _checks(StubHttp(_echo(headers))).identity_headers()
    assert "overwritten" in detail


@pytest.mark.parametrize(
    "headers",
    [
        [
            ["X-Twingate-User", checks.SPOOF],
            ["X_twingate_user", "id"],
            ["X-Rig-Passthrough", "keep-me"],
        ],
        [["X-Twingate-User", "id"], ["X-Rig-Passthrough", "keep-me"]],
        [["X-Twingate-User", "id"], ["X_twingate_user", "id"]],
        [
            ["X-Twingate-User", "id"],
            ["X_twingate_user", "id"],
            ["X-Rig-Passthrough", "keep-me"],
            ["X-Forwarded-For", "10.0.0.1"],
        ],
        [
            ["X-Twingate-User", "id"],
            ["X_twingate_user", "id"],
            ["X-Rig-Passthrough", "keep-me"],
            ["X-Forwarded-Host", "h"],
        ],
    ],
)
async def test_identity_assertion_fails_on_a_leak_a_missing_header_or_forwarding(
    headers: list[list[str]],
) -> None:
    with pytest.raises(CheckFailed):
        await _checks(StubHttp(_echo(headers))).identity_headers()


async def test_tls13_without_the_gwops_ca_requires_curl_exit_60() -> None:
    assert "60" in await _checks(StubHttp(CurlResult(60))).tls13_untrusted()
    with pytest.raises(CheckFailed):
        await _checks(StubHttp(CurlResult(0, 200))).tls13_untrusted()
    with pytest.raises(CheckFailed):
        await _checks(StubHttp(CurlResult(35))).tls13_untrusted()


# --- refusal before any docker or HTTP call --------------------------------------------------


@pytest.fixture
def forbid_side_effects(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Any subprocess, HTTP or tenant call fails the test."""
    calls: list[str] = []

    async def no_subprocess(*_a: Any, **_k: Any) -> Any:
        calls.append("subprocess")
        raise AssertionError("docker was called")

    async def no_http(*_a: Any, **_k: Any) -> Any:
        calls.append("http")
        raise AssertionError("HTTP was called")

    async def no_start(*_a: Any, **_k: Any) -> Any:
        calls.append("tenant")
        raise AssertionError("the tenant was touched")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_subprocess)
    monkeypatch.setattr("httpx.AsyncClient.send", no_http)
    monkeypatch.setattr(run.RigTenant, "start", no_start)
    return calls


@pytest.mark.parametrize("missing", list(guards.REQUIRED_ENV) + ["all"])
def test_run_refuses_when_any_it_variable_is_unset(
    missing: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    forbid_side_effects: list[str],
) -> None:
    values = {
        guards.ENV_API_KEY: API_KEY,
        guards.ENV_NETWORK: NETWORK,
        guards.ENV_REMOTE_NETWORK_ID: REMOTE_NETWORK_ID,
        guards.ENV_APPROVED_NETWORK: NETWORK,
        guards.ENV_APPROVED_REMOTE_NETWORK_ID: REMOTE_NETWORK_ID,
    }
    for name in guards.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        if missing not in (name, "all"):
            monkeypatch.setenv(name, value)
    assert run.main([]) == 2
    out = capsys.readouterr().out
    assert out.startswith("REFUSED")
    assert API_KEY not in out
    assert forbid_side_effects == []


def test_run_refuses_a_non_approved_pair_before_any_call(
    monkeypatch: pytest.MonkeyPatch, forbid_side_effects: list[str]
) -> None:
    monkeypatch.setenv(guards.ENV_API_KEY, API_KEY)
    monkeypatch.setenv(guards.ENV_NETWORK, "other-tenant")
    monkeypatch.setenv(guards.ENV_REMOTE_NETWORK_ID, REMOTE_NETWORK_ID)
    monkeypatch.setenv(guards.ENV_APPROVED_NETWORK, NETWORK)
    monkeypatch.setenv(guards.ENV_APPROVED_REMOTE_NETWORK_ID, REMOTE_NETWORK_ID)
    assert run.main([]) == 2
    assert forbid_side_effects == []


def test_make_target_checks_every_it_variable_and_is_not_part_of_test() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("integration-webapp:", 1)[1]
    for name in guards.REQUIRED_ENV:
        assert f"${{{name}:-}}" in recipe
    test_recipe = makefile.split("\ntest:", 1)[1].split("\n\n", 1)[0]
    assert "integration" not in test_recipe
    assert "-m tests.integration.webapp.run" in recipe


# --- teardown order, gwops stop, sweep scope --------------------------------------------------


class FakeTenant:
    """The tenant surface Rig uses; records ordering events."""

    def __init__(self, run_dir: Path, events: list[str]) -> None:
        self.run_dir = run_dir
        self.prefix = NAMES.prefix
        self.state_path = run_dir / "state.json"
        self.state = SimpleNamespace(created=[], ids=lambda _kind: [])
        self.events = events
        self.cleanup_kinds: Any = "unset"
        self.address_error: Exception | None = None

    async def record_discovered(self) -> list[tuple[str, str, str]]:
        self.events.append("record-discovered")
        return []

    async def assert_address_free(self) -> None:
        self.events.append("address-check")
        if self.address_error is not None:
            raise self.address_error

    async def setup(self) -> Any:
        connector = self.run_dir / "connector.env"
        client = self.run_dir / "client.env"
        connector.write_text("TWINGATE_ACCESS_TOKEN=at-secret-value-1\n", encoding="utf-8")
        service_key = json.dumps({"key_id": "kid-secret-123", "private_key": "PRIVATE-BODY-xyz"})
        client.write_text(f"TWINGATE_SERVICE_KEY={service_key}\n", encoding="utf-8")
        return SimpleNamespace(connector_env_file=connector, client_env_file=client)

    async def cleanup(self, *, only_kinds: Any = None) -> Any:
        self.events.append("tenant-cleanup")
        self.cleanup_kinds = only_kinds
        return SimpleNamespace(deleted=[], already_gone=[], inventory_compared=True)


def _rig(tmp_path: Path, events: list[str], runner: RecordingRunner) -> run.Rig:
    env = approved_env()
    args = SimpleNamespace(image="gwops-gateway:dev", apply_timeout=None)
    rig = run.Rig(env, FakeTenant(tmp_path, events), NAMES, args)  # type: ignore[arg-type]
    rig.docker = _docker(tmp_path, runner)
    return rig


async def test_teardown_stops_gwops_before_the_sweep_and_downs_compose_last(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    runner = RecordingRunner(events, {"inspect": CommandResult(0, "false\n", "")})
    rig = _rig(tmp_path, events, runner)
    (tmp_path / run.GWOPS_ENV_FILE).write_text(f"TWINGATE_API_KEY='{API_KEY}'\n", encoding="utf-8")
    await rig.teardown()
    await rig.admin.aclose()

    stop = events.index("docker:stop")
    discovery = events.index("record-discovered")
    assert stop < discovery < events.index("tenant-cleanup") < events.index("compose-down")
    stop_argv = next(argv for argv, _env in runner.calls if "stop" in argv)
    assert stop_argv[1:3] == ["compose", "-p"]
    assert stop_argv[-4:] == ["stop", "-t", "30", "gwops"]
    assert not (tmp_path / run.GWOPS_ENV_FILE).exists()
    assert rig.book.infrastructure_errors == []
    assert [r.number for r in rig.book.results] == ["11"]
    assert rig.book.results[0].outcome is Outcome.PASS


async def test_teardown_that_cannot_confirm_gwops_stopped_sweeps_only_the_service_account(
    tmp_path: Path,
) -> None:
    """The sweep is narrowed to the service account, not skipped."""
    events: list[str] = []
    runner = RecordingRunner(events, {"inspect": CommandResult(0, "true\n", "")})
    rig = _rig(tmp_path, events, runner)
    await rig.teardown()
    await rig.admin.aclose()
    assert rig.tenant.cleanup_kinds == {"service_account_key", "service_account"}  # type: ignore[attr-defined]
    assert any("sweep incomplete; run: python -m" in e for e in rig.book.infrastructure_errors)
    assert rig.book.results[0].outcome is Outcome.FAIL
    assert "gwops may still be running" in rig.book.results[0].detail
    assert rig.book.exit_code() == 1


async def test_stop_gwops_escalates_to_rm_f_and_confirms_the_container_is_gone(
    tmp_path: Path,
) -> None:
    absent = CommandResult(1, "", "Error: No such object: x")
    runner = RecordingRunner(
        replies={
            "inspect": [CommandResult(0, "true\n", ""), absent],
            "stop": CommandResult(1, "", "boom"),
        }
    )
    assert await _docker(tmp_path, runner).stop_gwops() is True
    rm = next(argv for argv, _env in runner.calls if "rm" in argv)
    assert rm == ["docker", "rm", "-f", f"{NAMES.project}-gwops"]


async def test_stop_gwops_is_false_when_it_cannot_be_confirmed(tmp_path: Path) -> None:
    runner = RecordingRunner(replies={"inspect": CommandResult(0, "true\n", "")})
    assert await _docker(tmp_path, runner).stop_gwops() is False


async def test_a_stopped_container_counts_as_stopped_without_rm(tmp_path: Path) -> None:
    runner = RecordingRunner(replies={"inspect": CommandResult(0, "false\n", "")})
    assert await _docker(tmp_path, runner).stop_gwops() is True
    assert not any("rm" in argv for argv, _env in runner.calls)


async def test_container_state_tells_absent_from_any_other_inspect_failure(
    tmp_path: Path,
) -> None:
    absent = RecordingRunner(replies={"inspect": CommandResult(1, "", "Error: No such object: x")})
    assert await _docker(tmp_path, absent).container_state("x") == "absent"
    daemon = RecordingRunner(replies={"inspect": CommandResult(1, "", "Cannot connect to daemon")})
    docker = _docker(tmp_path, daemon)
    with pytest.raises(DockerError):
        await docker.container_state("x")
    assert await docker.may_be_running("x") is True


# --- local-only docker and image --------------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "ghcr.io/o/gwops:dev",
        "docker.io/library/x",
        "registry:5000/x",
        "localhost/x:1",
        "-x",
        " x",
        "",
    ],
)
def test_image_references_naming_a_registry_are_refused(ref: str) -> None:
    with pytest.raises(guards.GuardError):
        guards.require_local_image_ref(ref)


@pytest.mark.parametrize(
    "ref", ["gwops-gateway:dev", "gwops-gateway", "local/gwops:1", "x@sha256:ab"]
)
def test_local_image_references_pass(ref: str) -> None:
    assert guards.require_local_image_ref(ref) == ref


def test_a_remote_docker_is_refused() -> None:
    with pytest.raises(guards.GuardError, match="DOCKER_HOST"):
        guards.require_local_docker("tcp://10.0.0.1:2375", "unix:///var/run/docker.sock")
    for endpoint in ("tcp://h:2376", "ssh://u@h", ""):
        with pytest.raises(guards.GuardError, match="not a local"):
            guards.require_local_docker(None, endpoint)
    guards.require_local_docker(None, "unix:///var/run/docker.sock")
    guards.require_local_docker(None, "npipe:////./pipe/docker_engine")


class ScriptedCli:
    """A docker CLI stub for preflight: context name, endpoint, image id."""

    def __init__(self, endpoint: str, *, image_ok: bool = True) -> None:
        self.endpoint = endpoint
        self.image_ok = image_ok
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], env: Mapping[str, str], timeout: float) -> Any:
        words = list(argv)
        self.calls.append(words)
        if words[1:3] == ["context", "show"]:
            return CommandResult(0, "ctx\n", "")
        if words[1:3] == ["context", "inspect"]:
            return CommandResult(0, f"{self.endpoint}\n", "")
        if words[1:3] == ["image", "inspect"]:
            return CommandResult(0 if self.image_ok else 1, "sha256:feed\n", "")
        return CommandResult(0, "", "")


async def test_require_local_engine_returns_the_context_and_endpoint() -> None:
    cli = ScriptedCli("unix:///var/run/docker.sock")
    engine = await dockerops.require_local_engine(runner=cli, environ={"PATH": "/bin"})
    assert (engine.context, engine.endpoint) == ("ctx", "unix:///var/run/docker.sock")


async def test_require_local_engine_refuses_docker_host_and_remote_endpoints() -> None:
    with pytest.raises(guards.GuardError):
        await dockerops.require_local_engine(
            runner=ScriptedCli("unix:///x"), environ={"DOCKER_HOST": "tcp://h:1"}
        )
    with pytest.raises(guards.GuardError):
        await dockerops.require_local_engine(runner=ScriptedCli("tcp://h:2376"), environ={})


async def test_local_image_id_returns_the_id_or_refuses_a_missing_image() -> None:
    assert await dockerops.local_image_id("x", runner=ScriptedCli("unix:///x")) == "sha256:feed"
    with pytest.raises(guards.GuardError, match="make image"):
        await dockerops.local_image_id("x", runner=ScriptedCli("unix:///x", image_ok=False))


def _valid_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(guards.ENV_API_KEY, API_KEY)
    monkeypatch.setenv(guards.ENV_NETWORK, NETWORK)
    monkeypatch.setenv(guards.ENV_REMOTE_NETWORK_ID, REMOTE_NETWORK_ID)
    monkeypatch.setenv(guards.ENV_APPROVED_NETWORK, NETWORK)
    monkeypatch.setenv(guards.ENV_APPROVED_REMOTE_NETWORK_ID, REMOTE_NETWORK_ID)


def test_run_refuses_a_registry_image_before_any_call(
    monkeypatch: pytest.MonkeyPatch, forbid_side_effects: list[str]
) -> None:
    _valid_env(monkeypatch)
    assert run.main(["--image", "ghcr.io/o/gwops:dev"]) == 2
    assert forbid_side_effects == []


def test_run_refuses_a_remote_docker_context_before_the_tenant_is_touched(
    monkeypatch: pytest.MonkeyPatch, forbid_side_effects: list[str]
) -> None:
    _valid_env(monkeypatch)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr(dockerops, "subprocess_runner", ScriptedCli("tcp://remote:2376"))
    assert run.main([]) == 2
    assert forbid_side_effects == []


# --- signals and cleanup ----------------------------------------------------------------------


async def test_cancel_once_cancels_the_task_a_single_time() -> None:
    async def forever() -> None:
        await asyncio.Event().wait()

    task = asyncio.create_task(forever())
    handler = run.CancelOnce(task)
    await asyncio.sleep(0)
    handler()
    handler()
    assert handler.fired is True
    with pytest.raises(asyncio.CancelledError):
        await task


def test_cancel_handlers_cover_sigterm_and_sigbreak_where_they_exist() -> None:
    registered: list[int] = []

    class Loop:
        def add_signal_handler(self, sig: int, _handler: Any) -> None:
            registered.append(sig)

    run.install_cancel_handlers(Loop(), SimpleNamespace(cancel=lambda: None))
    assert signal.SIGTERM in registered
    if hasattr(signal, "SIGBREAK"):
        assert signal.SIGBREAK in registered


def test_cancel_handlers_fall_back_to_signal_signal_when_the_loop_lacks_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed: list[int] = []
    monkeypatch.setattr(signal, "signal", lambda sig, _h: installed.append(sig))

    class Loop:
        def add_signal_handler(self, *_a: Any) -> None:
            raise NotImplementedError

        def call_soon_threadsafe(self, _fn: Any) -> None:
            pass

    run.install_cancel_handlers(Loop(), SimpleNamespace(cancel=lambda: None))
    assert signal.SIGTERM in installed


async def test_a_cancelled_run_still_tears_down_logs_the_image_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    torn: list[str] = []
    logged: list[tuple[str, dict[str, Any]]] = []

    async def noop() -> None:
        return None

    class FakeRig:
        def __init__(self, env: Any, tenant: Any, names: Any, args: Any) -> None:
            self.book = ResultBook()
            self.log = SimpleNamespace(event=self._event)
            self.admin = SimpleNamespace(aclose=noop)

        @staticmethod
        def _event(event: str, /, **fields: Any) -> None:
            logged.append((event, fields))

        async def bring_up(self) -> dict[str, str]:
            await asyncio.Event().wait()
            return {}

        async def teardown(self) -> None:
            torn.append("teardown")

        def finish(self) -> int:
            return self.book.exit_code()

    async def fake_start(env: Any, **_kw: Any) -> Any:
        return SimpleNamespace(prefix=NAMES.prefix, aclose=noop)

    async def fake_preflight(_image: str) -> Any:
        return dockerops.LocalEngine("ctx", "unix:///x", "sha256:feedbeef")

    monkeypatch.setattr(run, "Rig", FakeRig)
    monkeypatch.setattr(run.RigTenant, "start", fake_start)
    monkeypatch.setattr(run, "preflight_local", fake_preflight)
    env = approved_env()
    task = asyncio.create_task(run.execute(env, SimpleNamespace(image="gwops-gateway:dev")))
    await asyncio.sleep(0.05)
    task.cancel()
    assert await task == 1
    assert torn == ["teardown"]
    assert ("gwops-image", {"ref": "gwops-gateway:dev", "id": "sha256:feedbeef"}) in logged
    assert ("docker-context", {"name": "ctx", "endpoint": "unix:///x"}) in logged


# --- adoption and incremental recording -------------------------------------------------------


class FakeAdmin:
    """Scripted admin API."""

    def __init__(
        self, events: list[str], status: dict[str, Any] | None = None, ready_after: int = 0
    ) -> None:
        self.events = events
        self._status = status or {}
        self.ready_after = ready_after
        self.gets = 0

    async def status(self) -> dict[str, Any]:
        return self._status

    async def reconcile(self) -> dict[str, Any]:
        return {"ok": True, "actions": [], "errors": []}

    async def get_webapp(self, name: str) -> dict[str, Any]:
        self.gets += 1
        self.events.append("get-webapp")
        return {"tg_resource_id": f"ID-{name}"} if self.gets > self.ready_after else {}

    async def aclose(self) -> None:
        return None


def test_reconcile_actions_reads_status_and_reconcile_results() -> None:
    assert run.reconcile_actions({"last_reconcile": {"actions": ["a", 1]}}) == ["a"]
    assert run.reconcile_actions({"actions": ["b"]}) == ["b"]
    assert run.reconcile_actions({"last_reconcile": None}) == []


def test_require_no_adoption_refuses_an_adopted_gateway_action() -> None:
    guards.require_no_adoption(["created gateway (GW) at x:8443 in remote network RN"])
    with pytest.raises(guards.GatewayAddressInUseError, match="adopted"):
        guards.require_no_adoption(["adopted existing gateway (GW-B) at x:8443"])


async def test_the_run_fails_when_gwops_reports_adopting_a_gateway(tmp_path: Path) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    status = {"last_reconcile": {"actions": ["adopted existing gateway (GW-B) at a:8443"]}}
    rig.admin = FakeAdmin([], status)  # type: ignore[assignment]
    with pytest.raises(guards.GatewayAddressInUseError):
        await rig.wait_admin()
    await rig.admin.aclose()


async def test_gateway_and_cas_are_recorded_while_waiting_for_the_apps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    rig = _rig(tmp_path, events, RecordingRunner())
    rig.admin = FakeAdmin(events, ready_after=len(seedgen.APP_SUFFIXES) * 2)  # type: ignore[assignment]

    async def instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(run.asyncio, "sleep", instant)
    ids = await rig.wait_apps_created()
    assert len(ids) == len(seedgen.APP_SUFFIXES)
    first_record = events.index("record-discovered")
    last_get = len(events) - 1 - events[::-1].index("get-webapp")
    assert first_record < last_get


async def test_the_address_is_rechecked_before_compose_up_and_secrets_are_registered(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    runner = RecordingRunner(events)
    rig = _rig(tmp_path, events, runner)
    rig.tenant.address_error = guards.GatewayAddressInUseError("taken")  # type: ignore[attr-defined]
    with pytest.raises(guards.GatewayAddressInUseError):
        await rig.bring_up()
    await rig.admin.aclose()
    assert "address-check" in events
    assert not any("up" in argv for argv, _env in runner.calls)
    for secret in ("kid-secret-123", "PRIVATE-BODY-xyz", "at-secret-value-1"):
        assert rig.log.redactor.redact(f"x {secret} y") == f"x {REDACTED} y"


# --- service-key secrets and file modes -------------------------------------------------------


def test_every_json_string_of_the_service_key_is_a_secret_but_the_network_name_is_not() -> None:
    key = json.dumps(
        {
            "version": "1",
            "network": "acme",
            "key_id": "kid-secret-123",
            "private_key": "PK-body",
        }
    )
    values = secret_values_from_env_text(f"TWINGATE_SERVICE_KEY={key}\n", exclude={"acme"})
    assert {"kid-secret-123", "PK-body", key} <= set(values)
    assert "acme" not in values
    assert "1" not in values


def test_multiline_service_key_values_register_each_line() -> None:
    text = 'K={"private_key": "line-one-aaaa\\nline-two-bbbb"}'
    redactor = Redactor(secret_values_from_env_text(text))
    assert "line-one-aaaa" not in redactor.redact("line-one-aaaa")


def test_run_log_is_created_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    modes: list[int] = []
    real = os.open

    def spy(path: Any, flags: int, mode: int = 0o777, **kw: Any) -> int:
        modes.append(mode)
        return real(path, flags, mode, **kw)

    monkeypatch.setattr(os, "open", spy)
    RunLog(tmp_path / "run.log", Redactor(), echo=False)
    assert modes == [0o600]


# --- compose hardening ------------------------------------------------------------------------


def _services() -> dict[str, dict[str, Any]]:
    document = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    return dict(document["services"])


def test_every_service_drops_all_capabilities_and_has_resource_limits() -> None:
    for name, svc in _services().items():
        assert svc["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert svc["mem_limit"], name
        assert svc["pids_limit"], name


def test_only_the_client_adds_a_capability_and_only_net_admin() -> None:
    added = {name: svc["cap_add"] for name, svc in _services().items() if "cap_add" in svc}
    assert added == {"client": ["NET_ADMIN"]}


def test_curl_verifiers_echoes_and_gwops_have_read_only_root_filesystems() -> None:
    services = _services()
    names = ("curl", "verifier-a", "verifier-b", "echo-http", "echo-tls", "echo-wrong", "gwops")
    for name in names:
        assert services[name]["read_only"] is True, name


def test_echo_upstreams_sit_only_on_the_internal_network() -> None:
    document = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert document["networks"]["backend"]["internal"] is True
    for name in ("echo-http", "echo-tls", "echo-wrong"):
        assert list(document["services"][name]["networks"]) == ["backend"], name
    for name in ("gwops", "connector"):
        assert "backend" in document["services"][name]["networks"], name


def test_the_client_uses_the_non_debug_build_pinned_by_digest() -> None:
    image = _services()["client"]["image"]
    assert image.startswith("twingate/client:")
    assert "debug" not in image
    assert re.search(r"@sha256:[0-9a-f]{64}$", image)


def test_run_log_events_accept_a_field_named_name_or_event(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    log.event("docker-context", name="ctx", event="x")
    assert "docker-context name=ctx event=x" in (tmp_path / "run.log").read_text(encoding="utf-8")


# --- teardown cannot be interrupted; the engine endpoint reaches the state --------------------


def test_begin_teardown_marks_the_handler_fired_so_a_later_signal_cannot_cancel() -> None:
    cancelled: list[bool] = []
    handler = run.CancelOnce(SimpleNamespace(cancel=lambda: cancelled.append(True)))
    handler.begin_teardown()
    handler()
    assert handler.fired is True
    assert cancelled == []


def test_the_teardown_shield_ignores_sigint_marks_shutdown_and_restores_the_handler() -> None:
    previous = signal.getsignal(signal.SIGINT)
    handler = run.CancelOnce(SimpleNamespace(cancel=lambda: None))
    with run.TeardownShield(handler) as shield:
        assert handler.fired is True
        installed = signal.getsignal(signal.SIGINT)
        assert installed is not previous
        assert callable(installed)
        installed(signal.SIGINT, None)
        installed(signal.SIGINT, None)
        assert shield.ignored == 2
    assert signal.getsignal(signal.SIGINT) is previous


async def test_run_shielded_finishes_the_work_despite_repeated_cancels() -> None:
    finished: list[str] = []

    async def work() -> None:
        await asyncio.sleep(0.05)
        finished.append("done")

    async def outer() -> int:
        return await run.run_shielded(work())

    task = asyncio.create_task(outer())
    await asyncio.sleep(0.01)
    task.cancel()
    await asyncio.sleep(0.01)
    task.cancel()
    assert await task == 2
    assert finished == ["done"]


async def test_run_shielded_propagates_the_works_own_error() -> None:
    async def work() -> None:
        raise RuntimeError("sweep exploded")

    with pytest.raises(RuntimeError, match="sweep exploded"):
        await run.run_shielded(work())


def _fake_rig_class(torn: list[str], logged: list[tuple[str, dict[str, Any]]], teardown_s: float):
    async def noop() -> None:
        return None

    class FakeRig:
        def __init__(self, env: Any, tenant: Any, names: Any, args: Any) -> None:
            self.book = ResultBook()
            self.log = SimpleNamespace(event=self._event)
            self.admin = SimpleNamespace(aclose=noop)

        @staticmethod
        def _event(event: str, /, **fields: Any) -> None:
            logged.append((event, fields))

        async def bring_up(self) -> dict[str, str]:
            return {}

        async def start_stage_two(self, ids: Any) -> None:
            return None

        async def assertions(self) -> None:
            return None

        async def teardown(self) -> None:
            await asyncio.sleep(teardown_s)
            torn.append("done")

        def finish(self) -> int:
            return self.book.exit_code()

    return FakeRig, noop


def _patch_run(monkeypatch: pytest.MonkeyPatch, rig_class: Any, noop: Any, started: dict[str, Any]):
    async def fake_start(env: Any, **kw: Any) -> Any:
        started.update(kw)
        return SimpleNamespace(prefix=NAMES.prefix, aclose=noop)

    async def fake_preflight(_image: str) -> Any:
        return dockerops.LocalEngine("ctx", "unix:///the-engine.sock", "sha256:feedbeef")

    monkeypatch.setattr(run, "Rig", rig_class)
    monkeypatch.setattr(run.RigTenant, "start", fake_start)
    monkeypatch.setattr(run, "preflight_local", fake_preflight)


async def test_shutdown_is_marked_fired_before_teardown_even_without_a_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SIGTERM arriving during a normal-completion teardown must not cancel the task."""
    torn: list[str] = []
    logged: list[tuple[str, dict[str, Any]]] = []
    rig_class, noop = _fake_rig_class(torn, logged, 0.0)
    fired_at_teardown: list[bool] = []
    handler = run.CancelOnce(SimpleNamespace(cancel=lambda: None))
    original = rig_class.teardown

    async def spy(self: Any) -> None:
        fired_at_teardown.append(handler.fired)
        await original(self)

    rig_class.teardown = spy
    _patch_run(monkeypatch, rig_class, noop, {})
    env = approved_env()
    await run.execute(env, SimpleNamespace(image="gwops-gateway:dev"), handler)
    assert fired_at_teardown == [True]
    assert any(
        event == "teardown" and "in progress" in f["state"] for event, f in logged if "state" in f
    )


async def test_a_second_cancel_during_teardown_does_not_abandon_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    torn: list[str] = []
    logged: list[tuple[str, dict[str, Any]]] = []
    rig_class, noop = _fake_rig_class(torn, logged, 0.08)

    async def hang(self: Any) -> dict[str, str]:
        await asyncio.Event().wait()
        return {}

    rig_class.bring_up = hang
    _patch_run(monkeypatch, rig_class, noop, {})
    env = approved_env()
    task = asyncio.create_task(run.execute(env, SimpleNamespace(image="gwops-gateway:dev")))
    await asyncio.sleep(0.02)
    task.cancel()
    await asyncio.sleep(0.02)
    task.cancel()
    assert await task == 1
    assert torn == ["done"]
    assert any(f.get("ignored_cancels") == 1 for _event, f in logged)


async def test_the_engine_endpoint_is_passed_to_the_tenant_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig_class, noop = _fake_rig_class([], [], 0.0)
    started: dict[str, Any] = {}
    _patch_run(monkeypatch, rig_class, noop, started)
    env = approved_env()
    await run.execute(env, SimpleNamespace(image="gwops-gateway:dev"))
    assert started["docker_endpoint"] == "unix:///the-engine.sock"


# --- --hold: keep the rig up after the assertions --------------------------------------------


def test_hold_options_default_to_off_and_two_hours() -> None:
    args = run.parse_args([])
    assert args.hold is False
    assert args.hold_max == 7200.0
    args = run.parse_args(["--hold", "--hold-max", "30"])
    assert (args.hold, args.hold_max) == (True, 30.0)


def test_hold_commands_cover_every_app_and_pass_cacert_only_for_tls13() -> None:
    commands = dict((title.split(":")[0], cmd) for title, cmd in seedgen.hold_commands(NAMES))
    text = "\n".join(commands.values())
    for host in NAMES.app_hosts():
        assert host in text, host
    for cmd in commands.values():
        assert cmd.startswith(f"docker exec {NAMES.project}-curl curl") or cmd.startswith(
            f"docker logs {NAMES.project}-verifier-b"
        )
    for host in (NAMES.tls_host, NAMES.alias_host):
        line = next(c for c in commands.values() if f"https://{host}/" in c)
        assert "--cacert /trust/gwops-ca.pem" in line
    plain = next(c for c in commands.values() if f"http://{NAMES.plain_host}/" in c)
    assert "--cacert" not in plain
    assert "--max-time" in plain


def test_hold_commands_show_the_verifiers_claims_json() -> None:
    claims = next(c for t, c in seedgen.hold_commands(NAMES) if t.startswith("verifier-a"))
    assert f"http://{NAMES.verifier_a_host}/" in claims
    assert claims.endswith("| python -m json.tool")


def test_hold_instructions_hold_no_secret(tmp_path: Path) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    text = "\n".join(rig.hold_instructions(7200))
    assert str(tmp_path / "HOLD") in text
    assert rig.admin_token not in text
    assert API_KEY not in text
    assert "Authorization" not in text


async def _hold_in_task(rig: run.Rig, **kw: Any) -> asyncio.Task[str]:
    task = asyncio.create_task(rig.hold(kw.pop("max_seconds", 5.0), poll_seconds=0.01, **kw))
    await asyncio.sleep(0.05)
    return task


async def test_hold_writes_the_marker_prints_commands_and_ends_when_it_is_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    task = await _hold_in_task(rig)
    marker = tmp_path / "HOLD"
    assert marker.exists()
    marker.unlink()
    assert await task == "released"
    out = capsys.readouterr().out
    assert f"docker exec {NAMES.project}-curl curl" in out
    assert "--cacert /trust/gwops-ca.pem" in out
    assert "python -m json.tool" in out
    await rig.admin.aclose()


async def test_hold_expires_after_the_maximum_and_removes_the_marker(tmp_path: Path) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    assert await rig.hold(0.05, poll_seconds=0.01) == "expired"
    assert not (tmp_path / "HOLD").exists()
    await rig.admin.aclose()


async def test_hold_logs_a_heartbeat_while_waiting(tmp_path: Path) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    await rig.hold(0.2, heartbeat_seconds=0.03, poll_seconds=0.01)
    assert "hold-heartbeat remaining_s=" in (tmp_path / "run.log").read_text(encoding="utf-8")
    await rig.admin.aclose()


async def test_an_interrupt_during_the_hold_ends_it_normally_and_removes_the_marker(
    tmp_path: Path,
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    task = await _hold_in_task(rig)
    task.cancel()
    assert await task == "interrupted"
    assert not (tmp_path / "HOLD").exists()
    await rig.admin.aclose()


async def test_hold_console_output_is_redacted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    monkeypatch.setattr(rig, "hold_instructions", lambda _max: [f"token {rig.admin_token}"])
    await rig.hold(0.02, poll_seconds=0.01)
    out = capsys.readouterr().out
    assert rig.admin_token not in out
    assert REDACTED in out
    await rig.admin.aclose()


def _hold_rig_class(holds: list[float], *, infra_error: bool, failed_assertion: bool) -> Any:
    rig_class, noop = _fake_rig_class([], [], 0.0)

    async def assertions(self: Any) -> None:
        if infra_error:
            self.book.infrastructure_errors.append("bring-up broke")
        if failed_assertion:
            self.book.record("1", "x", Outcome.FAIL, "got 502")

    async def hold(self: Any, max_seconds: float) -> str:
        holds.append(max_seconds)
        return "released"

    rig_class.assertions = assertions
    rig_class.hold = hold
    return rig_class, noop


@pytest.mark.parametrize(
    ("hold", "infra_error", "failed_assertion", "expected"),
    [
        (True, False, False, [42.0]),
        (True, False, True, [42.0]),
        (True, True, False, []),
        (False, False, False, []),
    ],
)
async def test_hold_runs_after_the_assertions_only_when_asked_and_without_an_infrastructure_error(
    monkeypatch: pytest.MonkeyPatch,
    hold: bool,
    infra_error: bool,
    failed_assertion: bool,
    expected: list[float],
) -> None:
    holds: list[float] = []
    rig_class, noop = _hold_rig_class(
        holds, infra_error=infra_error, failed_assertion=failed_assertion
    )
    _patch_run(monkeypatch, rig_class, noop, {})
    env = approved_env()
    args = SimpleNamespace(image="gwops-gateway:dev", hold=hold, hold_max=42.0)
    await run.execute(env, args)
    assert holds == expected


async def test_the_hold_happens_before_the_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    rig_class, noop = _fake_rig_class([], [], 0.0)

    async def hold(self: Any, max_seconds: float) -> str:
        order.append("hold")
        return "released"

    async def teardown(self: Any) -> None:
        order.append("teardown")

    rig_class.hold = hold
    rig_class.teardown = teardown
    _patch_run(monkeypatch, rig_class, noop, {})
    env = approved_env()
    await run.execute(env, SimpleNamespace(image="gwops-gateway:dev", hold=True, hold_max=1.0))
    assert order == ["hold", "teardown"]


def test_make_passes_hold_through_and_keeps_crlf() -> None:
    raw = (REPO_ROOT / "Makefile").read_bytes().decode("utf-8")
    recipe = raw.split("integration-webapp:", 1)[1]
    line = next(ln for ln in recipe.split("\r\n") if "tests.integration.webapp.run" in ln)
    assert "$(if $(filter 1,$(HOLD)),--hold)" in line
    assert "--hold-max $(HOLD_MAX)" in line
    assert "\n" not in raw.replace("\r\n", "")


# --- verifier GAT rewrite ---------------------------------------------------------------------


def _effective_state(doc: dict[str, Any]) -> Any:
    from gwops.configmodel.schema import EffectiveState

    return EffectiveState.model_validate(doc)


def _policy_violations(state: Any) -> list[str]:
    from gwops.access.webapp_policy import violations
    from gwops.renderer.capabilities import Capabilities

    return violations(state, Capabilities())


def _rewrites(state: Any, suffix: str) -> dict[str, str]:
    entry = next(a for a in state.web_apps if a.name == NAMES.app_name(suffix))
    return dict(entry.tg_extras()["request_header_rewrites"] or ())


@pytest.mark.parametrize("phase_two", [False, True])
def test_only_the_verifiers_carry_the_gat_authorization_rewrite(phase_two: bool) -> None:
    apps = {app["name"]: app for app in _seed(phase_two=phase_two)["web_apps"]}
    gat = {"Authorization": "Bearer {{jwt}}"}
    for suffix in ("verifier-a", "verifier-b"):
        assert apps[NAMES.app_name(suffix)]["request_headers"] == gat
    for suffix in ("plain", "vfull", "vca", "vfullwrong"):
        assert "request_headers" not in apps[NAMES.app_name(suffix)]


@pytest.mark.parametrize("phase_two", [False, True])
def test_the_verifier_rewrites_reach_the_tenant_extras_and_pass_the_web_app_policy(
    phase_two: bool,
) -> None:
    state = _effective_state(_seed(phase_two=phase_two))
    assert _policy_violations(state) == []
    for suffix in ("verifier-a", "verifier-b"):
        assert _rewrites(state, suffix) == {"Authorization": "Bearer {{jwt}}"}
    assert _rewrites(state, "plain") == {}


def test_the_rewrite_put_resends_authorization_alongside_the_marker() -> None:
    body = seedgen.rewrite_body(NAMES)
    assert body["request_headers"] == {"Authorization": "Bearer {{jwt}}", "X-Rig-Rewrite": "v2"}


def test_the_rewrite_put_keeps_the_policy_clean_when_it_replaces_the_headers_wholesale() -> None:
    doc = _seed(phase_two=True)
    body = seedgen.rewrite_body(NAMES)
    name = NAMES.app_name("verifier-a")
    doc["web_apps"] = [{**app, **body} if app["name"] == name else app for app in doc["web_apps"]]
    state = _effective_state(doc)
    assert _policy_violations(state) == []
    assert _rewrites(state, "verifier-a") == {
        "Authorization": "Bearer {{jwt}}",
        "X-Rig-Rewrite": "v2",
    }


# --- gateway log capture ----------------------------------------------------------------------

SHIM_DIR = Path(run.__file__).resolve().parent / "gwops-shim"


def test_the_gateway_shim_is_lf_only_merges_stderr_and_keeps_validation_stderr_apart() -> None:
    raw = (SHIM_DIR / "gateway-stdio.sh").read_bytes()
    assert raw.startswith(b"#!/bin/sh\n")
    assert b"\r" not in raw
    text = raw.decode("utf-8")
    assert 'exec /usr/local/bin/gateway "$@" 2>&1' in text
    assert text.index(".next") < text.index('"$@" 2>&1')


def test_the_shim_target_is_the_binary_gwops_would_have_run() -> None:
    from gwops.settings import GwopsSettings

    assert GwopsSettings().gateway_binary.as_posix() == "/usr/local/bin/gateway"
    assert "/usr/local/bin/gateway" in (SHIM_DIR / "gateway-stdio.sh").read_text(encoding="utf-8")
    assert "/usr/local/bin/gateway" in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_the_shim_image_bakes_in_lf_and_the_exec_bit_instead_of_relying_on_a_bind_mount() -> None:
    dockerfile = (SHIM_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM ${BASE_IMAGE}" in dockerfile
    assert "chmod 0755 /usr/local/bin/gateway-stdio" in dockerfile
    assert "s/\\r$//" in dockerfile
    assert dockerfile.rstrip().endswith("USER gwops")


def test_gwops_runs_the_shim_image_with_the_shim_as_its_gateway_binary() -> None:
    gwops = _services()["gwops"]
    binary = gwops["environment"]["GWOPS_GATEWAY_BINARY"]
    assert binary == "${RIG_GATEWAY_SHIM:?set RIG_GATEWAY_SHIM}"
    assert _compose_env()["RIG_GATEWAY_SHIM"] == "/usr/local/bin/gateway-stdio"
    assert gwops["build"]["context"] == "./gwops-shim"
    assert gwops["build"]["args"]["BASE_IMAGE"].startswith("${RIG_GWOPS_IMAGE")
    assert gwops["image"] == "gwops-rig-gwops:local"
    assert not any("gateway-stdio" in str(v) for v in gwops.get("volumes", []))


async def test_stage_one_builds_the_shim_image(tmp_path: Path) -> None:
    events: list[str] = []
    runner = RecordingRunner(events)
    rig = _rig(tmp_path, events, runner)
    rig.admin = FakeAdmin(events, {"state_error": "stop here"})  # type: ignore[assignment]
    with pytest.raises(run.RigError, match="stop here"):
        await rig.bring_up()
    up = next(argv for argv, _env in runner.calls if "up" in argv)
    assert "--build" in up
    assert "gwops" in up


def test_the_rig_seed_keeps_recording_disabled_and_has_no_ssh_or_k8s_upstreams() -> None:
    from gwops.configmodel.schema import SeedConfig

    for phase_two in (False, True):
        doc = _seed(phase_two=phase_two)
        assert doc["recording"] == {"enabled": False}
        assert not doc.get("ssh_upstreams")
        assert not doc.get("k8s_clusters")
        seed = SeedConfig.model_validate(doc)
        assert seed.recording.enabled is False
        assert seed.ssh_upstreams == [] and seed.k8s_clusters == []


def test_gwops_log_filter_keeps_gateway_supervisor_and_reconcile_events_and_problems() -> None:
    def line(**fields: Any) -> str:
        return json.dumps(fields)

    text = "\n".join(
        [
            line(event="gateway.line", stream="stdout", line="401 token used before issued"),
            line(event="supervisor.state", state="running"),
            line(event="reconcile.done", ok=True),
            line(event="api.audit", level="info"),
            line(event="something.else", level="warning"),
            line(event="boom", level="error"),
            line(event="chatter", level="info"),
            "Traceback (most recent call last):",
        ]
    )
    kept = logfilter.filter_gwops_log(text).splitlines()
    assert [json.loads(k).get("event") if k.startswith("{") else k for k in kept] == [
        "gateway.line",
        "supervisor.state",
        "reconcile.done",
        "something.else",
        "boom",
        "Traceback (most recent call last):",
    ]


def test_client_log_filter_keeps_errors_and_authorize_flow_lines_only() -> None:
    text = "\n".join(
        [
            "INFO connected",
            "ERROR failed to refresh",
            "DEBUG authorize_flow started",
            "warn: Error: bad",
            "INFO heartbeat",
        ]
    )
    assert logfilter.filter_client_log(text).splitlines() == [
        "ERROR failed to refresh",
        "DEBUG authorize_flow started",
        "warn: Error: bad",
    ]


class LogsRunner:
    """docker logs answers keyed by container suffix; everything else succeeds quietly."""

    def __init__(self, logs: dict[str, str]) -> None:
        self.logs = logs
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], env: Mapping[str, str], timeout: float) -> Any:
        words = list(argv)
        self.calls.append(words)
        if words[1] == "logs":
            for suffix, text in self.logs.items():
                if words[-1].endswith(f"-{suffix}"):
                    return CommandResult(0, text, "")
        return CommandResult(0, "", "")


async def test_teardown_dumps_the_full_filtered_gwops_and_client_logs_through_the_redactor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gateway_lines = [
        json.dumps({"event": "gateway.line", "stream": "stdout", "line": f"request {i}"})
        for i in range(3000)
    ]
    secret_line = json.dumps(
        {"event": "gateway.line", "line": f"Authorization: Bearer {GAT} {API_KEY}"}
    )
    gwops_text = "\n".join(
        [*gateway_lines, secret_line, json.dumps({"event": "api.audit", "level": "info"})]
    )
    client_text = "INFO ok\nERROR denied\nauthorize_flow step 2\nINFO ok again"
    rig = _rig(tmp_path, [], RecordingRunner())
    runner = LogsRunner({"gwops": gwops_text, "client": client_text})
    rig.docker = Docker(rig.log, NAMES, COMPOSE_FILE, {"RIG_PROJECT": NAMES.project}, runner=runner)
    capsys.readouterr()
    await rig.dump_logs()
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert written.count('"event": "gateway.line"') == 3001
    assert "api.audit" not in written
    assert "ERROR denied" in written and "authorize_flow step 2" in written
    assert "INFO ok" not in written
    assert GAT not in written and API_KEY not in written
    assert "request 0" in written and "request 2999" in written
    assert "request 0" not in capsys.readouterr().out
    logs_calls = [c for c in runner.calls if c[1] == "logs"]
    assert not any(
        a.startswith("--tail") for c in logs_calls for a in c if c[-1].endswith("-gwops")
    )
    await rig.admin.aclose()


def test_run_log_blocks_are_not_truncated_at_the_old_cap(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    text = "\n".join(f"line {i}" for i in range(15_000))
    log.block("big", text)
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "line 0" in written and "line 14999" in written
    assert "[truncated]" not in written


async def test_a_skew_rejection_in_the_gateway_log_allows_the_one_retry(tmp_path: Path) -> None:
    fake = FakeDocker([CurlResult(0, 401), CurlResult(0, 200)], [["e"]])
    http, book = _http(tmp_path, fake)
    assert (await http.get("http://x/")).status == 200
    assert book.skew_retries == ["http://x/"]


# --- failure diagnostics ----------------------------------------------------------------------


class DiagDocker:
    """Records the diagnostic curl and log calls."""

    def __init__(self, *, fail: bool = False) -> None:
        self.curls: list[dict[str, Any]] = []
        self.log_calls: list[tuple[str, str | None]] = []
        self.fail = fail

    @staticmethod
    def container(service: str) -> str:
        return f"{NAMES.project}-{service}"

    async def curl(self, url: str, **kwargs: Any) -> CurlResult:
        if self.fail:
            raise DockerError("engine went away")
        self.curls.append({"url": url, **kwargs})
        verbose = (
            "> GET / HTTP/1.1\n> Authorization: Bearer SECRET-GAT-VALUE\n"
            f"< HTTP/1.1 502 Bad Gateway\n< x-note: ok\n{GAT}\n"
        )
        return CurlResult(0, None, {}, "body text", verbose)

    async def logs(self, container: str, *, since: str | None = None, **_kw: Any) -> str:
        self.log_calls.append((container, since))
        return f"log of {container}"


def _record(url: str = "https://t/", at: float = 100.0) -> Any:
    return checks.RequestRecord(url, True, ("X-A: b",), 20, at)


async def test_a_failed_assertion_repeats_its_last_request_once_with_curl_v(
    tmp_path: Path,
) -> None:
    docker = DiagDocker()
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    http = SimpleNamespace(last=_record(at=100.0))
    started = datetime.now(UTC)
    await diagnose.diagnose_failure(docker, http, log, "2a", wall_start=started, mono_start=99.0)
    assert docker.curls == [
        {
            "url": "https://t/",
            "cacert": True,
            "headers": ("X-A: b",),
            "max_time": 20,
            "verbose": True,
        }
    ]
    assert [c for c, _s in docker.log_calls] == [
        f"{NAMES.project}-gwops",
        f"{NAMES.project}-client",
    ]
    assert all(since == diagnose.since_arg(started) for _c, since in docker.log_calls)
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "diagnostic 2a: curl -v https://t/" in written
    assert "< HTTP/1.1 502 Bad Gateway" in written
    assert "log of " + f"{NAMES.project}-gwops" in written
    assert "Authorization" not in written and "SECRET-GAT-VALUE" not in written
    assert GAT not in written


async def test_a_request_from_an_earlier_assertion_is_not_repeated(tmp_path: Path) -> None:
    docker = DiagDocker()
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    http = SimpleNamespace(last=_record(at=50.0))
    await diagnose.diagnose_failure(
        docker, http, log, "5a", wall_start=datetime.now(UTC), mono_start=99.0
    )
    assert docker.curls == []
    assert len(docker.log_calls) == 2


async def test_diagnostics_never_raise_and_say_so_in_the_log(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    await diagnose.diagnose_failure(
        DiagDocker(fail=True),
        SimpleNamespace(last=_record()),
        log,
        "6b",
        wall_start=datetime.now(UTC),
        mono_start=0.0,
    )
    assert "diagnostic-failed assertion=6b" in (tmp_path / "run.log").read_text(encoding="utf-8")


def test_since_arg_is_rfc3339_utc_backed_off_five_seconds() -> None:
    moment = datetime(2026, 10, 8, 12, 0, 10, 500000, tzinfo=UTC)
    assert diagnose.since_arg(moment) == "2026-10-08T12:00:05.500000Z"


async def test_docker_curl_verbose_uses_dash_v_and_logs_accept_since(tmp_path: Path) -> None:
    runner = RecordingRunner()
    docker = _docker(tmp_path, runner)
    await docker.curl("http://x/", verbose=True)
    await docker.curl("http://x/")
    await docker.logs("c", since="2026-10-08T12:00:05.500000Z")
    verbose, plain, logs = (argv for argv, _env in runner.calls)
    assert "-v" in verbose and "-i" not in verbose
    assert "-i" in plain and "-v" not in plain
    assert logs[-3:] == ["--since", "2026-10-08T12:00:05.500000Z", "c"]


async def test_the_http_helper_remembers_its_last_request_after_a_skew_retry(
    tmp_path: Path,
) -> None:
    fake = FakeDocker([CurlResult(0, 401), CurlResult(0, 200)], [["e"]])
    http, _book = _http(tmp_path, fake)
    await http.get("http://x/", cacert=True, headers=["X-A: b"], max_time=9)
    assert http.last is not None
    assert (http.last.url, http.last.cacert, http.last.headers, http.last.max_time) == (
        "http://x/",
        True,
        ("X-A: b",),
        9,
    )


async def test_diagnostics_run_only_for_a_non_pass_and_never_change_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    seen: list[str] = []

    async def fake_diagnose(*_a: Any, **kw: Any) -> None:
        seen.append(_a[3])

    monkeypatch.setattr(run.diagnose, "diagnose_failure", fake_diagnose)

    async def ok() -> str:
        return "fine"

    async def bad() -> str:
        raise CheckFailed("expected 200, got 502")

    async def finding() -> str:
        raise CheckFinding("not applied")

    assert await rig.run_check("1", "t", ok) is Outcome.PASS
    assert await rig.run_check("2a", "t", bad) is Outcome.FAIL
    assert await rig.run_check("8", "t", finding) is Outcome.FINDING
    assert seen == ["2a", "8"]
    assert [r.outcome for r in rig.book.results] == [Outcome.PASS, Outcome.FAIL, Outcome.FINDING]
    await rig.admin.aclose()


async def test_the_wrong_host_assertion_does_not_retry_a_mismatch() -> None:
    class CountingHttp:
        calls = 0

        async def get(self, url: str, **_kw: Any) -> CurlResult:
            self.calls += 1
            return CurlResult(0, 200)

    http = CountingHttp()
    with pytest.raises(CheckFailed):
        await _checks(http).verify_full_wrong_host()
    assert http.calls == 1


# --- restarting the client for a resource created mid-run -------------------------------------


class InsecureAllowlistedWorld:
    """Fakes for assertion 5b that record the order of every side effect."""

    def __init__(self, tmp_path: Path, *, netns_ok: bool = True) -> None:
        self.events: list[str] = []
        self.waits: list[tuple[str, int, float]] = []
        self.netns_ok = netns_ok
        world = self

        class Admin:
            async def put_webapp(self, name: str, body: Any) -> Any:
                world.events.append("put")
                return SimpleNamespace(status_code=200, text="")

            async def get_webapp(self, name: str) -> dict[str, Any]:
                return {"tg_resource_id": "RES-INS"}

        class Tenant:
            async def discover_new(self, kind: str, **sel: str) -> list[tuple[str, str]]:
                world.events.append("discover")
                return [("RES-INS", sel["name"])]

            def record(self, kind: str, object_id: str, name: str = "") -> None:
                world.events.append("record")

            async def grant_access(self, ids: list[str]) -> None:
                world.events.append("grant")

        class FakeDockerRestart:
            @staticmethod
            def container(service: str) -> str:
                return f"{NAMES.project}-{service}"

            async def restart(self, container: str) -> None:
                world.events.append(f"restart:{container.rsplit('-', 1)[-1]}")

            async def curl_shares_client_netns(self) -> bool:
                world.events.append("netns-check")
                return world.netns_ok

        class Http:
            async def wait_for(self, url: str, want: int, *, timeout: float = 180.0, **_kw: Any):
                world.events.append(f"wait:{url.split('//')[1].split('.')[0]}")
                world.waits.append((url, want, timeout))
                return CurlResult(0, want)

        self.log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
        self.checks = checks.Checks(
            SimpleNamespace(
                names=NAMES,
                admin=Admin(),
                tenant=Tenant(),
                docker=FakeDockerRestart(),
                http=Http(),
                log=self.log,
            )  # type: ignore[arg-type]
        )


async def test_5b_restarts_the_client_then_curl_after_the_grant_and_reverifies(
    tmp_path: Path,
) -> None:
    world = InsecureAllowlistedWorld(tmp_path)
    detail = await world.checks.insecure_allowlisted()
    assert world.events == [
        "put",
        "discover",
        "record",
        "grant",
        "restart:client",
        "restart:curl",
        "netns-check",
        "wait:echo-plain",
        "wait:echo-insecure",
    ]
    assert "restarted" in detail


async def test_5b_waits_for_a_known_good_app_and_then_the_new_one_with_the_existing_timeout(
    tmp_path: Path,
) -> None:
    world = InsecureAllowlistedWorld(tmp_path)
    await world.checks.insecure_allowlisted()
    assert world.waits == [
        (f"http://{NAMES.plain_host}/", 200, 300),
        (f"http://{NAMES.insecure_host}/", 200, 300),
    ]


async def test_5b_records_the_restart_in_the_run_log(tmp_path: Path) -> None:
    world = InsecureAllowlistedWorld(tmp_path)
    await world.checks.insecure_allowlisted()
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "client-restart reason=resource created mid-run" in written
    assert f"{NAMES.project}-client" in written and f"{NAMES.project}-curl" in written
    assert "client-restart result=client up" in written


async def test_5b_fails_when_curl_lost_the_clients_network_namespace(tmp_path: Path) -> None:
    world = InsecureAllowlistedWorld(tmp_path, netns_ok=False)
    with pytest.raises(CheckFailed, match="network namespace"):
        await world.checks.insecure_allowlisted()
    assert not any(e.startswith("wait:") for e in world.events)


async def test_docker_restart_restarts_the_named_container_with_a_short_stop_timeout(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner()
    await _docker(tmp_path, runner).restart(f"{NAMES.project}-client")
    assert runner.calls[0][0] == ["docker", "restart", "-t", "10", f"{NAMES.project}-client"]


class NetnsRunner:
    """Scripted inspect/exec answers for the shared-namespace check."""

    def __init__(
        self,
        *,
        mode: str,
        client_dev: str | None,
        curl_dev: str | None,
        client_id: str = "abc123",
    ) -> None:
        self.mode, self.client_id = mode, client_id
        self.client_dev, self.curl_dev = client_dev, curl_dev

    async def __call__(self, argv: Sequence[str], env: Mapping[str, str], timeout: float) -> Any:
        words = list(argv)
        if words[1] == "inspect" and words[-1].endswith("-client"):
            return CommandResult(0, f"{self.client_id}\n", "")
        if words[1] == "inspect":
            return CommandResult(0, f"{self.mode}\n", "")
        if words[1] == "exec":
            dev = self.client_dev if words[2].endswith("-client") else self.curl_dev
            return (
                CommandResult(0, dev or "", "") if dev is not None else CommandResult(126, "", "")
            )
        return CommandResult(0, "", "")


_DEV = "Inter-|   Receive\n  eth0: 1 2\n    lo: 3 4\n"


@pytest.mark.parametrize(
    ("mode", "client_dev", "curl_dev", "expected"),
    [
        ("container:abc123", _DEV, _DEV, True),
        ("container:old999", _DEV, _DEV, False),
        ("bridge", _DEV, _DEV, False),
        ("container:abc123", _DEV, "  lo: 1 2\n", False),
        ("container:abc123", None, _DEV, True),
        ("container:abc123", _DEV, None, True),
    ],
)
async def test_curl_shares_client_netns_checks_the_mode_and_the_interfaces(
    tmp_path: Path, mode: str, client_dev: str | None, curl_dev: str | None, expected: bool
) -> None:
    runner = NetnsRunner(mode=mode, client_dev=client_dev, curl_dev=curl_dev)
    docker = Docker(
        RunLog(tmp_path / "run.log", Redactor(), echo=False),
        NAMES,
        COMPOSE_FILE,
        {"RIG_PROJECT": NAMES.project},
        runner=runner,
    )
    assert await docker.curl_shares_client_netns() is expected


def test_the_curl_service_joins_the_clients_network_namespace_by_service() -> None:
    services = _services()
    assert services["curl"]["network_mode"] == "service:client"
    assert services["curl"]["depends_on"] == ["client"]


# --- teardown never skips the sweep or compose down -------------------------------------------


class StepDocker:
    """Docker stand-in whose steps can be made to raise; records down_stack."""

    def __init__(self, *, stop: Any = True, down: Any = None) -> None:
        self._stop, self._down = stop, down
        self.downs = 0

    async def stop_gwops(self) -> bool:
        if isinstance(self._stop, BaseException):
            raise self._stop
        return bool(self._stop)

    async def down_stack(self) -> None:
        self.downs += 1
        if self._down is not None:
            raise self._down


class StepTenant:
    """Tenant stand-in whose record/cleanup can raise."""

    def __init__(self, tmp_path: Path, *, record: Any = None, cleanup: Any = None) -> None:
        self.state_path = tmp_path / "state.json"
        self._record, self._cleanup = record, cleanup

    async def record_discovered(self) -> list[Any]:
        if self._record is not None:
            raise self._record
        return []

    async def cleanup(self, *, only_kinds: Any = None) -> Any:
        if self._cleanup is not None:
            raise self._cleanup
        return SimpleNamespace(deleted=[], already_gone=[], inventory_compared=True)


def _step_log(tmp_path: Path) -> RunLog:
    return RunLog(tmp_path / "run.log", Redactor(), echo=False)


async def test_every_step_failing_still_runs_compose_down_and_records_each_error(
    tmp_path: Path,
) -> None:
    async def dump() -> None:
        raise RuntimeError("dump failed")

    docker = StepDocker(stop=RuntimeError("stop exploded"), down=RuntimeError("down exploded"))
    tenant = StepTenant(tmp_path, record=ValueError("discovery"), cleanup=KeyError("sweep"))
    result = await teardown.stop_sweep_down(
        tenant,  # type: ignore[arg-type]
        docker,  # type: ignore[arg-type]
        _step_log(tmp_path),
        before_sweep=dump,
    )
    text = "\n".join(result.errors)
    for needle in ("stop exploded", "discovery", "sweep", "down exploded", "may still be running"):
        assert needle in text
    assert docker.downs == 1
    assert result.ok is False
    assert "log-dump-failed" in (tmp_path / "run.log").read_text(encoding="utf-8")


async def test_compose_down_runs_even_when_a_step_is_cancelled(tmp_path: Path) -> None:
    docker = StepDocker(stop=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await teardown.stop_sweep_down(
            StepTenant(tmp_path),  # type: ignore[arg-type]
            docker,  # type: ignore[arg-type]
            _step_log(tmp_path),
        )
    assert docker.downs == 1


async def test_a_teardown_that_raises_records_assertion_11_and_the_recovery_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())

    async def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("everything broke")

    monkeypatch.setattr(run.teardown, "stop_sweep_down", boom)
    await rig.teardown()
    await rig.admin.aclose()
    assert rig.book.results[0].number == "11"
    assert rig.book.results[0].outcome is Outcome.FAIL
    assert "everything broke" in rig.book.results[0].detail
    assert any(
        run.recovery_command(rig.tenant.state_path) in e  # type: ignore[attr-defined]
        for e in rig.book.infrastructure_errors
    )


def _failing_rig_class(torn: list[str]) -> Any:
    rig_class, _noop = _fake_rig_class(torn, [], 0.0)

    async def failing_close() -> None:
        raise OSError("close failed")

    async def failing_teardown(self: Any) -> None:
        raise RuntimeError("teardown failed")

    class Rig(rig_class):  # type: ignore[valid-type, misc]
        def __init__(self, *a: Any) -> None:
            super().__init__(*a)
            self.admin = SimpleNamespace(aclose=failing_close)
            self.finished = False

        teardown = failing_teardown

        def finish(self) -> int:
            torn.append("finish")
            return self.book.exit_code()

    return Rig


async def test_a_failing_teardown_and_failing_closes_still_reach_finish_and_close_the_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    torn: list[str] = []
    closed: list[str] = []

    async def tenant_close() -> None:
        closed.append("tenant")
        raise OSError("tenant close failed")

    async def fake_start(env: Any, **_kw: Any) -> Any:
        return SimpleNamespace(
            prefix=NAMES.prefix, aclose=tenant_close, state_path=Path("run/state.json")
        )

    async def fake_preflight(_image: str) -> Any:
        return dockerops.LocalEngine("ctx", "unix:///x", "sha256:feed")

    monkeypatch.setattr(run, "Rig", _failing_rig_class(torn))
    monkeypatch.setattr(run.RigTenant, "start", fake_start)
    monkeypatch.setattr(run, "preflight_local", fake_preflight)
    env = approved_env()
    code = await run.execute(env, SimpleNamespace(image="gwops-gateway:dev"))
    assert code == 1
    assert torn == ["finish"]
    assert closed == ["tenant"]


def test_an_error_after_the_tenant_was_reached_is_error_1_never_refused_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _valid_env(monkeypatch)
    closed: list[str] = []

    async def tenant_close() -> None:
        closed.append("tenant")

    async def fake_start(env: Any, **_kw: Any) -> Any:
        return SimpleNamespace(prefix=NAMES.prefix, aclose=tenant_close, state_path=Path("s.json"))

    async def fake_preflight(_image: str) -> Any:
        return dockerops.LocalEngine("ctx", "unix:///x", "sha256:feed")

    def broken_rig(*_a: Any) -> Any:
        raise ValueError(f"constructor failed {API_KEY}")

    monkeypatch.setattr(run, "Rig", broken_rig)
    monkeypatch.setattr(run.RigTenant, "start", fake_start)
    monkeypatch.setattr(run, "preflight_local", fake_preflight)
    monkeypatch.setattr(run, "install_cancel_handlers", lambda *_a: None)
    assert run.main([]) == 1
    out = capsys.readouterr().out
    assert out.startswith("ERROR") and "REFUSED" not in out
    assert API_KEY not in out
    assert "state.json" in out or "s.json" in out
    assert closed == ["tenant"]


# --- admin errors carry a status; only transport errors are retried ---------------------------


class Clock:
    """A fake monotonic clock that `asyncio.sleep` advances."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clock = Clock()
    monkeypatch.setattr(run, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(run.asyncio, "sleep", clock.sleep)
    return clock


class ScriptedAdmin:
    """An admin whose calls raise a scripted AdminError (or return a scripted dict)."""

    def __init__(self, *, status: Any = None, webapp: Any = None, reconcile: Any = None) -> None:
        self._status, self._webapp, self._reconcile = status, webapp, reconcile
        self.webapp_calls = 0

    @staticmethod
    def _outcome(value: Any) -> dict[str, Any]:
        if isinstance(value, Exception):
            raise value
        return dict(value if value is not None else {})

    async def status(self) -> dict[str, Any]:
        return self._outcome(self._status)

    async def get_webapp(self, name: str) -> dict[str, Any]:
        self.webapp_calls += 1
        return self._outcome(self._webapp)

    async def reconcile(self) -> dict[str, Any]:
        return self._outcome(self._reconcile)

    async def healthz(self) -> bool:
        return False

    async def aclose(self) -> None:
        return None


def test_admin_error_carries_the_http_status_or_none_for_a_transport_error() -> None:
    assert AdminError("x").status is None
    assert AdminError("x", 503).status == 503


async def test_the_admin_client_sets_status_on_http_errors_and_none_on_transport_errors() -> None:
    import httpx

    def handler(request: Any) -> Any:
        if request.url.path == "/status":
            return httpx.Response(401)
        raise httpx.ConnectError("refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    admin = AdminClient(1, "tok", client=client)
    with pytest.raises(AdminError) as http_error:
        await admin.status()
    assert http_error.value.status == 401
    with pytest.raises(AdminError) as transport_error:
        await admin.get_webapp("x")
    assert transport_error.value.status is None
    await admin.aclose()


@pytest.mark.parametrize("status", [401, 403])
async def test_wait_admin_raises_at_once_when_the_token_is_rejected(
    tmp_path: Path, fake_clock: Clock, status: int
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.admin = ScriptedAdmin(status=AdminError("GET /status: HTTP", status))  # type: ignore[assignment]
    with pytest.raises(run.RigError, match="rejected the token"):
        await rig.wait_admin()
    assert fake_clock.now == 0


async def test_wait_admin_retries_transport_errors_and_names_the_last_one_on_timeout(
    tmp_path: Path, fake_clock: Clock
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.admin = ScriptedAdmin(status=AdminError("GET /status: ConnectError"))  # type: ignore[assignment]
    with pytest.raises(run.RigError, match=r"last admin error: GET /status: ConnectError"):
        await rig.wait_admin()
    assert fake_clock.now >= 240
    log = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert log.count("admin-retry") == 1


async def test_wait_admin_does_not_retry_a_server_error(tmp_path: Path, fake_clock: Clock) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.admin = ScriptedAdmin(status=AdminError("GET /status: HTTP 500", 500))  # type: ignore[assignment]
    with pytest.raises(run.RigError, match="HTTP 500"):
        await rig.wait_admin()
    assert fake_clock.now == 0


async def test_wait_apps_created_retries_an_expected_404_and_logs_it(
    tmp_path: Path, fake_clock: Clock
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.admin = ScriptedAdmin(webapp=AdminError("GET x: HTTP 404", 404))  # type: ignore[assignment]
    with pytest.raises(run.RigError, match=r"never reached the tenant.*last admin error: GET x"):
        await rig.wait_apps_created()
    assert "admin-retry what=GET" in (tmp_path / "run.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("status", [401, 403, 409, 500])
async def test_wait_apps_created_raises_at_once_on_any_other_http_status(
    tmp_path: Path, fake_clock: Clock, status: int
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    admin = ScriptedAdmin(webapp=AdminError(f"GET x: HTTP {status}", status))
    rig.admin = admin  # type: ignore[assignment]
    with pytest.raises(run.RigError):
        await rig.wait_apps_created()
    assert admin.webapp_calls == 1


async def test_wait_reconcile_settled_raises_when_the_token_is_rejected(
    tmp_path: Path, fake_clock: Clock
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.admin = ScriptedAdmin(status=AdminError("GET /status: HTTP 403", 403))  # type: ignore[assignment]
    with pytest.raises(run.RigError, match="rejected the token"):
        await rig.wait_reconcile_settled("before")


async def test_wait_reconcile_settled_names_the_last_transport_error_on_timeout(
    tmp_path: Path, fake_clock: Clock
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.admin = ScriptedAdmin(status=AdminError("GET /status: ReadTimeout"))  # type: ignore[assignment]
    with pytest.raises(run.RigError, match=r"last admin error: GET /status: ReadTimeout"):
        await rig.wait_reconcile_settled("before")


# --- header and query scrubbing of gateway audit lines ----------------------------------------


def _audit_line(request: dict[str, Any], response: dict[str, Any] | None = None) -> str:
    inner: dict[str, Any] = {"request": request, "response": response or {}}
    return json.dumps(
        {"event": "gateway.line", "stream": "stdout", "level": "info", "line": json.dumps(inner)}
    )


_SECRET_REQUEST = {
    "url": "/api/items?token=QUERYSECRET99&page=2",
    "headers": {
        "Authorization": ["Basic dXNlcjpCQVNJQ1NFQ1JFVA=="],
        "Cookie": ["sid=COOKIESECRET77"],
        "X-Api-Key": ["APIKEYSECRET55"],
        "Accept": ["*/*"],
        "X-Twingate-User": ["svc-user"],
    },
}
_SECRET_RESPONSE = {
    "headers": {"Set-Cookie": ["session=SETCOOKIESECRET33"], "Content-Type": ["text/plain"]}
}
_SECRETS = ("BASICSECRET", "dXNlcjpCQVNJQ1NFQ1JFVA", "COOKIESECRET77", "APIKEYSECRET55")


def test_gateway_audit_lines_lose_credential_headers_and_query_strings() -> None:
    raw = _audit_line(_SECRET_REQUEST, _SECRET_RESPONSE)
    scrubbed = logfilter.filter_gwops_log(raw)
    for secret in (*_SECRETS, "SETCOOKIESECRET33", "QUERYSECRET99"):
        assert secret not in scrubbed
    inner = json.loads(json.loads(scrubbed)["line"])
    assert inner["request"]["url"] == "/api/items?[redacted]"
    assert inner["request"]["headers"]["Authorization"] == ["[redacted]"]
    assert inner["response"]["headers"]["Set-Cookie"] == ["[redacted]"]
    assert inner["request"]["headers"]["Accept"] == ["*/*"]
    assert inner["request"]["headers"]["X-Twingate-User"] == ["svc-user"]
    assert inner["response"]["headers"]["Content-Type"] == ["text/plain"]


@pytest.mark.parametrize(
    "name",
    [
        "Accept",
        "User-Agent",
        "Content-Type",
        "Content-Length",
        "X-Rig-Rewrite",
        "X-Twingate-User",
        "X_Twingate_User",
        "X_twingate_user",
        "X-Forwarded-Proto",
    ],
)
def test_allowlisted_headers_keep_their_values(name: str) -> None:
    line = _audit_line({"headers": {name: ["keep-me"]}})
    inner = json.loads(json.loads(logfilter.scrub_gwops_line(line))["line"])
    assert inner["request"]["headers"][name] == ["keep-me"]


@pytest.mark.parametrize("name", ["Authorization", "Proxy-Authorization", "Host", "X-Custom-Token"])
def test_every_other_header_is_redacted(name: str) -> None:
    line = _audit_line({"headers": {name: ["value-123"]}})
    assert "value-123" not in logfilter.scrub_gwops_line(line)


def test_a_url_without_a_query_keeps_its_path_and_other_events_pass_unchanged() -> None:
    line = _audit_line({"url": "/plain/path", "headers": {}})
    assert json.loads(json.loads(logfilter.scrub_gwops_line(line))["line"])["request"]["url"] == (
        "/plain/path"
    )
    other = json.dumps({"event": "reconcile.done", "ok": True})
    assert logfilter.scrub_gwops_line(other) == other


def test_a_non_json_gateway_line_is_left_for_the_regular_redactor() -> None:
    raw = json.dumps({"event": "gateway.line", "line": f"plain text Authorization: Bearer {GAT}"})
    assert logfilter.scrub_gwops_line(raw) == raw
    assert GAT not in Redactor().redact(raw)


async def test_the_teardown_dump_scrubs_escaped_audit_lines_before_writing(
    tmp_path: Path,
) -> None:
    raw = _audit_line(_SECRET_REQUEST, _SECRET_RESPONSE)
    rig = _rig(tmp_path, [], RecordingRunner())
    runner = LogsRunner({"gwops": raw})
    rig.docker = Docker(rig.log, NAMES, COMPOSE_FILE, {"RIG_PROJECT": NAMES.project}, runner=runner)
    await rig.dump_logs()
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    for secret in (*_SECRETS, "SETCOOKIESECRET33", "QUERYSECRET99"):
        assert secret not in written
    assert "svc-user" in written
    await rig.admin.aclose()


async def test_diagnostic_gwops_logs_are_scrubbed_too(tmp_path: Path) -> None:
    class AuditDocker(DiagDocker):
        async def logs(self, container: str, *, since: str | None = None, **_kw: Any) -> str:
            return _audit_line(_SECRET_REQUEST) if container.endswith("-gwops") else "client"

    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    await diagnose.diagnose_failure(
        AuditDocker(),
        SimpleNamespace(last=None),
        log,
        "2a",
        wall_start=datetime.now(UTC),
        mono_start=0.0,
    )
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "COOKIESECRET77" not in written and "QUERYSECRET99" not in written


def test_filters_keep_the_extra_levels_and_failure_words() -> None:
    def event(level: str) -> str:
        return json.dumps({"event": "x", "level": level})

    kept = logfilter.filter_gwops_log(
        "\n".join(event(lv) for lv in ("warn", "err", "fatal", "info"))
    )
    assert [json.loads(k)["level"] for k in kept.splitlines()] == ["warn", "err", "fatal"]
    client = "INFO fine\nlogin failed\naccess denied\nFATAL boom\nINFO ok"
    assert logfilter.filter_client_log(client).splitlines() == [
        "login failed",
        "access denied",
        "FATAL boom",
    ]


# --- skew evidence tied to the request window -------------------------------------------------


def _gw_line(stamp: datetime, text: str = "401: token used before issued") -> str:
    return json.dumps(
        {
            "event": "gateway.line",
            "stream": "stdout",
            "timestamp": stamp.isoformat().replace("+00:00", "Z"),
            "line": text,
        }
    )


async def test_skew_evidence_keeps_only_marked_lines_inside_the_request_window(
    tmp_path: Path,
) -> None:
    start = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
    from datetime import timedelta

    lines = [
        _gw_line(start - timedelta(seconds=30)),
        _gw_line(start - timedelta(seconds=1)),
        _gw_line(start + timedelta(seconds=1)),
        _gw_line(start + timedelta(seconds=2), "something else"),
        "not json but token used before issued",
        json.dumps({"event": "gateway.line", "line": "token used before issued"}),
    ]
    runner = RecordingRunner(replies={"logs": CommandResult(0, "\n".join(lines), "")})
    evidence = await _docker(tmp_path, runner).skew_evidence(start)
    assert evidence == [lines[1], lines[2]]
    logs_call = next(argv for argv, _env in runner.calls if "logs" in argv)
    assert logs_call[logs_call.index("--since") + 1] == diagnose.since_arg(start)


class EvidenceDocker:
    """curl results plus one evidence list per request."""

    def __init__(self, results: list[CurlResult], evidence: list[Any]) -> None:
        self.results, self.evidence = list(results), list(evidence)
        self.curl_calls = 0

    async def skew_evidence(self, since: datetime) -> list[str]:
        item = self.evidence.pop(0)
        if isinstance(item, Exception):
            raise item
        return list(item)

    async def curl(self, url: str, **_kwargs: Any) -> CurlResult:
        self.curl_calls += 1
        return self.results.pop(0)


def _evidence_http(tmp_path: Path, fake: EvidenceDocker) -> tuple[checks.RigHttp, ResultBook]:
    book = ResultBook()
    log = RunLog(tmp_path / "run.log", Redactor(), echo=False)
    return checks.RigHttp(fake, log, book), book  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "first", [CurlResult(0, 200), CurlResult(0, 502), CurlResult(56), CurlResult(0, 401)]
)
async def test_any_outcome_is_retried_once_when_skew_was_logged_during_the_request(
    tmp_path: Path, first: CurlResult
) -> None:
    fake = EvidenceDocker([first, CurlResult(0, 200)], [[_gw_line(datetime.now(UTC))]])
    http, book = _evidence_http(tmp_path, fake)
    assert (await http.get("http://x/")).status == 200
    assert fake.curl_calls == 2
    assert book.skew_retries == ["http://x/"]


async def test_the_retry_is_bounded_to_one_even_if_evidence_persists(tmp_path: Path) -> None:
    fake = EvidenceDocker([CurlResult(0, 401), CurlResult(0, 401)], [["line"], ["line"]])
    http, book = _evidence_http(tmp_path, fake)
    assert (await http.get("http://x/")).status == 401
    assert fake.curl_calls == 2
    assert len(book.skew_retries) == 1


async def test_no_evidence_means_no_retry_even_for_a_401(tmp_path: Path) -> None:
    fake = EvidenceDocker([CurlResult(0, 401)], [[]])
    http, book = _evidence_http(tmp_path, fake)
    assert (await http.get("http://x/")).status == 401
    assert fake.curl_calls == 1 and book.skew_retries == []


async def test_the_skew_retry_logs_the_matched_line_scrubbed_and_redacted(tmp_path: Path) -> None:
    inner = json.dumps(
        {"request": {"headers": {"Cookie": ["COOKIESECRET77"]}}, "msg": "token used before issued"}
    )
    line = json.dumps({"event": "gateway.line", "timestamp": "2026-10-08T12:00:00Z", "line": inner})
    fake = EvidenceDocker([CurlResult(0, 200), CurlResult(0, 200)], [[line]])
    http, _book = _evidence_http(tmp_path, fake)
    await http.get("http://x/")
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "skew-retry url=http://x/" in written
    assert "token used before issued" in written
    assert "COOKIESECRET77" not in written


async def test_a_failing_evidence_check_is_logged_and_does_not_break_the_request(
    tmp_path: Path,
) -> None:
    fake = EvidenceDocker([CurlResult(0, 200)], [DockerError("engine gone")])
    http, book = _evidence_http(tmp_path, fake)
    assert (await http.get("http://x/")).status == 200
    assert book.skew_retries == []
    assert "skew-check-failed" in (tmp_path / "run.log").read_text(encoding="utf-8")


async def test_docker_logs_raises_on_failure_but_not_for_an_absent_container(
    tmp_path: Path,
) -> None:
    absent = RecordingRunner(replies={"logs": CommandResult(1, "", "Error: No such container: x")})
    assert await _docker(tmp_path, absent).logs("x") == ""
    broken = RecordingRunner(replies={"logs": CommandResult(1, "", "Cannot connect to the daemon")})
    with pytest.raises(DockerError, match="docker logs x exited 1"):
        await _docker(tmp_path, broken).logs("x")


# --- hold cap, secret file modes, leaf-key cleanup --------------------------------------------


def test_hold_max_is_capped_at_four_hours() -> None:
    assert run.parse_args(["--hold-max", "14400"]).hold_max == 14400.0
    for bad in ("14401", "0", "-5"):
        with pytest.raises(SystemExit):
            run.parse_args(["--hold-max", bad])


async def test_the_hold_itself_clamps_to_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _rig(tmp_path, [], RecordingRunner())
    monkeypatch.setattr(run, "HOLD_CAP_SECONDS", 0.05)
    assert await rig.hold(10_000, poll_seconds=0.01) == "expired"
    await rig.admin.aclose()


async def test_the_admin_token_goes_to_its_own_0600_file_and_the_banner_points_at_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modes: dict[str, int] = {}
    real = os.open

    def spy(path: Any, flags: int, mode: int = 0o777, **kw: Any) -> int:
        modes[Path(path).name] = mode
        return real(path, flags, mode, **kw)

    monkeypatch.setattr(os, "open", spy)
    rig = _rig(tmp_path, [], RecordingRunner())
    rig.tenant.address_error = guards.GatewayAddressInUseError("stop")  # type: ignore[attr-defined]
    with pytest.raises(guards.GatewayAddressInUseError):
        await rig.bring_up()
    assert (tmp_path / "admin-token").read_text(encoding="utf-8").strip() == rig.admin_token
    assert modes["admin-token"] == 0o600
    banner = "\n".join(rig.hold_instructions(60))
    assert str(tmp_path / "admin-token") in banner
    assert "gwops.env" not in banner
    assert rig.admin_token not in banner
    await rig.admin.aclose()


async def test_down_stack_deletes_the_leaf_keys_and_the_admin_token(tmp_path: Path) -> None:
    pki = tmp_path / "pki"
    pki.mkdir()
    for name in ("echo.key", "verifier.key", "wrong-host.key", "echo.crt"):
        (pki / name).write_text("x", encoding="utf-8")
    (tmp_path / "admin-token").write_text("tok", encoding="utf-8")
    runner = RecordingRunner()
    await _docker(tmp_path, runner).down_stack()
    assert sorted(p.name for p in pki.iterdir()) == ["echo.crt"]
    assert not (tmp_path / "admin-token").exists()


async def test_the_leaf_keys_are_deleted_even_when_compose_down_fails(tmp_path: Path) -> None:
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "echo.key").write_text("x", encoding="utf-8")
    runner = RecordingRunner(replies={"compose": CommandResult(1, "", "down failed")})
    with pytest.raises(DockerError):
        await _docker(tmp_path, runner).down_stack()
    assert not (pki / "echo.key").exists()


def test_the_compose_and_shim_comments_state_the_stream_carries_headers_verbatim() -> None:
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    shim = (SHIM_DIR / "gateway-stdio.sh").read_text(encoding="utf-8")
    for text in (compose, shim):
        assert "nothing sensitive" not in text
        assert "verbatim" in text
        assert "recording.enabled" in text
        assert "logfilter" in text


# --- docstring shape, log truncation, empty inventory -----------------------------------------


def test_the_named_docstrings_are_one_line() -> None:
    import inspect

    targets = [
        run,
        diagnose,
        pki.generate_rig_pki,
        tenant.RigTenant.discover_all,
        tenant.RigTenant.sweep,
        tenant.RigTenant.cleanup,
        tenant.RigTenant.resume,
        teardown.stop_sweep_down,
        Docker.curl_shares_client_netns,
        checks.Checks._restart_client_for_new_resource,
        run.Rig.hold,
    ]
    for target in targets:
        doc = inspect.getdoc(target) or ""
        assert doc and "\n" not in doc, getattr(target, "__name__", target)


def test_block_redacts_before_it_truncates(tmp_path: Path) -> None:
    secret = "SECRETVALUE-0123456789"
    log = RunLog(tmp_path / "run.log", Redactor([secret]), echo=False)
    text = "a" * 40 + secret + "b" * 10
    log.block("t", text, max_chars=len(secret) // 2 + 10)
    written = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "[truncated]" in written
    assert secret[len(secret) // 2 :] not in written and "0123456789" not in written


def test_rig_names_no_longer_carry_the_unused_ca_names_helper() -> None:
    assert not hasattr(NAMES, "ca_names")
    assert guards.derived_ca_names(NAMES.gateway_address)[0].startswith("gwops-x509-")


async def test_report_says_nothing_to_compare_when_there_was_no_inventory(
    tmp_path: Path,
) -> None:
    class Cleanup(FakeTenant):
        async def cleanup(self, *, only_kinds: Any = None) -> Any:
            await super().cleanup(only_kinds=only_kinds)
            return SimpleNamespace(deleted=[], already_gone=[], inventory_compared=False)

    events: list[str] = []
    env = approved_env()
    args = SimpleNamespace(image="gwops-gateway:dev", apply_timeout=None)
    rig = run.Rig(env, Cleanup(tmp_path, events), NAMES, args)  # type: ignore[arg-type]
    rig.docker = _docker(
        tmp_path, RecordingRunner(events, {"inspect": CommandResult(0, "false\n", "")})
    )
    await rig.teardown()
    await rig.admin.aclose()
    assert "nothing to compare" in rig.book.results[0].detail


# --- no 200 at all is a failure, not a finding ------------------------------------------------


class RewriteWorld:
    def __init__(self, tmp_path: Path, *, statuses: list[int]) -> None:
        self.statuses = list(statuses)
        base_claims = {"jti": "J0", "exp": 4_000_000_000}
        base = CurlResult(0, 200, {}, json.dumps({"claims": base_claims, "headers": {}}))
        world = self

        class Http:
            async def wait_for(self, url: str, want: int, **_kw: Any) -> CurlResult:
                return base

            async def get(self, url: str, **_kw: Any) -> CurlResult:
                status = world.statuses.pop(0) if world.statuses else 502
                if status == 200:
                    body = json.dumps({"claims": {"jti": "J0"}, "headers": {}})
                    return CurlResult(0, 200, {}, body)
                return CurlResult(0, status)

        class Admin:
            async def put_webapp(self, name: str, body: Any) -> Any:
                return SimpleNamespace(status_code=200, text="")

        self.book = ResultBook()
        self.checks = checks.Checks(
            SimpleNamespace(
                names=NAMES,
                http=Http(),
                admin=Admin(),
                book=self.book,
                log=RunLog(tmp_path / "run.log", Redactor(), echo=False),
                apply_timeout=0.2,
            )  # type: ignore[arg-type]
        )


async def test_rewrite_with_no_200_while_polling_is_a_failure_with_the_last_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = RewriteWorld(tmp_path, statuses=[502, 502])

    real_sleep = asyncio.sleep

    async def fast(_s: float) -> None:
        await real_sleep(0.01)

    monkeypatch.setattr(checks.asyncio, "sleep", fast)
    with pytest.raises(CheckFailed, match=r"no 200 from .* last result exit=0 status=502"):
        await world.checks.rewrite_applies()


async def test_rewrite_with_200s_but_no_rewrite_is_a_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = RewriteWorld(tmp_path, statuses=[200] * 200)

    real_sleep = asyncio.sleep

    async def fast(_s: float) -> None:
        await real_sleep(0.01)

    monkeypatch.setattr(checks.asyncio, "sleep", fast)
    with pytest.raises(CheckFinding, match="not applied"):
        await world.checks.rewrite_applies()


# --- late skew evidence after a connection-level failure ---------------------------------------


class ClockedEvidenceDocker:
    """curl results plus an evidence function; counts skew checks."""

    def __init__(self, results: list[CurlResult], evidence_after: int | None) -> None:
        self.results = list(results)
        self.evidence_after = evidence_after
        self.checks = 0
        self.curl_calls = 0

    async def skew_evidence(self, since: datetime) -> list[str]:
        self.checks += 1
        late = self.evidence_after is not None and self.checks > self.evidence_after
        return ["late skew line"] if late else []

    async def curl(self, url: str, **_kwargs: Any) -> CurlResult:
        self.curl_calls += 1
        return self.results.pop(0)


@pytest.fixture
def checks_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clock = Clock()
    monkeypatch.setattr(checks, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(checks.asyncio, "sleep", clock.sleep)
    return clock


async def test_skew_evidence_arriving_late_after_a_connection_failure_triggers_the_retry(
    tmp_path: Path, checks_clock: Clock
) -> None:
    fake = ClockedEvidenceDocker([CurlResult(56), CurlResult(0, 200)], evidence_after=4)
    http, book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    assert (await http.get("http://x/")).status == 200
    assert fake.curl_calls == 2
    assert fake.checks == 5
    assert book.skew_retries == ["http://x/"]
    assert 0 < checks_clock.now < checks.SKEW_POLL_SECONDS


@pytest.mark.parametrize("exit_code", [7, 28, 35, 52, 55, 56])
async def test_no_evidence_inside_the_window_means_no_retry_and_the_wait_is_bounded(
    tmp_path: Path, checks_clock: Clock, exit_code: int
) -> None:
    fake = ClockedEvidenceDocker([CurlResult(exit_code)], evidence_after=None)
    http, book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    result = await http.get("http://x/")
    assert result.exit_code == exit_code
    assert fake.curl_calls == 1 and book.skew_retries == []
    assert checks.SKEW_POLL_SECONDS <= checks_clock.now < checks.SKEW_POLL_SECONDS + 0.5
    assert fake.checks == 1 + int(checks.SKEW_POLL_SECONDS / checks.SKEW_POLL_INTERVAL)


@pytest.mark.parametrize("status", [200, 401, 502, 503])
async def test_an_http_status_never_waits_for_late_evidence(
    tmp_path: Path, checks_clock: Clock, status: int
) -> None:
    fake = ClockedEvidenceDocker([CurlResult(0, status)], evidence_after=None)
    http, book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    assert (await http.get("http://x/")).status == status
    assert fake.checks == 1 and checks_clock.now == 0 and book.skew_retries == []


async def test_an_http_status_with_evidence_already_present_is_still_retried_without_waiting(
    tmp_path: Path, checks_clock: Clock
) -> None:
    fake = ClockedEvidenceDocker([CurlResult(0, 502), CurlResult(0, 200)], evidence_after=0)
    http, book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    assert (await http.get("http://x/")).status == 200
    assert fake.checks == 1 and checks_clock.now == 0
    assert book.skew_retries == ["http://x/"]


async def test_a_determinate_failure_such_as_a_tls_verify_error_does_not_wait(
    tmp_path: Path, checks_clock: Clock
) -> None:
    fake = ClockedEvidenceDocker([CurlResult(60)], evidence_after=None)
    http, _book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    assert (await http.get("https://x/")).exit_code == 60
    assert fake.checks == 1 and checks_clock.now == 0


async def test_the_retry_is_still_one_at_most_and_is_not_followed_by_another_poll(
    tmp_path: Path, checks_clock: Clock
) -> None:
    fake = ClockedEvidenceDocker([CurlResult(56), CurlResult(56)], evidence_after=1)
    http, book = _evidence_http(tmp_path, fake)  # type: ignore[arg-type]
    assert (await http.get("http://x/")).exit_code == 56
    assert fake.curl_calls == 2 and len(book.skew_retries) == 1
    assert fake.checks == 2
