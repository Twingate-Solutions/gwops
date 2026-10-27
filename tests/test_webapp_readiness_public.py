"""Readiness in public mode: coverage by certificate, no browser-trust reasons, new codes."""

import dataclasses
from datetime import UTC, datetime
from typing import Any

import pytest
import structlog.testing

from gwops.acme.runner import AcmeCertState, AcmeSnapshot, CertSnapshot
from gwops.acme.state import AcmeErrorClass
from gwops.configmodel.schema import EffectiveState
from gwops.reconciler.core import AcmeError, PublicCertStatus, ReconcileResult, RemoteWebApp
from gwops.webapp_readiness import (
    PublicReadinessInput,
    acme_snapshot,
    compute_readiness,
    public_input,
)
from tests.public_tls_support import ZONE, public_cert, public_seed, tls_block

GW = "g-1"
APP_HOST = f"grafana.{ZONE}"


def _state(
    *certs: dict[str, Any], alias: str | None = None, host: str = APP_HOST
) -> EffectiveState:
    app: dict[str, Any] = {"name": "grafana", "address": host}
    if alias is not None:
        app["alias"] = alias
    tls = tls_block(certificates=list(certs) or [public_cert("wild", [f"*.{ZONE}"])])
    return EffectiveState.model_validate(public_seed(tls, web_apps=[app]))


def _remote(host: str = APP_HOST, alias: str | None = None, **fields: Any) -> RemoteWebApp:
    values: dict[str, Any] = {
        "id": "r-grafana",
        "name": "grafana",
        "gateway_id": GW,
        "address": host,
        "upstream_port": 443,
        "alias": alias,
        "upstream_tls": "verify_full",
        "downstream_tls": "tls13",
        "downstream_port": 443,
        "header_rewrite_names": (),
        "managed": True,
    }
    values.update(fields)
    return RemoteWebApp(**values)


def _status(name: str, state: str = "ok") -> PublicCertStatus:
    return PublicCertStatus(
        name=name,
        names=(),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        state=state,  # type: ignore[arg-type]
        last_error=None,
        generation="0123456789ab",
    )


def _run(
    state: EffectiveState,
    remote: list[RemoteWebApp],
    statuses: list[PublicCertStatus],
    bound: bool | None = True,
) -> dict[str, Any]:
    assert state.public_tls is not None
    public = PublicReadinessInput(
        certificates=tuple(state.public_tls.certificates), statuses=tuple(statuses), bound=bound
    )
    result = ReconcileResult(
        ok=True, trigger="tick", started_at=datetime.now(UTC), remote_web_apps=remote
    )
    entries = compute_readiness(
        state,
        result,
        # A leaf with unrelated SANs: public mode must never consult it.
        {"unrelated.example"},
        ca_generated=True,
        on_demand=False,
        gateway_id=GW,
        public=public,
    )
    return {e.name: dataclasses.asdict(e) for e in entries}["grafana"]


def test_a_wildcard_certificate_covers_the_name_and_the_app_is_ready() -> None:
    entry = _run(_state(), [_remote()], [_status("wild")])

    assert entry["reasons"] == []
    assert entry["state"] == "ready"


def test_the_check_never_compares_against_the_leaf_sans() -> None:
    """The leaf holds only `unrelated.example`; wildcard-served names are still covered."""
    entry = _run(_state(), [_remote()], [_status("wild")])

    assert not any(r.startswith(("san_missing", "leaf_unreadable")) for r in entry["reasons"])


def test_a_name_no_certificate_covers_is_san_missing() -> None:
    state = _state(public_cert("api", [f"api.{ZONE}"]), host=f"api.{ZONE}")
    entry = _run(state, [_remote(host=f"grafana.{ZONE}")], [_status("api")])

    assert entry["reasons"] == [f"san_missing:grafana.{ZONE}"]
    assert entry["state"] == "action_required"


def test_an_uncovered_alias_is_san_missing_while_the_address_is_covered() -> None:
    alias = f"a.b.{ZONE}"  # two labels deep: `*.<zone>` does not match
    entry = _run(_state(), [_remote(alias=alias)], [_status("wild")])

    assert entry["reasons"] == [f"san_missing:{alias}"]


def test_an_invalid_certificate_is_action_required_on_the_apps_it_covers() -> None:
    entry = _run(_state(), [_remote()], [_status("wild", "invalid")])

    assert entry["reasons"] == ["public_cert_invalid:wild"]
    assert entry["state"] == "action_required"


def test_an_expiring_certificate_is_informational() -> None:
    entry = _run(_state(), [_remote()], [_status("wild", "expiring")])

    assert entry["reasons"] == ["public_cert_expiring:wild"]
    assert entry["state"] == "ready"


def test_a_certificate_is_reported_once_when_it_covers_address_and_alias() -> None:
    entry = _run(_state(), [_remote(alias=f"docs.{ZONE}")], [_status("wild", "invalid")])

    assert entry["reasons"] == ["public_cert_invalid:wild"]


def test_only_the_certificate_covering_the_app_is_reported() -> None:
    state = _state(public_cert("wild", [f"*.{ZONE}"]), public_cert("other", [f"api.{ZONE}"]))
    # `grafana.<zone>` is covered by `wild` only, so `other` being invalid is not its concern.
    entry = _run(state, [_remote()], [_status("wild"), _status("other", "invalid")])

    assert entry["reasons"] == []


def test_an_unbound_gateway_is_action_required() -> None:
    entry = _run(_state(), [_remote()], [_status("wild")], bound=False)

    assert entry["reasons"] == ["gateway_ca_unbound"]
    assert entry["state"] == "action_required"


def test_a_bound_or_unknown_binding_adds_no_reason() -> None:
    for bound in (True, None):
        assert _run(_state(), [_remote()], [_status("wild")], bound=bound)["reasons"] == []


def test_a_tls13_app_has_no_browser_trust_reason_even_with_ca_generated() -> None:
    entry = _run(_state(), [_remote(downstream_tls="tls13")], [_status("wild")])

    assert not {"operator_action", "byo_ca"} & {r.partition(":")[0] for r in entry["reasons"]}


def test_a_wildcard_address_stays_unverifiable() -> None:
    entry = _run(_state(), [_remote(host=f"*.{ZONE}")], [_status("wild")])

    assert "wildcard_address" in entry["reasons"]


def test_public_input_is_none_in_private_mode() -> None:
    state = EffectiveState.model_validate({"twingate": {"network": "acme", "gateway_id": GW}})
    result = ReconcileResult(ok=True, trigger="t", started_at=datetime.now(UTC))

    assert public_input(state, result) is None


def test_public_input_before_the_first_pass_has_no_statuses_and_unknown_binding() -> None:
    result = ReconcileResult(ok=True, trigger="t", started_at=datetime.now(UTC))

    public = public_input(_state(), result)

    assert public is not None
    assert public.statuses == ()
    assert public.bound is None
    assert [c.name for c in public.certificates] == ["wild"]


def test_a_pending_certificate_that_was_never_installed_is_action_required() -> None:
    """Valid but not installed (another certificate failed), and nothing serves it yet."""
    pending = dataclasses.replace(_status("wild", "pending"), generation=None, not_after=None)

    entry = _run(_state(), [_remote()], [pending])

    assert entry["reasons"] == ["public_cert_invalid:wild"]
    assert entry["state"] == "action_required"


def test_a_pending_certificate_with_a_served_copy_adds_no_reason() -> None:
    """Its last installed copy is still served; the failing certificate carries the action."""
    entry = _run(_state(), [_remote()], [_status("wild", "pending")])

    assert entry["reasons"] == []
    assert entry["state"] == "ready"


# --- source: acme -----------------------------------------------------------------------

_ACME_BLOCK: dict[str, Any] = {
    "email": "ops@example.com",
    "accept_tos": True,
    "directory": "production",
    "token_file": "/config/acme/cloudflare-token",
}
_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"


def _acme_cert(name: str = "issued", names: list[str] | None = None) -> dict[str, Any]:
    return {"name": name, "names": [f"*.{ZONE}"] if names is None else names, "source": "acme"}


def _acme_state(
    *certs: dict[str, Any], alias: str | None = None, directory: str = "production"
) -> EffectiveState:
    app: dict[str, Any] = {"name": "grafana", "address": APP_HOST}
    if alias is not None:
        app["alias"] = alias
    tls = tls_block(
        certificates=list(certs) or [_acme_cert()], acme={**_ACME_BLOCK, "directory": directory}
    )
    return EffectiveState.model_validate(public_seed(tls, web_apps=[app]))


def _acme_status(
    name: str = "issued", state: str = "pending", generation: str | None = None
) -> PublicCertStatus:
    """The pass's status of a ``source: acme`` certificate (pending, nothing installed)."""
    return PublicCertStatus(
        name=name,
        names=(),
        not_after=None if generation is None else datetime(2027, 1, 1, tzinfo=UTC),
        state=state,  # type: ignore[arg-type]
        last_error=None,
        generation=generation,
        source="acme",
    )


def _installed(name: str = "issued") -> PublicCertStatus:
    return _acme_status(name, "ok", generation="0123456789ab")


def _snap(name: str = "issued", **fields: Any) -> CertSnapshot:
    values: dict[str, Any] = {
        "name": name,
        "names": (f"*.{ZONE}",),
        "directory": _PRODUCTION,
        "staging": False,
        "state": AcmeCertState.IDLE,
        "installed": True,
        "installed_at": None,
        "installed_serial": None,
        "last_attempt_at": None,
        "last_success_at": None,
        "next_attempt_at": None,
        "error_code": None,
        "error_excerpt": None,
        "renewal_reason": None,
        "consecutive_failures": 0,
        "in_backoff": False,
        "retry_after": None,
    }
    values.update(fields)
    return CertSnapshot(**values)


def _snapshot(*certs: CertSnapshot, **fields: Any) -> AcmeSnapshot:
    values: dict[str, Any] = {
        "configured": True,
        "directory": _PRODUCTION,
        "staging": False,
        "running": None,
        "state_error": None,
        "certificates": certs,
    }
    values.update(fields)
    return AcmeSnapshot(**values)


def _run_acme(
    state: EffectiveState,
    statuses: list[PublicCertStatus],
    *,
    snapshot: AcmeSnapshot | None = None,
    config_error: bool = False,
    internal_error: bool = False,
    staging: bool = False,
    remote: list[RemoteWebApp] | None = None,
    bound: bool | None = True,
) -> dict[str, Any]:
    assert state.public_tls is not None
    public = PublicReadinessInput(
        certificates=tuple(state.public_tls.certificates),
        statuses=tuple(statuses),
        bound=bound,
        acme=snapshot,
        acme_config_error=config_error,
        acme_internal_error=internal_error,
        acme_staging=staging,
    )
    result = ReconcileResult(
        ok=True,
        trigger="tick",
        started_at=datetime.now(UTC),
        remote_web_apps=[_remote()] if remote is None else remote,
    )
    entries = compute_readiness(
        state,
        result,
        {"unrelated.example"},
        ca_generated=True,
        on_demand=False,
        gateway_id=GW,
        public=public,
    )
    return {e.name: dataclasses.asdict(e) for e in entries}["grafana"]


class TestAcmePending:
    def test_a_pending_acme_certificate_is_public_cert_pending_not_invalid(self) -> None:
        entry = _run_acme(_acme_state(), [_acme_status()])

        assert entry["reasons"] == ["public_cert_pending:issued"]
        assert entry["state"] == "action_required"
        assert "public_cert_invalid:issued" not in entry["reasons"]

    def test_a_pending_file_certificate_is_still_public_cert_invalid(self) -> None:
        """The same never-installed state on a ``source: file`` certificate keeps its code."""
        pending = dataclasses.replace(_status("wild", "pending"), generation=None, not_after=None)

        entry = _run(_state(), [_remote()], [pending])

        assert entry["reasons"] == ["public_cert_invalid:wild"]

    def test_pending_is_reported_once_when_the_snapshot_also_says_not_installed(self) -> None:
        snapshot = _snapshot(_snap(installed=False))

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot)

        assert entry["reasons"] == ["public_cert_pending:issued"]

    def test_a_staging_dry_run_stays_pending_with_no_failure_reason(self) -> None:
        snapshot = _snapshot(
            _snap(state=AcmeCertState.DRY_RUN_OK, staging=True, installed=False)
        )

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot)

        assert entry["reasons"] == ["public_cert_pending:issued"]
        assert entry["state"] == "action_required"

    def test_an_installed_acme_certificate_adds_no_reason(self) -> None:
        entry = _run_acme(_acme_state(), [_installed()], snapshot=_snapshot(_snap()))

        assert entry["reasons"] == []
        assert entry["state"] == "ready"

    def test_a_pending_certificate_is_not_reported_for_an_app_it_does_not_cover(self) -> None:
        state = _acme_state(
            _acme_cert("issued", [f"api.{ZONE}"]), _acme_cert("wild", [f"*.{ZONE}"])
        )

        entry = _run_acme(state, [_acme_status("issued"), _installed("wild")])

        assert entry["reasons"] == []

    def test_a_pending_certificate_is_reported_once_for_address_and_alias(self) -> None:
        entry = _run_acme(_acme_state(alias=f"docs.{ZONE}"), [_acme_status()])

        assert entry["reasons"] == ["public_cert_pending:issued"]


class TestAcmeFailed:
    @pytest.mark.parametrize("code", list(AcmeErrorClass))
    def test_a_recorded_failure_is_acme_failed_with_its_class(self, code: AcmeErrorClass) -> None:
        snapshot = _snapshot(_snap(error_code=code, state=AcmeCertState.FAILED))

        entry = _run_acme(_acme_state(), [_installed()], snapshot=snapshot)

        assert entry["reasons"] == [f"acme_failed:{code.value}"]
        assert entry["state"] == "action_required"

    def test_a_failure_with_nothing_installed_reports_pending_then_the_failure(self) -> None:
        snapshot = _snapshot(
            _snap(
                installed=False,
                error_code=AcmeErrorClass.DNS_AUTH,
                state=AcmeCertState.FAILED,
            )
        )

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_failed:dns_auth"]
        assert entry["state"] == "action_required"

    def test_an_expiring_certificate_that_is_failing_to_renew_reports_both(self) -> None:
        snapshot = _snapshot(_snap(error_code=AcmeErrorClass.INTERNAL))
        statuses = [dataclasses.replace(_installed(), state="expiring")]

        entry = _run_acme(_acme_state(), statuses, snapshot=snapshot)

        assert entry["reasons"] == ["public_cert_expiring:issued", "acme_failed:internal"]

    def test_a_failure_is_reported_once_for_address_and_alias(self) -> None:
        snapshot = _snapshot(_snap(error_code=AcmeErrorClass.TIMEOUT))

        entry = _run_acme(_acme_state(alias=f"docs.{ZONE}"), [_installed()], snapshot=snapshot)

        assert entry["reasons"] == ["acme_failed:timeout"]

    def test_a_config_error_is_acme_failed_config(self) -> None:
        entry = _run_acme(_acme_state(), [_installed()], config_error=True)

        assert entry["reasons"] == ["acme_failed:config"]
        assert entry["state"] == "action_required"

    def test_a_config_error_with_a_pending_certificate_reports_pending_then_config(self) -> None:
        entry = _run_acme(_acme_state(), [_acme_status()], config_error=True)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_failed:config"]

    def test_a_config_error_and_a_config_class_failure_are_reported_once(self) -> None:
        snapshot = _snapshot(_snap(error_code=AcmeErrorClass.CONFIG))

        entry = _run_acme(_acme_state(), [_installed()], snapshot=snapshot, config_error=True)

        assert entry["reasons"] == ["acme_failed:config"]

    def test_a_snapshot_without_the_certificate_adds_nothing(self) -> None:
        entry = _run_acme(_acme_state(), [_installed()], snapshot=_snapshot(_snap("elsewhere")))

        assert entry["reasons"] == []

    def test_a_failure_is_not_reported_for_an_app_the_certificate_does_not_cover(self) -> None:
        state = _acme_state(
            _acme_cert("issued", [f"api.{ZONE}"]), _acme_cert("wild", [f"*.{ZONE}"])
        )
        snapshot = _snapshot(
            _snap("issued", error_code=AcmeErrorClass.DNS_AUTH), _snap("wild")
        )

        entry = _run_acme(state, [_installed("issued"), _installed("wild")], snapshot=snapshot)

        assert entry["reasons"] == []

    def test_only_the_covering_certificates_failure_is_reported(self) -> None:
        state = _acme_state(
            _acme_cert("issued", [f"api.{ZONE}"]), _acme_cert("wild", [f"*.{ZONE}"])
        )
        snapshot = _snapshot(
            _snap("issued", error_code=AcmeErrorClass.DNS_AUTH),
            _snap("wild", error_code=AcmeErrorClass.RATE_LIMITED),
        )

        entry = _run_acme(state, [_installed("issued"), _installed("wild")], snapshot=snapshot)

        assert entry["reasons"] == ["acme_failed:rate_limited"]


class TestAcmeBackoff:
    def test_backoff_alone_is_informational(self) -> None:
        snapshot = _snapshot(_snap(in_backoff=True, state=AcmeCertState.BACKOFF))

        entry = _run_acme(_acme_state(), [_installed()], snapshot=snapshot)

        assert entry["reasons"] == ["acme_backoff"]
        assert entry["state"] == "ready"

    def test_failed_and_in_backoff_reports_the_failure_then_the_backoff(self) -> None:
        snapshot = _snapshot(
            _snap(
                error_code=AcmeErrorClass.RATE_LIMITED,
                in_backoff=True,
                state=AcmeCertState.BACKOFF,
            )
        )

        entry = _run_acme(_acme_state(), [_installed()], snapshot=snapshot)

        assert entry["reasons"] == ["acme_failed:rate_limited", "acme_backoff"]
        assert entry["state"] == "action_required"

    def test_a_pending_certificate_in_backoff_is_still_action_required(self) -> None:
        snapshot = _snapshot(_snap(installed=False, in_backoff=True))

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_backoff"]
        assert entry["state"] == "action_required"


class TestFileCertificatesUnchanged:
    """``source: file`` readiness ignores the ACME inputs entirely."""

    def test_an_acme_failure_elsewhere_does_not_touch_an_app_served_by_a_file_certificate(
        self,
    ) -> None:
        state = _state(public_cert("wild", [f"*.{ZONE}"]))
        public = PublicReadinessInput(
            certificates=tuple(state.public_tls.certificates),  # type: ignore[union-attr]
            statuses=(_status("wild"),),
            bound=True,
            acme=_snapshot(_snap("wild", error_code=AcmeErrorClass.DNS_AUTH, in_backoff=True)),
            acme_config_error=True,
        )
        result = ReconcileResult(
            ok=True, trigger="tick", started_at=datetime.now(UTC), remote_web_apps=[_remote()]
        )

        entries = compute_readiness(
            state,
            result,
            None,
            ca_generated=False,
            on_demand=False,
            gateway_id=GW,
            public=public,
        )

        assert [e.reasons for e in entries] == [[]]
        assert [e.state for e in entries] == ["ready"]

    @pytest.mark.parametrize("state", ["invalid", "expiring"])
    def test_file_certificate_states_keep_their_codes(self, state: str) -> None:
        entry = _run(_state(), [_remote()], [_status("wild", state)])

        assert entry["reasons"] == [f"public_cert_{state}:wild"]

    def test_a_mixed_gateway_reports_acme_reasons_only_for_the_acme_certificate(self) -> None:
        state = _acme_state(
            public_cert("wild", [f"*.{ZONE}"]), _acme_cert("issued", [f"x.apps.{ZONE}"])
        )
        snapshot = _snapshot(_snap("issued", error_code=AcmeErrorClass.DNS_AUTH))

        entry = _run_acme(
            state, [_status("wild"), _installed("issued")], snapshot=snapshot, config_error=True
        )

        # `grafana.<zone>` is served by the file certificate `wild`: no ACME reason.
        assert entry["reasons"] == []


class TestPublicInputAcme:
    def _result(self, *errors: AcmeError) -> ReconcileResult:
        return ReconcileResult(
            ok=True, trigger="t", started_at=datetime.now(UTC), acme_errors=list(errors)
        )

    def test_the_snapshot_is_carried_into_the_input(self) -> None:
        snapshot = _snapshot(_snap())

        public = public_input(_acme_state(), self._result(), snapshot)

        assert public is not None
        assert public.acme is snapshot

    def test_without_a_snapshot_the_input_has_none(self) -> None:
        public = public_input(_acme_state(), self._result())

        assert public is not None
        assert public.acme is None
        assert public.acme_config_error is False

    def test_a_pass_level_config_error_sets_acme_config_error(self) -> None:
        result = self._result(AcmeError(None, "config", "token file missing"))

        public = public_input(_acme_state(), result)

        assert public is not None
        assert public.acme_config_error is True

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(AcmeError("issued", "config", "per certificate"), id="per-cert-config"),
            pytest.param(AcmeError(None, "internal", "state file"), id="pass-level-internal"),
            pytest.param(AcmeError("issued", "dns_auth", "token rejected"), id="per-cert-class"),
        ],
    )
    def test_other_acme_errors_do_not_set_acme_config_error(self, error: AcmeError) -> None:
        public = public_input(_acme_state(), self._result(error))

        assert public is not None
        assert public.acme_config_error is False

    def test_a_config_error_among_others_is_found(self) -> None:
        result = self._result(
            AcmeError("issued", "internal", "x"), AcmeError(None, "config", "token file missing")
        )

        public = public_input(_acme_state(), result)

        assert public is not None
        assert public.acme_config_error is True

    def test_private_mode_is_still_none_with_a_snapshot(self) -> None:
        state = EffectiveState.model_validate({"twingate": {"network": "acme", "gateway_id": GW}})

        assert public_input(state, self._result(), _snapshot(_snap())) is None


# --- internal errors, staging, invalid material, snapshot failures ------------------------


class _Runner:
    """The one member ``acme_snapshot`` uses."""

    def __init__(
        self, snapshot: AcmeSnapshot | None = None, error: Exception | None = None
    ) -> None:
        self.snapshot_value = snapshot
        self.error = error
        self.calls = 0

    def snapshot(self) -> AcmeSnapshot:
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.snapshot_value is not None
        return self.snapshot_value


class TestAcmeSnapshotHelper:
    def test_without_a_runner_it_is_none_and_not_a_failure(self) -> None:
        assert acme_snapshot(None) == (None, False)

    def test_a_working_runner_gives_its_snapshot(self) -> None:
        snapshot = _snapshot(_snap())
        runner = _Runner(snapshot)

        taken, failed = acme_snapshot(runner)  # type: ignore[arg-type]

        assert taken is snapshot
        assert failed is False
        assert runner.calls == 1

    def test_a_raising_runner_is_none_and_failed_and_never_raises(self) -> None:
        runner = _Runner(error=RuntimeError("secret-looking detail"))

        assert acme_snapshot(runner) == (None, True)  # type: ignore[arg-type]

    def test_the_failure_is_logged_once_as_an_error_with_its_traceback(self) -> None:
        runner = _Runner(error=ValueError("boom"))

        with structlog.testing.capture_logs() as logs:
            acme_snapshot(runner)  # type: ignore[arg-type]

        [event] = [e for e in logs if e["event"] == "webapp_readiness.acme_snapshot_failed"]
        assert event["log_level"] == "error"
        assert event["exc_info"] is True


class TestPublicInputInternalAndStaging:
    def _result(self, *errors: AcmeError) -> ReconcileResult:
        return ReconcileResult(
            ok=True, trigger="t", started_at=datetime.now(UTC), acme_errors=list(errors)
        )

    def test_a_quiet_pass_has_no_internal_error_and_no_staging(self) -> None:
        public = public_input(_acme_state(), self._result(), _snapshot(_snap()))

        assert public is not None
        assert public.acme_internal_error is False
        assert public.acme_staging is False

    def test_a_failed_snapshot_sets_acme_internal_error(self) -> None:
        public = public_input(_acme_state(), self._result(), None, acme_snapshot_failed=True)

        assert public is not None
        assert public.acme_internal_error is True
        assert public.acme is None

    def test_a_dead_runner_task_sets_acme_internal_error(self) -> None:
        public = public_input(_acme_state(), self._result(), _snapshot(_snap(), task_dead=True))

        assert public is not None
        assert public.acme_internal_error is True

    @pytest.mark.parametrize("code", ["internal", "invalid_output", "rate_limited"])
    def test_a_certificate_less_error_other_than_config_sets_acme_internal_error(
        self, code: str
    ) -> None:
        public = public_input(_acme_state(), self._result(AcmeError(None, code, "x")))

        assert public is not None
        assert public.acme_internal_error is True
        assert public.acme_config_error is False

    def test_a_pass_level_config_error_is_config_not_internal(self) -> None:
        public = public_input(_acme_state(), self._result(AcmeError(None, "config", "token")))

        assert public is not None
        assert public.acme_config_error is True
        assert public.acme_internal_error is False

    @pytest.mark.parametrize("code", ["internal", "dns_auth", "config", "invalid_output"])
    def test_an_error_that_names_a_certificate_is_not_an_internal_error(self, code: str) -> None:
        public = public_input(_acme_state(), self._result(AcmeError("issued", code, "x")))

        assert public is not None
        assert public.acme_internal_error is False

    def test_a_staging_directory_sets_acme_staging(self) -> None:
        public = public_input(_acme_state(directory="staging"), self._result())

        assert public is not None
        assert public.acme_staging is True

    @pytest.mark.parametrize(
        ("directory", "staging"),
        [
            ("https://acme-staging-v02.api.letsencrypt.org/directory", True),
            ("https://acme-v02.api.letsencrypt.org/directory", False),
            ("https://acme.example.org/directory", False),
        ],
    )
    def test_a_url_directory_is_staging_only_when_it_is_the_staging_directory(
        self, directory: str, staging: bool
    ) -> None:
        public = public_input(_acme_state(directory=directory), self._result())

        assert public is not None
        assert public.acme_staging is staging

    def test_a_seed_without_an_acme_block_is_not_staging(self) -> None:
        public = public_input(_state(), self._result())

        assert public is not None
        assert public.acme_staging is False


class TestAcmeInternalReason:
    def test_an_internal_error_is_acme_failed_internal_and_keeps_the_rest_of_readiness(
        self,
    ) -> None:
        entry = _run_acme(_acme_state(), [_installed()], internal_error=True)

        assert entry["reasons"] == ["acme_failed:internal"]
        assert entry["state"] == "action_required"

    def test_the_other_reasons_are_kept_beside_it(self) -> None:
        snapshot = _snapshot(_snap(installed=False, in_backoff=True))

        entry = _run_acme(
            _acme_state(), [_acme_status()], snapshot=snapshot, internal_error=True
        )

        assert entry["reasons"] == [
            "public_cert_pending:issued",
            "acme_failed:internal",
            "acme_backoff",
        ]

    def test_an_expiring_certificate_still_reports_expiring_beside_the_internal_error(self) -> None:
        statuses = [dataclasses.replace(_installed(), state="expiring")]

        entry = _run_acme(_acme_state(), statuses, internal_error=True)

        assert entry["reasons"] == ["public_cert_expiring:issued", "acme_failed:internal"]

    def test_a_failed_snapshot_alone_gives_the_reason_without_a_snapshot(self) -> None:
        """No snapshot to consult (it raised), so only the flag speaks; readiness itself holds."""
        entry = _run_acme(_acme_state(), [_installed()], snapshot=None, internal_error=True)

        assert entry["reasons"] == ["acme_failed:internal"]
        assert "computation_failed" not in entry["reasons"]
        assert entry["state"] == "action_required"

    def test_the_snapshots_internal_class_and_the_flag_are_reported_once(self) -> None:
        snapshot = _snapshot(_snap(error_code=AcmeErrorClass.INTERNAL))

        entry = _run_acme(_acme_state(), [_installed()], snapshot=snapshot, internal_error=True)

        assert entry["reasons"] == ["acme_failed:internal"]

    def test_config_and_internal_are_both_reported_config_first(self) -> None:
        entry = _run_acme(
            _acme_state(), [_installed()], config_error=True, internal_error=True
        )

        assert entry["reasons"] == ["acme_failed:config", "acme_failed:internal"]

    def test_it_is_reported_once_for_address_and_alias(self) -> None:
        entry = _run_acme(
            _acme_state(alias=f"docs.{ZONE}"), [_installed()], internal_error=True
        )

        assert entry["reasons"] == ["acme_failed:internal"]

    def test_it_is_not_reported_for_an_app_a_file_certificate_covers(self) -> None:
        state = _acme_state(
            public_cert("wild", [f"*.{ZONE}"]), _acme_cert("issued", [f"x.apps.{ZONE}"])
        )

        entry = _run_acme(
            state, [_status("wild"), _installed("issued")], internal_error=True, staging=True
        )

        assert entry["reasons"] == []
        assert entry["state"] == "ready"

    def test_it_applies_to_whichever_acme_certificate_covers_the_app(self) -> None:
        state = _acme_state(
            _acme_cert("issued", [f"api.{ZONE}"]), _acme_cert("wild", [f"*.{ZONE}"])
        )

        entry = _run_acme(
            state, [_installed("issued"), _installed("wild")], internal_error=True
        )

        # `grafana.<zone>` is covered by `wild`; the flag describes the runner as a whole.
        assert entry["reasons"] == ["acme_failed:internal"]


class TestAcmeStagingDryRun:
    def test_a_staging_certificate_is_pending_and_a_dry_run_both_action_required(self) -> None:
        snapshot = _snapshot(
            _snap(state=AcmeCertState.DRY_RUN_OK, staging=True, installed=False),
            directory="https://acme-staging-v02.api.letsencrypt.org/directory",
            staging=True,
        )

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot, staging=True)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_staging_dry_run:issued"]
        assert entry["state"] == "action_required"

    def test_the_reason_names_the_certificate_covering_the_app(self) -> None:
        state = _acme_state(
            _acme_cert("issued", [f"api.{ZONE}"]), _acme_cert("wild", [f"*.{ZONE}"])
        )

        entry = _run_acme(state, [_acme_status("issued"), _acme_status("wild")], staging=True)

        assert entry["reasons"] == ["public_cert_pending:wild", "acme_staging_dry_run:wild"]

    def test_it_is_actionable_even_when_nothing_else_is_wrong(self) -> None:
        """An installed certificate (earlier production run) beside a staging seed still flags."""
        entry = _run_acme(_acme_state(), [_installed()], staging=True)

        assert entry["reasons"] == ["acme_staging_dry_run:issued"]
        assert entry["state"] == "action_required"

    def test_it_sits_before_the_backoff_reason(self) -> None:
        snapshot = _snapshot(_snap(installed=False, in_backoff=True))

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot, staging=True)

        assert entry["reasons"] == [
            "public_cert_pending:issued",
            "acme_staging_dry_run:issued",
            "acme_backoff",
        ]

    def test_a_failure_on_a_staging_certificate_is_reported_with_the_dry_run(self) -> None:
        snapshot = _snapshot(_snap(installed=False, error_code=AcmeErrorClass.DNS_AUTH))

        entry = _run_acme(_acme_state(), [_acme_status()], snapshot=snapshot, staging=True)

        assert entry["reasons"] == [
            "public_cert_pending:issued",
            "acme_staging_dry_run:issued",
            "acme_failed:dns_auth",
        ]

    def test_it_is_reported_once_for_address_and_alias(self) -> None:
        entry = _run_acme(_acme_state(alias=f"docs.{ZONE}"), [_installed()], staging=True)

        assert entry["reasons"] == ["acme_staging_dry_run:issued"]

    def test_a_production_seed_has_no_dry_run_reason(self) -> None:
        entry = _run_acme(_acme_state(), [_installed()], staging=False)

        assert entry["reasons"] == []

    def test_a_file_only_gateway_never_reports_it(self) -> None:
        entry = _run_acme(_state(), [_status("wild")], staging=True, internal_error=True)

        assert entry["reasons"] == []
        assert entry["state"] == "ready"


class TestAcmeInvalidInstalledMaterial:
    def _invalid(self) -> PublicCertStatus:
        return PublicCertStatus(
            name="issued",
            names=(f"*.{ZONE}",),
            not_after=None,
            state="invalid",
            last_error="public certificate 'issued': cert_file: chain: no valid path",
            generation=None,
            source="acme",
        )

    def test_refused_material_is_public_cert_invalid_not_pending(self) -> None:
        entry = _run_acme(_acme_state(), [self._invalid()])

        assert entry["reasons"] == ["public_cert_invalid:issued"]
        assert entry["state"] == "action_required"
        assert "public_cert_pending:issued" not in entry["reasons"]

    def test_the_acme_reasons_follow_the_invalid_certificate(self) -> None:
        snapshot = _snapshot(_snap(installed=True, error_code=AcmeErrorClass.INVALID_OUTPUT))

        entry = _run_acme(_acme_state(), [self._invalid()], snapshot=snapshot, staging=True)

        assert entry["reasons"] == [
            "public_cert_invalid:issued",
            "acme_staging_dry_run:issued",
            "acme_failed:invalid_output",
        ]

    def test_an_acme_certificate_pending_for_changed_names_is_still_pending(self) -> None:
        pending = dataclasses.replace(
            _acme_status(), last_error="awaiting reissue for changed names"
        )

        entry = _run_acme(_acme_state(), [pending])

        assert entry["reasons"] == ["public_cert_pending:issued"]


class TestPublicInputEndToEnd:
    """``public_input`` feeds ``compute_readiness`` the way the reconciler and ``/status`` do."""

    def _entry(
        self,
        state: EffectiveState,
        statuses: list[PublicCertStatus],
        *,
        snapshot: AcmeSnapshot | None,
        snapshot_failed: bool = False,
        errors: list[AcmeError] | None = None,
    ) -> dict[str, Any]:
        result = ReconcileResult(
            ok=True,
            trigger="tick",
            started_at=datetime.now(UTC),
            remote_web_apps=[_remote()],
            public_certs=statuses,
            acme_errors=errors or [],
        )
        entries = compute_readiness(
            state,
            result,
            None,
            ca_generated=False,
            on_demand=False,
            gateway_id=GW,
            public=public_input(state, result, snapshot, acme_snapshot_failed=snapshot_failed),
        )
        return {e.name: dataclasses.asdict(e) for e in entries}["grafana"]

    def test_a_failed_snapshot_degrades_to_one_internal_reason_and_readiness_is_kept(self) -> None:
        entry = self._entry(
            _acme_state(), [_installed()], snapshot=None, snapshot_failed=True
        )

        assert entry["reasons"] == ["acme_failed:internal"]
        assert entry["state"] == "action_required"

    def test_the_runner_unavailable_error_the_reconciler_records_gives_the_reason(self) -> None:
        errors = [AcmeError(None, "internal", "ACME runner unavailable: OSError: boom")]

        entry = self._entry(_acme_state(), [_acme_status()], snapshot=None, errors=errors)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_failed:internal"]

    def test_a_dead_task_gives_the_reason_even_with_a_healthy_certificate(self) -> None:
        entry = self._entry(
            _acme_state(), [_installed()], snapshot=_snapshot(_snap(), task_dead=True)
        )

        assert entry["reasons"] == ["acme_failed:internal"]

    def test_a_staging_seed_gives_the_dry_run_reason(self) -> None:
        entry = self._entry(
            _acme_state(directory="staging"),
            [_acme_status()],
            snapshot=_snapshot(_snap(installed=False)),
        )

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_staging_dry_run:issued"]
