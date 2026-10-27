"""``routes_state._change_failure`` attributes a failure to a change in a kind's extras."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from gwops.api.routes_state import _change_failure
from gwops.reconciler.core import ReconcileResult
from gwops.renderer.desired import DesiredResource


def _deps(managed: dict[str, str] | None = None) -> Any:
    return SimpleNamespace(registry=SimpleNamespace(managed_ids=lambda: dict(managed or {})))


def _resource(name: str = "app", **extras: Any) -> DesiredResource:
    return DesiredResource(
        kind="ssh", name=name, address="10.0.0.5", upstream_port=22, extras=extras
    )


def _result(*, synced: set[str], unavailable: bool = False) -> ReconcileResult:
    result = ReconcileResult(ok=True, trigger="api", started_at=datetime.now(UTC))
    result.tg_synced = set(synced)
    result.tg_unavailable = unavailable
    return result


def test_an_extras_only_change_that_did_not_sync_is_attributed_to_the_change() -> None:
    before = {"ssh/app": _resource(alias="old.example")}
    after = {"ssh/app": _resource(alias="new.example")}
    assert before["ssh/app"] == after["ssh/app"]  # equality ignores extras

    failure = _change_failure(_deps(), before, after, True, _result(synced=set()))

    assert failure is not None
    status, reason, unsynced = failure
    assert status == 422
    assert unsynced == ["ssh/app"]
    assert "ssh/app" in reason


def test_an_extras_only_failure_while_the_tenant_is_down_is_a_503() -> None:
    before = {"ssh/app": _resource(alias="old.example")}
    after = {"ssh/app": _resource(alias="new.example")}

    failure = _change_failure(
        _deps(), before, after, True, _result(synced=set(), unavailable=True)
    )

    assert failure is not None
    assert failure[0] == 503


def test_an_extras_only_change_that_synced_is_not_a_failure() -> None:
    before = {"ssh/app": _resource(alias="old.example")}
    after = {"ssh/app": _resource(alias="new.example")}

    assert _change_failure(_deps(), before, after, True, _result(synced={"ssh/app"})) is None


def test_identical_extras_are_not_a_change() -> None:
    state = {"ssh/app": _resource(alias="same.example")}
    again = {"ssh/app": _resource(alias="same.example")}

    # Not synced this pass, but not this change's doing either.
    assert _change_failure(_deps(), state, again, True, _result(synced=set())) is None


def test_extras_added_to_an_entry_without_any_count_as_a_change() -> None:
    before = {"ssh/app": _resource()}
    after = {"ssh/app": _resource(alias="new.example")}

    failure = _change_failure(_deps(), before, after, True, _result(synced=set()))

    assert failure is not None
    assert failure[2] == ["ssh/app"]


_POLICY_REASON = "web-app policy refused the change"


def _policy_refused(*, synced: set[str], extra_errors: tuple[str, ...] = ()) -> ReconcileResult:
    result = _result(synced=synced)
    result.local_ok = False
    result.errors = ["web-app policy: web_apps entry 'app' ...", *extra_errors]
    return result


def test_a_web_app_policy_refusal_is_not_blamed_on_twingate_sync() -> None:
    before = {"ssh/app": _resource()}
    after = {"ssh/app": _resource(alias="new.example"), "ssh/new": _resource("new")}

    failure = _change_failure(_deps(), before, after, True, _policy_refused(synced=set()))

    assert failure is not None
    status, reason, _unsynced = failure
    assert status == 422
    assert reason == _POLICY_REASON
    assert "Twingate" not in reason


def test_a_web_app_policy_refusal_is_422_even_when_the_tenant_was_unavailable() -> None:
    before = {"ssh/app": _resource()}
    after = {"ssh/app": _resource(alias="new.example")}
    result = _policy_refused(synced=set())
    result.tg_unavailable = True

    failure = _change_failure(_deps(), before, after, True, result)

    assert failure is not None
    assert (failure[0], failure[1]) == (422, _POLICY_REASON)


def test_a_policy_refusal_with_nothing_to_sync_is_still_reported() -> None:
    state = {"ssh/app": _resource()}

    failure = _change_failure(_deps(), state, dict(state), True, _policy_refused(synced=set()))

    assert failure == (422, _POLICY_REASON, [])


def test_a_local_failure_without_policy_errors_keeps_the_local_config_reason() -> None:
    state = {"ssh/app": _resource()}
    result = _result(synced=set())
    result.local_ok = False
    result.errors = ["render failed: bad template"]

    failure = _change_failure(_deps(), state, dict(state), True, result)

    assert failure == (422, "the change broke the local gateway config", [])


def test_a_policy_failure_that_pre_dates_the_change_is_not_attributed_to_it() -> None:
    state = {"ssh/app": _resource()}

    result = _policy_refused(synced=set())

    assert _change_failure(_deps(), state, dict(state), False, result) is None


def test_an_address_change_is_still_attributed() -> None:
    before = {"ssh/app": _resource()}
    moved = DesiredResource(kind="ssh", name="app", address="10.0.0.6", upstream_port=22)

    failure = _change_failure(_deps(), before, {"ssh/app": moved}, True, _result(synced=set()))

    assert failure is not None
    assert failure[2] == ["ssh/app"]
