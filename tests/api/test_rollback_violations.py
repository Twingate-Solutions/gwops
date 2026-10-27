"""A reconcile-side web-app policy refusal rolls the write back with a top-level `violations`."""

from pathlib import Path

import httpx

from gwops.api.app import create_app
from gwops.reconciler.core import ReconcileResult

from .conftest import ADMIN_TOKEN, StubReconciler, make_deps, ok_result

_POLICY_ERRORS = [
    "web-app policy: web_apps entry 'x': header 'Host' is denied (Host header)",
    "web-app policy: web_app_proxy.request_headers: header 'Via' is denied (forwarding header)",
]


class _PolicyRefusingReconciler(StubReconciler):
    """Refuses the write's own pass the way the real reconciler does under a policy refusal."""

    async def reconcile(self, trigger: str) -> ReconcileResult:
        if trigger != "api":
            return await super().reconcile(trigger)
        self.triggers.append(trigger)
        result = ok_result(trigger)
        result.ok = result.local_ok = False
        result.errors = list(_POLICY_ERRORS)
        self.last_result = result
        return result


def _client(app_deps) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(app_deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )


async def test_a_policy_refusal_rollback_carries_a_top_level_violations_list(
    tmp_path: Path,
) -> None:
    bundle = make_deps(tmp_path)
    bundle.deps.reconciler = _PolicyRefusingReconciler(bundle.seed_path, bundle.store)  # type: ignore[assignment]

    async with _client(bundle.deps) as client:
        response = await client.put("/upstreams/ssh/new-host", json={"address": "10.0.0.9:22"})

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["violations"] == [
        "web_apps entry 'x': header 'Host' is denied (Host header)",
        "web_app_proxy.request_headers: header 'Via' is denied (forwarding header)",
    ]
    assert bundle.store.list() == []


async def test_the_existing_detail_content_is_kept(tmp_path: Path) -> None:
    bundle = make_deps(tmp_path)
    bundle.deps.reconciler = _PolicyRefusingReconciler(bundle.seed_path, bundle.store)  # type: ignore[assignment]

    async with _client(bundle.deps) as client:
        response = await client.put("/upstreams/ssh/new-host", json={"address": "10.0.0.9:22"})

    detail = response.json()["detail"]
    assert detail["message"] == "change rolled back: web-app policy refused the change"
    assert detail["rolled_back"] is True
    assert detail["unsynced"] == ["ssh/new-host"]
    assert detail["errors"] == _POLICY_ERRORS
    assert detail["rollback"]["ok"] is True


async def test_a_twingate_sync_failure_rollback_has_no_violations_key(tmp_path: Path) -> None:
    bundle = make_deps(tmp_path)
    bundle.reconciler.fail_keys = {"ssh/new-host"}

    async with _client(bundle.deps) as client:
        response = await client.put("/upstreams/ssh/new-host", json={"address": "10.0.0.9:22"})

    assert response.status_code == 422
    assert "violations" not in response.json()
    assert response.json()["detail"]["rolled_back"] is True
