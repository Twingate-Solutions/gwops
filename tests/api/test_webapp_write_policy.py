"""The web-app write pipeline: policy 422 for every web-app write, ahead of the field policy."""

import dataclasses
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import structlog.testing
import yaml
from pydantic import SecretStr

from gwops.api import routes_state
from gwops.api.app import create_app
from gwops.api.routes_state import WebAppPolicyRefused, check_webapp_policy
from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.tgapi.client import TGClient

from .conftest import make_deps
from .test_automation_webapp import Env, Tenant

_ADMIN = "admin-token"
_AUTO = "automation-token"
_TG_URL = "https://acme.twingate.com/api/graphql/"
_REFUSED = "web-app policy refused the change"
_SECRET = "Zx9Qp4Lm7Vb2Nc5Rt8Yh3Wk6Jd1Fs0Ga"
_NAME_NOT_ALLOWED = "header name not in admin_api.automation.web_apps.request_header_names"
_ROUTES = ["admin-put", "admin-overlay", "automation-put"]


def _seed(
    proxy: dict[str, Any] | None = None, web_apps: list[dict[str, Any]] | None = None
) -> str:
    doc: dict[str, Any] = {
        "twingate": {
            "network": "acme",
            "gateway_id": "g-1",
            "address_allowlist": {
                "cidrs": ["10.20.0.0/16"],
                "dns_suffixes": ["apps.example.com", "corp.example.com"],
            },
            "access_allowlist": {"groups": ["App Users"], "security_policies": []},
        },
        "admin_api": {
            "automation": {
                "name_prefix": "auto-",
                "web_apps": {"enabled": True, "request_header_names": ["X-Team", "x-env"]},
            }
        },
    }
    if proxy is not None:
        doc["web_app_proxy"] = proxy
    if web_apps is not None:
        doc["web_apps"] = web_apps
    return yaml.safe_dump(doc, sort_keys=False)


@pytest.fixture
async def wenv(tmp_path: Path) -> AsyncIterator[Env]:
    bundle = make_deps(tmp_path, seed=_seed(), admin_token=_ADMIN)
    tg = TGClient(network="acme", api_key="test-key")
    settings = bundle.deps.settings.model_copy(
        update={"gwops_automation_token": SecretStr(_AUTO)}
    )
    bundle.deps = dataclasses.replace(bundle.deps, settings=settings, tg=tg)
    transport = httpx.ASGITransport(app=create_app(bundle.deps))
    tenant = Tenant()
    with respx.mock(assert_all_called=False) as router:
        router.post(_TG_URL).mock(side_effect=tenant.handler)
        async with (
            httpx.AsyncClient(
                transport=transport, base_url="http://gwops",
                headers={"Authorization": f"Bearer {_ADMIN}"},
            ) as admin,
            httpx.AsyncClient(
                transport=transport, base_url="http://gwops",
                headers={"Authorization": f"Bearer {_AUTO}"},
            ) as auto,
        ):
            yield Env(bundle, tenant, admin, auto)
    await tg.aclose()


def _body(**fields: Any) -> dict[str, Any]:
    return {"address": "app.apps.example.com", **fields}


async def _write(
    env: Env, route: str, body: dict[str, Any], name: str = "auto-app"
) -> httpx.Response:
    if route == "admin-overlay":
        patch = {"web_apps": [{"name": name, **body}]}
        return await env.admin.post("/overlays", json={"patch": patch})
    client = env.admin if route == "admin-put" else env.auto
    return await client.put(f"/upstreams/webapp/{name}", json=body)


def _assert_refused(response: httpx.Response, env: Env) -> list[str]:
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["detail"] == _REFUSED
    assert set(body) == {"detail", "violations"}
    assert all(isinstance(v, str) for v in body["violations"])
    env.assert_nothing_persisted()
    assert env.tenant.operations == []
    return list(body["violations"])


_PROXY_TRUSTED = {"request_headers": {"X-Twingate-User": "{{username}}"}}
_PROXY_JWT = {"request_headers": {"Authorization": "Bearer {{jwt}}"}}
_PROXY_BAD_HOST = {"request_headers": {"Host": "{{username}}"}}

_CLASSES = [
    pytest.param(
        {"request_headers": {"Host": "{{username}}"}}, None, "header 'Host' is denied",
        id="denied-name",
    ),
    pytest.param(
        {"request_headers": {"X-Thing": "{{username}}{{groups}}"}}, None,
        "not a valid template", id="malformed-template",
    ),
    pytest.param(
        {"request_headers": {"X-Thing": "{{email}}"}}, None,
        "does not support", id="unsupported-template-key",
    ),
    pytest.param(
        {"request_headers": {"X-Thing": _SECRET + "{{username}}"}}, None,
        "looks like a secret", id="secret-text-around-template",
    ),
    pytest.param(
        {"request_headers": {"X-Thing": " "}}, None, "is empty", id="empty-value"
    ),
    pytest.param(
        {"request_headers": {"Authorization": "hunter2"}}, None,
        "secret-like name", id="static-value-under-secret-name",
    ),
    pytest.param(
        {"request_headers": {"X-Thing": _SECRET}}, None,
        "looks like a secret", id="high-entropy-static-value",
    ),
    pytest.param(
        {"request_headers": {"X-Twingate-User": "someone"}}, _PROXY_TRUSTED,
        "trusted gateway-wide name", id="trusted-gateway-wide-name",
    ),
    pytest.param(
        {"upstream_tls": "insecure"}, None, "plaintext_upstreams", id="insecure-not-allowed"
    ),
    pytest.param(
        {"upstream_tls": "none"}, None, "plaintext_upstreams", id="plaintext-not-allowed"
    ),
    pytest.param(
        {"upstream_tls": "verify_ca", "request_headers": {"Authorization": "Bearer {{jwt}}"}},
        None, "loopback", id="jwt-over-verify-ca",
    ),
    pytest.param(
        {"upstream_tls": "verify_ca"}, _PROXY_JWT, "loopback", id="gateway-jwt-over-verify-ca"
    ),
]


class TestPolicyRefusal:
    @pytest.mark.parametrize("route", _ROUTES)
    @pytest.mark.parametrize(("fields", "proxy", "expected"), _CLASSES)
    async def test_each_violation_class_is_refused_with_422(
        self, wenv: Env, route: str, fields: dict[str, Any], proxy: dict[str, Any] | None,
        expected: str,
    ) -> None:
        if proxy is not None:
            wenv.bundle.seed_path.write_text(_seed(proxy), encoding="utf-8")
        response = await _write(wenv, route, _body(**fields))
        violations = _assert_refused(response, wenv)
        assert any(expected in v for v in violations), violations
        assert _SECRET not in response.text
        assert "hunter2" not in response.text

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_every_added_violation_is_listed(self, wenv: Env, route: str) -> None:
        body = _body(upstream_tls="insecure", request_headers={"Host": "{{username}}"})
        violations = _assert_refused(await _write(wenv, route, body), wenv)
        assert len(violations) == 2
        assert any("'Host'" in v for v in violations)
        assert any("plaintext_upstreams" in v for v in violations)

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_the_refusal_names_the_entry_and_never_echoes_a_value(
        self, wenv: Env, route: str
    ) -> None:
        body = _body(request_headers={"X-Thing": _SECRET, "Host": _SECRET})
        response = await _write(wenv, route, body)
        violations = _assert_refused(response, wenv)
        assert all("'auto-app'" in v for v in violations)
        assert _SECRET not in response.text

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_a_partial_body_is_judged_on_the_merged_entry(
        self, wenv: Env, route: str
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(_PROXY_JWT), encoding="utf-8")
        ok = await _write(wenv, route, _body())
        assert ok.status_code in (200, 201), ok.text
        stored = len(wenv.bundle.store.list())
        triggers = list(wenv.bundle.reconciler.triggers)
        wenv.tenant.operations.clear()
        response = await _write(wenv, route, {"upstream_tls": "verify_ca"})
        assert response.status_code == 422, response.text
        assert response.json()["detail"] == _REFUSED
        assert any("loopback" in v for v in response.json()["violations"])
        assert len(wenv.bundle.store.list()) == stored
        assert wenv.bundle.reconciler.triggers == triggers
        assert wenv.tenant.operations == []


class TestPreExistingViolations:
    _SEED_BAD = [
        {
            "name": "seed-bad",
            "address": "seed-bad.apps.example.com",
            "request_headers": {"Cookie": "{{username}}"},
        }
    ]
    _PROXY_BAD = {"request_headers": {"Host": "{{username}}"}}

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_violations_elsewhere_in_the_state_are_not_reported(
        self, wenv: Env, route: str
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(self._PROXY_BAD, self._SEED_BAD), encoding="utf-8")
        response = await _write(wenv, route, _body(upstream_tls="insecure"))
        violations = _assert_refused(response, wenv)
        assert len(violations) == 1
        assert "'auto-app'" in violations[0] and "plaintext_upstreams" in violations[0]
        assert "seed-bad" not in response.text
        assert "web_app_proxy.request_headers" not in response.text

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_a_clean_write_is_not_blocked_by_violations_elsewhere(
        self, wenv: Env, route: str
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(self._PROXY_BAD, self._SEED_BAD), encoding="utf-8")
        response = await _write(wenv, route, _body())
        assert response.status_code in (200, 201), response.text

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_the_gateway_wide_jwt_header_is_not_blamed_on_the_write(
        self, wenv: Env, route: str
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(_PROXY_JWT), encoding="utf-8")
        response = await _write(wenv, route, _body(upstream_tls="verify_ca"))
        violations = _assert_refused(response, wenv)
        assert len(violations) == 1
        assert "'auto-app'" in violations[0] and "loopback" in violations[0]


class TestValidWrite:
    @pytest.mark.parametrize(("route", "status"), [
        ("admin-put", 200), ("admin-overlay", 201), ("automation-put", 200),
    ])
    async def test_a_valid_body_is_persisted_and_reconciled(
        self, wenv: Env, route: str, status: int
    ) -> None:
        body = _body(
            alias="wiki.corp.example.com", request_headers={"X-Team": "{{username}}"}
        )
        response = await _write(wenv, route, body)
        assert response.status_code == status, response.text
        assert response.json()["reconcile"]["ok"] is True
        [overlay] = wenv.bundle.store.list()
        assert overlay.origin == ("automation" if route == "automation-put" else "admin")
        assert overlay.patch["web_apps"][0]["name"] == "auto-app"
        assert wenv.bundle.reconciler.triggers == ["api"]
        assert wenv.tenant.listings == (1 if route == "automation-put" else 0)


class TestAliasAllowlist:
    @pytest.mark.parametrize("route", _ROUTES)
    async def test_an_alias_outside_the_allowlist_is_403_like_an_address(
        self, wenv: Env, route: str
    ) -> None:
        address = await _write(wenv, route, _body(address="x.evil.test"))
        response = await _write(wenv, route, _body(alias="wiki.evil.test"))
        assert (address.status_code, response.status_code) == (403, 403), response.text
        assert "address allowlist" in response.json()["detail"]
        wenv.assert_nothing_persisted()

    @pytest.mark.parametrize("route", _ROUTES)
    async def test_an_alias_inside_the_allowlist_is_accepted(
        self, wenv: Env, route: str
    ) -> None:
        response = await _write(wenv, route, _body(alias="wiki.corp.example.com"))
        assert response.status_code in (200, 201), response.text


class TestOverlayProxyKey:
    async def test_a_web_app_proxy_key_in_an_overlay_patch_is_422(self, wenv: Env) -> None:
        patch = {"web_app_proxy": {"request_headers": {"X-A": "{{username}}"}}}
        response = await wenv.admin.post("/overlays", json={"patch": patch})
        assert response.status_code == 422
        wenv.assert_nothing_persisted()

    async def test_the_key_is_refused_even_beside_a_valid_web_app(self, wenv: Env) -> None:
        patch = {
            "web_apps": [{"name": "auto-app", **_body()}],
            "web_app_proxy": {"request_headers": {"X-A": "{{username}}"}},
        }
        response = await wenv.admin.post("/overlays", json={"patch": patch})
        assert response.status_code == 422
        wenv.assert_nothing_persisted()


class TestPipelineOrder:
    @pytest.mark.parametrize("route", _ROUTES)
    async def test_schema_validation_precedes_the_policy(self, wenv: Env, route: str) -> None:
        body = _body(upstream_tls="bogus", request_headers={"Host": "{{username}}"})
        response = await _write(wenv, route, body)
        assert response.status_code == 422
        assert "violations" not in response.json()
        assert response.json()["detail"] != _REFUSED
        wenv.assert_nothing_persisted()

    async def test_the_namespace_409_precedes_the_policy(self, wenv: Env) -> None:
        assert (await wenv.admin.put("/upstreams/webapp/auto-x", json=_body())).status_code == 200
        stored = len(wenv.bundle.store.list())
        wenv.tenant.operations.clear()
        response = await wenv.auto.put(
            "/upstreams/webapp/auto-x", json=_body(request_headers={"Host": "{{username}}"})
        )
        assert response.status_code == 409
        assert "violations" not in response.json()
        assert len(wenv.bundle.store.list()) == stored
        assert wenv.tenant.operations == []

    async def test_the_policy_422_precedes_the_automation_field_policy(self, wenv: Env) -> None:
        response = await wenv.auto.put(
            "/upstreams/webapp/auto-a", json=_body(upstream_tls="insecure")
        )
        violations = _assert_refused(response, wenv)
        assert any("plaintext_upstreams" in v for v in violations)

    async def test_the_policy_422_wins_when_the_field_policy_also_refuses(
        self, wenv: Env
    ) -> None:
        body = _body(upstream_tls="verify_ca", request_headers={"X-Other": "{{jwt}}"})
        response = await wenv.auto.put("/upstreams/webapp/auto-a", json=body)
        violations = _assert_refused(response, wenv)
        assert any("loopback" in v for v in violations)

    async def test_the_field_policy_403_applies_once_the_policy_passes(self, wenv: Env) -> None:
        headers = await wenv.auto.put(
            "/upstreams/webapp/auto-a", json=_body(request_headers={"X-Other": "x"})
        )
        assert headers.status_code == 403
        assert headers.json()["violations"] == [
            {"field": "request_headers.X-Other", "reason": _NAME_NOT_ALLOWED}
        ]
        tls = await wenv.auto.put("/upstreams/webapp/auto-a", json=_body(upstream_tls="verify_ca"))
        assert tls.status_code == 403
        assert [v["field"] for v in tls.json()["violations"]] == ["upstream_tls"]
        wenv.assert_nothing_persisted()

    async def test_the_admin_token_skips_the_field_policy_but_not_the_policy(
        self, wenv: Env
    ) -> None:
        allowed = await wenv.admin.put(
            "/upstreams/webapp/ops-app",
            json=_body(upstream_tls="verify_ca", request_headers={"X-Other": "x"}),
        )
        assert allowed.status_code == 200, allowed.text
        refused = await wenv.admin.put(
            "/upstreams/webapp/ops-app", json=_body(upstream_tls="insecure")
        )
        assert refused.status_code == 422
        assert refused.json()["detail"] == _REFUSED


class TestAutomationSchemaOracle:
    _STORED_ALIAS = "secret.corp.example.com"

    async def _admin_owned(self, env: Env) -> None:
        response = await env.admin.put(
            "/upstreams/webapp/auto-x", json=_body(alias=self._STORED_ALIAS)
        )
        assert response.status_code == 200, response.text
        env.tenant.operations.clear()
        env.bundle.reconciler.triggers.clear()

    async def test_a_body_colliding_with_the_stored_alias_is_409_whatever_the_guess(
        self, wenv: Env
    ) -> None:
        await self._admin_owned(wenv)
        stored = len(wenv.bundle.store.list())
        guess = await wenv.auto.put(
            "/upstreams/webapp/auto-x", json={"address": self._STORED_ALIAS}
        )
        miss = await wenv.auto.put(
            "/upstreams/webapp/auto-x", json={"address": "other.apps.example.com"}
        )
        assert (guess.status_code, miss.status_code) == (409, 409), (guess.text, miss.text)
        assert guess.json() == miss.json()
        assert len(wenv.bundle.store.list()) == stored
        assert wenv.bundle.reconciler.triggers == []
        assert wenv.tenant.operations == []

    async def test_the_admin_token_still_gets_the_merged_422(self, wenv: Env) -> None:
        await self._admin_owned(wenv)
        response = await wenv.admin.put(
            "/upstreams/webapp/auto-x", json={"address": self._STORED_ALIAS}
        )
        assert response.status_code == 422
        assert "alias must differ from address" in response.json()["detail"]

    async def test_a_body_invalid_on_its_own_is_422_before_the_namespace_409(
        self, wenv: Env
    ) -> None:
        await self._admin_owned(wenv)
        response = await wenv.auto.put(
            "/upstreams/webapp/auto-x", json=_body(upstream_tls="bogus")
        )
        assert response.status_code == 422
        assert self._STORED_ALIAS not in response.text

    async def test_the_standalone_422_never_echoes_a_header_value(self, wenv: Env) -> None:
        response = await wenv.auto.put(
            "/upstreams/webapp/auto-a",
            json=_body(request_headers={"X-Team": 5, "Bad Name": _SECRET}),
        )
        assert response.status_code == 422
        assert _SECRET not in response.text

    async def test_a_merged_only_failure_on_an_owned_entry_is_still_422(self, wenv: Env) -> None:
        created = await wenv.auto.put(
            "/upstreams/webapp/auto-y", json=_body(alias="mine.corp.example.com")
        )
        assert created.status_code == 200, created.text
        response = await wenv.auto.put(
            "/upstreams/webapp/auto-y", json={"address": "mine.corp.example.com"}
        )
        assert response.status_code == 422
        assert "alias must differ from address" in response.json()["detail"]

    async def test_a_partial_body_without_an_address_passes_the_standalone_step(
        self, wenv: Env
    ) -> None:
        assert (await wenv.auto.put("/upstreams/webapp/auto-y", json=_body())).status_code == 200
        response = await wenv.auto.put(
            "/upstreams/webapp/auto-y", json={"alias": "mine.corp.example.com"}
        )
        assert response.status_code == 200, response.text


_SEED_INSECURE = [
    {"name": "seed-bad", "address": "seed-bad.apps.example.com", "upstream_tls": "insecure"}
]


class TestTouchedEntryViolations:
    @pytest.mark.parametrize("route", ["admin-put", "admin-overlay"])
    async def test_an_identical_pre_existing_violation_on_a_touched_entry_is_refused(
        self, wenv: Env, route: str
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(None, _SEED_INSECURE), encoding="utf-8")
        response = await _write(
            wenv, route, {"address": "moved.apps.example.com"}, name="seed-bad"
        )
        violations = _assert_refused(response, wenv)
        assert len(violations) == 1
        assert "'seed-bad'" in violations[0] and "plaintext_upstreams" in violations[0]

    @pytest.mark.parametrize("route", ["admin-put", "admin-overlay"])
    async def test_a_write_that_fixes_the_touched_entry_is_accepted(
        self, wenv: Env, route: str
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(None, _SEED_INSECURE), encoding="utf-8")
        response = await _write(wenv, route, {"upstream_tls": "verify_full"}, name="seed-bad")
        assert response.status_code in (200, 201), response.text

    async def test_a_write_to_another_entry_is_not_blamed_for_the_bad_one(
        self, wenv: Env
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(None, _SEED_INSECURE), encoding="utf-8")
        response = await _write(wenv, "admin-put", _body(), name="other-app")
        assert response.status_code == 200, response.text

    async def test_a_newly_added_gateway_wide_violation_is_reported(self, tmp_path: Path) -> None:
        deps = make_deps(tmp_path, seed=_seed()).deps
        current, _provenance = load_effective_state(deps.settings.seed_path, deps.store)
        proxy = current.web_app_proxy.model_copy(
            update={"request_headers": {"Host": "{{username}}"}}
        )
        candidate = current.model_copy(update={"web_app_proxy": proxy})
        patch = {"web_apps": [{"name": "a", "address": "a.apps.example.com"}]}
        with pytest.raises(WebAppPolicyRefused) as refused:
            check_webapp_policy(deps, patch, candidate)
        assert [v for v in refused.value.violations if "web_app_proxy.request_headers" in v]

    async def test_a_pre_existing_gateway_wide_violation_is_not_reported(
        self, tmp_path: Path
    ) -> None:
        seed = _seed({"request_headers": {"Host": "{{username}}"}})
        deps = make_deps(tmp_path, seed=seed).deps
        current, _provenance = load_effective_state(deps.settings.seed_path, deps.store)
        patch = {"web_apps": [{"name": "a", "address": "a.apps.example.com"}]}
        check_webapp_policy(deps, patch, current)


class TestCurrentStateDoesNotLoad:
    """The comparison state is unavailable: only the write's own entries and gateway-wide names."""

    @staticmethod
    def _break_current_state(monkeypatch: pytest.MonkeyPatch, real_store: Any) -> None:
        """Make loading the real store fail, but only while check_webapp_policy runs."""
        real_load = routes_state.load_effective_state
        real_check = routes_state.check_webapp_policy
        armed = False

        def load(seed_path: Path, store: Any) -> Any:
            if armed and store is real_store:
                raise ConfigLoadError("current state is broken")
            return real_load(seed_path, store)

        def check(*args: Any, **kwargs: Any) -> None:
            nonlocal armed
            armed = True
            try:
                real_check(*args, **kwargs)
            finally:
                armed = False

        monkeypatch.setattr(routes_state, "load_effective_state", load)
        monkeypatch.setattr(routes_state, "check_webapp_policy", check)

    async def test_the_automation_token_never_sees_other_entries_violations(
        self, wenv: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wenv.bundle.seed_path.write_text(
            _seed(_PROXY_BAD_HOST, _SEED_INSECURE), encoding="utf-8"
        )
        self._break_current_state(monkeypatch, wenv.bundle.deps.store)

        with structlog.testing.capture_logs() as logs:
            response = await _write(wenv, "automation-put", _body(upstream_tls="insecure"))

        violations = _assert_refused(response, wenv)
        assert any("'auto-app'" in v and "plaintext_upstreams" in v for v in violations)
        assert any("web_app_proxy.request_headers" in v for v in violations)
        assert "seed-bad" not in response.text
        [event] = [e for e in logs if e["event"] == "api.webapp_policy_current_state_unloadable"]
        assert event["error_type"] == "ConfigLoadError"
        assert "broken" not in str(event)

    async def test_a_clean_write_is_not_blocked_by_an_untouched_entrys_violation(
        self, wenv: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(None, _SEED_INSECURE), encoding="utf-8")
        self._break_current_state(monkeypatch, wenv.bundle.deps.store)

        response = await _write(wenv, "automation-put", _body())

        assert response.status_code == 200, response.text

    async def test_a_touched_entrys_own_violation_is_still_reported(
        self, wenv: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wenv.bundle.seed_path.write_text(_seed(None, _SEED_INSECURE), encoding="utf-8")
        self._break_current_state(monkeypatch, wenv.bundle.deps.store)

        response = await _write(wenv, "admin-put", {"address": "m.apps.example.com"}, "seed-bad")

        violations = _assert_refused(response, wenv)
        assert len(violations) == 1 and "'seed-bad'" in violations[0]


class TestOverlayDeletePolicy:
    async def _fixed_overlay(self, env: Env) -> str:
        env.bundle.seed_path.write_text(_seed(None, _SEED_INSECURE), encoding="utf-8")
        fixed = await _write(env, "admin-put", {"upstream_tls": "verify_full"}, name="seed-bad")
        assert fixed.status_code == 200, fixed.text
        [overlay] = env.bundle.store.list()
        return overlay.id

    async def test_a_delete_that_restores_a_violation_is_refused_with_the_same_body(
        self, wenv: Env
    ) -> None:
        overlay_id = await self._fixed_overlay(wenv)
        triggers = list(wenv.bundle.reconciler.triggers)
        response = await wenv.admin.delete(f"/overlays/{overlay_id}")
        assert response.status_code == 422, response.text
        body = response.json()
        assert body["detail"] == _REFUSED
        assert set(body) == {"detail", "violations"}
        assert len(body["violations"]) == 1
        assert "'seed-bad'" in body["violations"][0]
        assert [o.id for o in wenv.bundle.store.list()] == [overlay_id]
        assert wenv.bundle.reconciler.triggers == triggers

    async def test_a_delete_that_adds_no_violation_still_works(self, wenv: Env) -> None:
        assert (await _write(wenv, "admin-put", _body(), name="ops-app")).status_code == 200
        [overlay] = wenv.bundle.store.list()
        response = await wenv.admin.delete(f"/overlays/{overlay.id}")
        assert response.status_code == 204
        assert wenv.bundle.store.list() == []

    async def test_an_unknown_overlay_is_still_404_and_a_malformed_id_422(self, wenv: Env) -> None:
        assert (await wenv.admin.delete("/overlays/0042-never-existed")).status_code == 404
        malformed = await wenv.admin.delete("/overlays/NOT-A-VALID-ID")
        assert malformed.status_code == 422
        assert "violations" not in malformed.json()
