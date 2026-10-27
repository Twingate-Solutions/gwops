"""The ``webapp`` kind descriptor and its parse, create and drift hooks."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from gwops.configmodel.schema import EffectiveState, WebApp
from gwops.kindhooks import normalise_extras
from gwops.kinds import KINDS, WEBAPP, by_key, by_segment, by_tg_type
from gwops.renderer.desired import desired_tg_objects
from gwops.tgapi import ops
from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError

_URL = "https://acme.twingate.com/api/graphql/"
_FIXTURE = Path(__file__).parent / "fixtures" / "tg" / "tg_webapp_list.json"


def _nodes() -> dict[str, dict[str, Any]]:
    payload = json.loads(_FIXTURE.read_text())
    return {e["node"]["name"]: e["node"] for e in payload["data"]["resources"]["edges"]}


def _node(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "__typename": "WebAppResource",
        "id": "res-1",
        "name": "app",
        "address": {"value": "app.internal"},
        "gateway": {"id": "gw-1"},
        "alias": None,
        "upstream": {"port": 443, "tlsMode": "VERIFY_FULL"},
        "downstream": {"port": 443, "tlsMode": "TLS13"},
        "requestHeaderRewrites": [],
    }
    return {**base, **overrides}


def _want(**fields: Any) -> tuple[int, dict[str, Any]]:
    """The (upstream_port, normalised extras) gwops wants for a web app seed entry."""
    entry = WebApp.model_validate({"name": "app", "address": "app.internal", **fields})
    return entry.upstream_port(), dict(normalise_extras(entry.tg_extras()))


@pytest.fixture
def tg() -> Any:
    return TGClient(network="acme", api_key="tg-secret-key")


class TestDescriptor:
    def test_is_registered_after_ssh_and_kubernetes(self) -> None:
        assert [k.key for k in KINDS] == ["ssh", "kubernetes", "webapp"]
        assert by_key("webapp") is WEBAPP
        assert by_segment("webapp") is WEBAPP
        assert by_tg_type("WebAppResource") is WEBAPP

    def test_identifiers(self) -> None:
        assert (WEBAPP.state_field, WEBAPP.api_segment) == ("web_apps", "webapp")
        assert (WEBAPP.tg_type, WEBAPP.tg_field_prefix) == ("WebAppResource", "webAppResource")
        assert WEBAPP.tg_upstream_input == "WebAppUpstreamInput"
        assert WEBAPP.upstream_input_required is True
        assert WEBAPP.gateway_id_required is True
        assert WEBAPP.automation_allowed is True
        assert WEBAPP.update_mutation == "webAppResourceUpdate"

    def test_list_fields_select_both_legs_alias_and_rewrites(self) -> None:
        assert WEBAPP.list_fields == (
            "gateway { id } alias upstream { port tlsMode } downstream { port tlsMode } "
            "requestHeaderRewrites { key value }"
        )

    def test_extra_arguments(self) -> None:
        assert WEBAPP.extra_create_args == (
            ("downstream", "WebAppDownstreamInput!"),
            ("requestHeaderRewrites", "[KeyValueInputObject!]"),
            ("alias", "String"),
        )
        assert WEBAPP.extra_update_args == (
            ("upstream", "WebAppUpstreamInput"),
            ("downstream", "WebAppDownstreamInput"),
            ("alias", "String"),
            ("requestHeaderRewrites", "[KeyValueInputObject!]"),
            ("gatewayId", "ID"),
        )

    def test_create_mutation_text(self) -> None:
        text = ops._create_mutation(WEBAPP)
        assert "$gatewayId: ID!," in text
        assert "$upstream: WebAppUpstreamInput!," in text
        assert "$downstream: WebAppDownstreamInput!" in text
        assert "$requestHeaderRewrites: [KeyValueInputObject!]" in text
        assert "$alias: String" in text
        assert "webAppResourceCreate(" in text
        assert "alias: $alias" in text

    def test_list_query_carries_the_webapp_fragment(self) -> None:
        assert "... on WebAppResource {" in ops._LIST_RESOURCES_QUERY

    def test_the_automation_fields_are_wired(self) -> None:
        state = EffectiveState.model_validate(
            {"twingate": {"network": "acme", "gateway_id": "g-1"}}
        )
        assert WEBAPP.automation_enabled(state) is False
        on = EffectiveState.model_validate(
            {
                "twingate": {"network": "acme", "gateway_id": "g-1"},
                "admin_api": {"automation": {"web_apps": {"enabled": True}}},
            }
        )
        assert WEBAPP.automation_enabled(on) is True
        assert WEBAPP.automation_exclusive_addresses is True


class TestParseRemote:
    def test_live_capture_minimal(self) -> None:
        extras = WEBAPP.parse_remote(_nodes()["lt-minimal"])
        assert dict(extras) == {
            "downstream_port": 80,
            "downstream_tls_mode": "NONE",
            "upstream_tls_mode": "NONE",
            "alias": None,
            "request_header_rewrites": (),
        }

    def test_live_capture_full(self) -> None:
        extras = WEBAPP.parse_remote(_nodes()["lt-full"])
        assert extras["upstream_tls_mode"] == "VERIFY_CA"
        assert (extras["downstream_port"], extras["downstream_tls_mode"]) == (443, "TLS13")

    def test_rewrites_are_normalised_like_the_desired_side(self) -> None:
        node = _node(
            requestHeaderRewrites=[
                {"key": "X-Zed", "value": "{{username}}"},
                {"key": "X_Twingate_User", "value": "{{groups}}"},
            ]
        )
        assert WEBAPP.parse_remote(node)["request_header_rewrites"] == (
            ("x-zed", "{{username}}"),
            ("x_twingate_user", "{{groups}}"),
        )

    def test_alias_is_lowercased_and_empty_is_unset(self) -> None:
        assert WEBAPP.parse_remote(_node(alias="Wiki.Corp.Internal"))["alias"] == (
            "wiki.corp.internal"
        )
        assert WEBAPP.parse_remote(_node(alias=""))["alias"] is None
        assert WEBAPP.parse_remote(_node(alias=None))["alias"] is None

    @pytest.mark.parametrize(
        ("leg", "field"), [("upstream", "upstream.tlsMode"), ("downstream", "downstream.tlsMode")]
    )
    def test_unknown_tls_mode_fails_loud_naming_the_field_not_the_value(
        self, leg: str, field: str
    ) -> None:
        node = _node(**{leg: {"port": 1, "tlsMode": "QUANTUM-LEAP"}})
        with pytest.raises(ValueError, match=field) as raised:
            WEBAPP.parse_remote(node)
        assert "QUANTUM-LEAP" not in str(raised.value)

    def test_a_mode_valid_on_the_other_leg_is_unknown_here(self) -> None:
        with pytest.raises(ValueError, match="downstream.tlsMode"):
            WEBAPP.parse_remote(_node(downstream={"port": 443, "tlsMode": "VERIFY_FULL"}))
        with pytest.raises(ValueError, match="upstream.tlsMode"):
            WEBAPP.parse_remote(_node(upstream={"port": 443, "tlsMode": "TLS13"}))

    def test_a_malformed_rewrite_is_a_value_error_without_the_value(self) -> None:
        node = _node(requestHeaderRewrites=[{"key": "X-A", "value": None}])
        with pytest.raises(ValueError, match="requestHeaderRewrites") as raised:
            WEBAPP.parse_remote(node)
        assert "X-A" not in str(raised.value)

    def test_missing_legs_raise_a_key_error(self) -> None:
        node = _node()
        del node["downstream"]
        with pytest.raises(KeyError):
            WEBAPP.parse_remote(node)


class TestCreateVariables:
    def test_both_tls_modes_are_always_explicit(self) -> None:
        port, extras = _want(upstream_tls="verify_full")
        variables = WEBAPP.create_variables(port, extras)
        assert variables["upstream"] == {"port": 443, "tlsMode": "VERIFY_FULL"}
        assert variables["downstream"] == {"port": 443, "tlsMode": "TLS13"}

    def test_plaintext_modes_are_sent_not_defaulted(self) -> None:
        port, extras = _want(
            address="app.internal:8080",
            upstream_tls="none",
            downstream={"tls": "none", "port": 8081},
        )
        variables = WEBAPP.create_variables(port, extras)
        assert variables["upstream"] == {"port": 8080, "tlsMode": "NONE"}
        assert variables["downstream"] == {"port": 8081, "tlsMode": "NONE"}

    def test_alias_and_rewrites_omitted_when_unset_and_unmanaged(self) -> None:
        port, extras = _want()
        variables = WEBAPP.create_variables(port, extras)
        assert set(variables) == {"upstream", "downstream"}

    def test_alias_and_rewrites_sent_when_declared(self) -> None:
        port, extras = _want(
            alias="wiki.corp.internal",
            request_headers={"X-Zed": "{{username}}", "X-Alpha": "{{groups}}"},
        )
        variables = WEBAPP.create_variables(port, extras)
        assert variables["alias"] == "wiki.corp.internal"
        assert variables["requestHeaderRewrites"] == [
            {"key": "x-alpha", "value": "{{groups}}"},
            {"key": "x-zed", "value": "{{username}}"},
        ]

    def test_managed_empty_rewrites_are_sent_as_an_empty_list(self) -> None:
        port, extras = _want(request_headers={})
        assert WEBAPP.create_variables(port, extras)["requestHeaderRewrites"] == []


class TestSettingsDrift:
    @staticmethod
    def _drift(want_fields: dict[str, Any], **node: Any) -> dict[str, Any]:
        want_port, want = _want(**want_fields)
        remote = _node(**node)
        return WEBAPP.settings_drift(
            want_port, want, remote["upstream"]["port"], WEBAPP.parse_remote(remote)
        )

    def test_in_sync_is_empty(self) -> None:
        assert self._drift({}) == {}

    def test_in_sync_with_alias_and_rewrites(self) -> None:
        drift = self._drift(
            {"alias": "wiki.corp.internal", "request_headers": {"X-Zed": "{{username}}"}},
            alias="wiki.corp.internal",
            requestHeaderRewrites=[{"key": "X-Zed", "value": "{{username}}"}],
        )
        assert drift == {}

    def test_a_reordered_remote_is_not_drift(self) -> None:
        drift = self._drift(
            {"request_headers": {"X-A": "a", "X-B": "b"}},
            requestHeaderRewrites=[{"key": "x-b", "value": "b"}, {"key": "X-A", "value": "a"}],
        )
        assert drift == {}

    def test_upstream_port_drift_sends_the_whole_leg(self) -> None:
        drift = self._drift({}, upstream={"port": 8443, "tlsMode": "VERIFY_FULL"})
        assert drift == {"upstream": {"port": 443, "tlsMode": "VERIFY_FULL"}}

    def test_upstream_mode_drift_sends_the_whole_leg(self) -> None:
        drift = self._drift({}, upstream={"port": 443, "tlsMode": "INSECURE"})
        assert drift == {"upstream": {"port": 443, "tlsMode": "VERIFY_FULL"}}

    def test_downstream_port_drift(self) -> None:
        drift = self._drift({}, downstream={"port": 8443, "tlsMode": "TLS13"})
        assert drift == {"downstream": {"port": 443, "tlsMode": "TLS13"}}

    def test_downstream_mode_drift(self) -> None:
        drift = self._drift({}, downstream={"port": 443, "tlsMode": "NONE"})
        assert drift == {"downstream": {"port": 443, "tlsMode": "TLS13"}}

    def test_alias_set_and_cleared(self) -> None:
        assert self._drift({"alias": "wiki.corp.internal"}) == {"alias": "wiki.corp.internal"}
        assert self._drift({}, alias="wiki.corp.internal") == {"alias": None}

    def test_rewrites_drift_sends_the_full_normalised_list(self) -> None:
        drift = self._drift(
            {"request_headers": {"X-Zed": "{{username}}", "X-Alpha": "{{groups}}"}},
            requestHeaderRewrites=[{"key": "X-Old", "value": "x"}],
        )
        assert drift == {
            "requestHeaderRewrites": [
                {"key": "x-alpha", "value": "{{groups}}"},
                {"key": "x-zed", "value": "{{username}}"},
            ]
        }

    def test_a_changed_value_is_drift(self) -> None:
        drift = self._drift(
            {"request_headers": {"X-A": "new"}},
            requestHeaderRewrites=[{"key": "X-A", "value": "old"}],
        )
        assert drift == {"requestHeaderRewrites": [{"key": "x-a", "value": "new"}]}

    def test_managed_empty_clears_remote_rewrites(self) -> None:
        drift = self._drift(
            {"request_headers": {}}, requestHeaderRewrites=[{"key": "X-A", "value": "a"}]
        )
        assert drift == {"requestHeaderRewrites": []}

    def test_unmanaged_rewrites_are_never_compared(self) -> None:
        drift = self._drift({}, requestHeaderRewrites=[{"key": "X-A", "value": "a"}])
        assert drift == {}

    def test_several_drifts_share_one_dict(self) -> None:
        drift = self._drift(
            {"alias": "wiki.corp.internal"},
            upstream={"port": 80, "tlsMode": "NONE"},
            downstream={"port": 80, "tlsMode": "NONE"},
        )
        assert set(drift) == {"upstream", "downstream", "alias"}

    def test_keys_are_all_declared_update_arguments(self) -> None:
        declared = {arg for arg, _ in WEBAPP.extra_update_args}
        drift = self._drift(
            {"alias": "wiki.corp.internal", "request_headers": {"X-A": "a"}},
            upstream={"port": 80, "tlsMode": "NONE"},
            downstream={"port": 80, "tlsMode": "NONE"},
        )
        assert set(drift) <= declared

    def test_desired_and_remote_agree_for_every_live_capture_node(self) -> None:
        """A resource gwops would create shows no drift once listed."""
        state = EffectiveState.model_validate(
            {
                "twingate": {"network": "acme", "gateway_id": "g"},
                "web_apps": [
                    {
                        "name": "app",
                        "address": "app.internal",
                        "alias": "wiki.corp.internal",
                        "upstream_tls": "verify_ca",
                        "downstream": {"tls": "tls13", "port": 8443},
                        "request_headers": {
                            "X_Twingate_User": "{{username}}",
                            "X-Groups": "{{groups}}",
                        },
                    }
                ],
            }
        )
        [desired] = desired_tg_objects(state)
        variables = WEBAPP.create_variables(desired.upstream_port, desired.extras)
        remote_node = _node(
            alias=variables["alias"],
            upstream=variables["upstream"],
            downstream=variables["downstream"],
            requestHeaderRewrites=variables["requestHeaderRewrites"],
        )
        remote_extras = WEBAPP.parse_remote(remote_node)
        assert (
            WEBAPP.settings_drift(
                desired.upstream_port,
                desired.extras,
                remote_node["upstream"]["port"],
                remote_extras,
            )
            == {}
        )


def _ok(field: str, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"data": {field: {"ok": True, "error": None, **extra}}})


class TestOpsWithTheRealDescriptor:
    async def test_create_sends_downstream_upstream_modes_alias_and_rewrites(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn-1"}}}}),
            _ok("webAppResourceCreate", entity={"id": "res-9"}),
        ]
        port, extras = _want(
            alias="wiki.corp.internal", request_headers={"X-User": "{{username}}"}
        )
        new_id = await ops.create_resource(
            tg, WEBAPP, "app", "app.internal", "gw-1", upstream_port=port, extras=extras
        )
        assert new_id == "res-9"
        sent = json.loads(route.calls[1].request.content)
        assert sent["variables"] == {
            "name": "app",
            "address": "app.internal",
            "remoteNetworkId": "rn-1",
            "gatewayId": "gw-1",
            "upstream": {"port": 443, "tlsMode": "VERIFY_FULL"},
            "downstream": {"port": 443, "tlsMode": "TLS13"},
            "alias": "wiki.corp.internal",
            "requestHeaderRewrites": [{"key": "x-user", "value": "{{username}}"}],
        }
        assert "webAppResourceCreate(" in sent["query"]

    async def test_the_settings_update_is_a_valid_web_app_update(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=_ok("webAppResourceUpdate"))
        want_port, want = _want(alias="wiki.corp.internal", request_headers={})
        remote = _node(
            upstream={"port": 80, "tlsMode": "NONE"},
            requestHeaderRewrites=[{"key": "X-A", "value": "a"}],
        )
        drift = WEBAPP.settings_drift(want_port, want, 80, WEBAPP.parse_remote(remote))
        await ops.update_resource_settings(tg, "webapp", "res-1", drift)
        [call] = route.calls
        sent = json.loads(call.request.content)
        assert "webAppResourceUpdate(id: $id" in sent["query"]
        assert sent["variables"] == {
            "id": "res-1",
            "upstream": {"port": 443, "tlsMode": "VERIFY_FULL"},
            "alias": "wiki.corp.internal",
            "requestHeaderRewrites": [],
        }

    async def test_listing_fails_loud_for_a_managed_unknown_mode_and_skips_unmanaged(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        payload = json.loads(_FIXTURE.read_text())
        edges = payload["data"]["resources"]["edges"]
        edges[0]["node"]["upstream"]["tlsMode"] = "QUANTUM-LEAP"
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))
        bad_id = edges[0]["node"]["id"]

        found = await ops.list_resources(tg, managed_ids=frozenset())
        assert bad_id not in {r.id for r in found}
        assert {r.kind for r in found} == {"webapp"}

        with pytest.raises(TGAPIError, match="malformed response"):
            await ops.list_resources(tg, managed_ids={bad_id})

    async def test_live_capture_lists_as_web_apps(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(200, json=json.loads(_FIXTURE.read_text()))
        )
        found = {r.name: r for r in await ops.list_resources(tg, managed_ids=frozenset())}
        assert found["lt-full"].upstream_port == 8443
        assert found["lt-full"].extras["downstream_tls_mode"] == "TLS13"
        assert found["lt-twokeys"].extras["request_header_rewrites"] == (
            ("x-two", "{{username}}-{{groups}}"),
        )
