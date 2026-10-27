"""tgapi ops driven by a kind that overrides the registry hooks.

A synthetic web-app descriptor (replacing the shipped one here) overrides every hook
field; the ops must honour it: the list fragment, the create mutation, the
``extras`` round trip, the address/access updates through ``update_mutation`` and the
settings update. The list fixture is a captured tenant response.
"""

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import structlog.testing

from gwops import kinds
from gwops.kindhooks import Extras
from gwops.kinds import SSH, ResourceKind
from gwops.tgapi import ops
from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError
from gwops.tgapi.ops import (
    _selection_lines,
    create_resource,
    list_resources,
    update_resource_access,
    update_resource_address,
    update_resource_settings,
)

_URL = "https://acme.twingate.com/api/graphql/"
_FIXTURE = Path(__file__).parent.parent / "fixtures" / "tg" / "tg_webapp_list.json"

_TLS_MODES = {"NONE", "VERIFY_CA", "TLS13"}
_MALFORMED_LISTING = r"ListResources returned a malformed response"


def _parse_remote(node: dict[str, Any]) -> Extras:
    """Read the web-app settings; an unknown tlsMode is a malformed response, never coerced."""
    upstream, downstream = node["upstream"], node["downstream"]
    for leg in (upstream, downstream):
        if leg["tlsMode"] not in _TLS_MODES:
            raise ValueError(f"unknown tlsMode {leg['tlsMode']!r}")
    return {
        "upstream_tls": upstream["tlsMode"],
        "downstream": (downstream["port"], downstream["tlsMode"]),
        "alias": node.get("alias"),
        "rewrites": tuple((r["key"], r["value"]) for r in node["requestHeaderRewrites"]),
    }


def _create_variables(port: int, extras: Extras) -> dict[str, Any]:
    downstream_port, downstream_tls = extras["downstream"]
    return {
        "upstream": {"port": port, "tlsMode": extras["upstream_tls"]},
        "downstream": {"port": downstream_port, "tlsMode": downstream_tls},
        "requestHeaderRewrites": [{"key": k, "value": v} for k, v in extras["rewrites"]],
    }


WEBAPP: ResourceKind = replace(
    SSH,
    key="webapp",
    state_field="ssh_upstreams",
    api_segment="webapp",
    tg_type="WebAppResource",
    tg_field_prefix="webAppResource",
    tg_upstream_input="WebAppUpstreamInput",
    automation_allowed=False,
    list_fields=(
        "gateway { id } alias upstream { port tlsMode } downstream { port tlsMode } "
        "requestHeaderRewrites { key value }"
    ),
    upstream_input_required=True,
    extra_create_args=(
        ("downstream", "WebAppDownstreamInput!"),
        ("requestHeaderRewrites", "[KeyValueInputObject!]"),
    ),
    extra_update_args=(
        ("upstream", "WebAppUpstreamInput"),
        ("downstream", "WebAppDownstreamInput"),
        ("alias", "String"),
        ("requestHeaderRewrites", "[KeyValueInputObject!]"),
    ),
    parse_remote=_parse_remote,
    create_variables=_create_variables,
    update_mutation="webAppResourceUpdate",
)


@pytest.fixture
def tg() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="tg-secret-key")


@pytest.fixture(autouse=True)
def webapp_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(kinds._BY_KEY, "webapp", WEBAPP)
    monkeypatch.setitem(kinds._BY_TG_TYPE, "WebAppResource", WEBAPP)
    monkeypatch.setattr(ops, "KINDS", (*(k for k in kinds.KINDS if k.key != "webapp"), WEBAPP))
    monkeypatch.setattr(ops, "_LIST_RESOURCES_QUERY", ops._list_resources_query())


def _sent(route: respx.Route) -> list[dict[str, Any]]:
    return [json.loads(call.request.content) for call in route.calls]


def _ok(field: str, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"data": {field: {"ok": True, "error": None, **extra}}})


class TestSelectionLayout:
    def test_nested_selection_is_one_name_per_line(self) -> None:
        assert _selection_lines("a b { c d { e } } f", 2) == (
            "  a\n  b {\n    c\n    d {\n      e\n    }\n  }\n  f"
        )

    @pytest.mark.parametrize("bad", ["a { b", "a } b", "{ a }", "a { { b } }"])
    def test_malformed_selection_fails_loud(self, bad: str) -> None:
        with pytest.raises(ValueError, match="selection"):
            _selection_lines(bad, 0)


class TestListFragment:
    def test_kind_list_fields_shape_its_fragment(self) -> None:
        query = ops._list_resources_query()
        assert query.count("... on ") == 3
        assert """
        ... on WebAppResource {
          gateway {
            id
          }
          alias
          upstream {
            port
            tlsMode
          }
          downstream {
            port
            tlsMode
          }
          requestHeaderRewrites {
            key
            value
          }
        }""" in query

    async def test_live_capture_parses_into_extras(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=json.loads(_FIXTURE.read_text())))
        found = {r.name: r for r in await list_resources(tg)}
        assert set(found) >= {"lt-minimal", "lt-full", "lt-twokeys"}
        full = found["lt-full"]
        assert (full.kind, full.upstream_port) == ("webapp", 8443)
        assert full.extras["upstream_tls"] == "VERIFY_CA"
        assert full.extras["downstream"] == (443, "TLS13")
        twokeys = found["lt-twokeys"]
        assert twokeys.extras["rewrites"] == (("X-Two", "{{username}}-{{groups}}"),)
        # Listed with the fragment the kind asked for.
        assert "tlsMode" in _sent(route)[0]["query"]

    async def test_unknown_tls_mode_is_a_malformed_response(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        payload = json.loads(_FIXTURE.read_text())
        payload["data"]["resources"]["edges"][0]["node"]["upstream"]["tlsMode"] = "QUANTUM"
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg)


class TestUnparseableNode:
    """``parse_remote`` rejecting a node: loud for a resource gwops manages, skipped otherwise."""

    @staticmethod
    def _poisoned(respx_mock: respx.MockRouter) -> tuple[str, str, int]:
        """Serve the capture with a bad first-node tlsMode; return ``(id, value, remaining)``."""
        payload = json.loads(_FIXTURE.read_text())
        edges = payload["data"]["resources"]["edges"]
        edges[0]["node"]["upstream"]["tlsMode"] = "QUANTUM-LEAP"
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))
        return str(edges[0]["node"]["id"]), "QUANTUM-LEAP", len(edges) - 1

    async def test_an_unmanaged_node_is_skipped_with_a_warning(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        bad_id, bad_value, remaining = self._poisoned(respx_mock)

        with structlog.testing.capture_logs() as logs:
            found = await list_resources(tg, managed_ids={"some-other-id"})

        assert bad_id not in {r.id for r in found}
        assert len(found) == remaining
        [warning] = [entry for entry in logs if entry["event"] == "tgapi.unmanaged_node_skipped"]
        assert warning["log_level"] == "warning"
        assert warning["resource_id"] == bad_id
        assert warning["typename"] == "WebAppResource"
        assert warning["error_type"] == "ValueError"
        # Neither the rejected value nor anything else read off the node is logged.
        assert bad_value not in repr(logs)

    async def test_a_managed_node_still_fails_the_listing(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        bad_id, _value, _remaining = self._poisoned(respx_mock)
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg, managed_ids={bad_id})

    async def test_unknown_ownership_fails_the_listing(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        self._poisoned(respx_mock)
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg)
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg, managed_ids=None)

    async def test_a_node_missing_a_field_the_hook_reads_is_skipped_when_unmanaged(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        payload = json.loads(_FIXTURE.read_text())
        edges = payload["data"]["resources"]["edges"]
        del edges[0]["node"]["downstream"]
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))

        found = await list_resources(tg, managed_ids=frozenset())

        assert len(found) == len(edges) - 1

    async def test_a_node_without_an_id_fails_even_when_ownership_is_known(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        payload = json.loads(_FIXTURE.read_text())
        payload["data"]["resources"]["edges"][0]["node"]["id"] = ""
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg, managed_ids=frozenset())


class TestUnmanagedNodeMissingCoreFields:
    """address, name and upstream.port are read inside the skip-unmanaged guard."""

    @staticmethod
    def _serve_without(respx_mock: respx.MockRouter, *path: str) -> tuple[str, int]:
        """Serve the capture with `path` deleted from the first node; return ``(id, others)``."""
        payload = json.loads(_FIXTURE.read_text())
        edges = payload["data"]["resources"]["edges"]
        parent: Any = edges[0]["node"]
        for step in path[:-1]:
            parent = parent[step]
        del parent[path[-1]]
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))
        return str(edges[0]["node"]["id"]), len(edges) - 1

    @pytest.mark.parametrize(
        "path", [("address",), ("address", "value"), ("name",), ("upstream",), ("upstream", "port")]
    )
    async def test_an_unmanaged_node_is_skipped_and_logged(
        self, tg: TGClient, respx_mock: respx.MockRouter, path: tuple[str, ...]
    ) -> None:
        bad_id, others = self._serve_without(respx_mock, *path)

        with structlog.testing.capture_logs() as logs:
            found = await list_resources(tg, managed_ids={"some-other-id"})

        assert bad_id not in {r.id for r in found}
        assert len(found) == others
        [warning] = [entry for entry in logs if entry["event"] == "tgapi.unmanaged_node_skipped"]
        assert warning["resource_id"] == bad_id
        assert warning["typename"] == "WebAppResource"
        assert warning["error_type"] in {"KeyError", "TypeError"}

    @pytest.mark.parametrize("path", [("address",), ("name",), ("upstream", "port")])
    async def test_a_managed_node_still_fails_loud(
        self, tg: TGClient, respx_mock: respx.MockRouter, path: tuple[str, ...]
    ) -> None:
        bad_id, _others = self._serve_without(respx_mock, *path)
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg, managed_ids={bad_id})

    async def test_unknown_ownership_still_fails_loud(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        self._serve_without(respx_mock, "address")
        with pytest.raises(TGAPIError, match=r"ListResources returned a malformed response"):
            await list_resources(tg)


class TestErrorTextCarriesNoNodeValues:
    """No listing error's text embeds a value read off a node (header rewrites included)."""

    _PLANTED = "planted-header-value-4f2a"

    def _serve(
        self, respx_mock: respx.MockRouter, mutate: Callable[[dict[str, Any]], None]
    ) -> None:
        payload = json.loads(_FIXTURE.read_text())
        node = payload["data"]["resources"]["edges"][0]["node"]
        node["requestHeaderRewrites"] = [{"key": "X-Planted", "value": self._PLANTED}]
        mutate(node)
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))

    @staticmethod
    def _everything(exc: BaseException) -> str:
        parts: list[str] = []
        current: BaseException | None = exc
        while current is not None:
            parts += [str(current), repr(current)]
            current = current.__cause__
        return "\n".join(parts)

    @pytest.mark.parametrize(
        ("field", "missing"),
        [("id", "id"), ("gateway", "gateway id")],
    )
    async def test_a_node_with_an_empty_id_names_the_type_and_field_only(
        self, tg: TGClient, respx_mock: respx.MockRouter, field: str, missing: str
    ) -> None:
        def mutate(node: dict[str, Any]) -> None:
            if field == "id":
                node["id"] = ""
            else:
                node["gateway"] = {"id": ""}

        self._serve(respx_mock, mutate)
        with pytest.raises(TGAPIError) as raised:
            await list_resources(tg, managed_ids=frozenset())
        text = self._everything(raised.value)
        assert self._PLANTED not in text
        assert "X-Planted" not in text
        assert "lt-minimal" not in text
        assert "WebAppResource" in str(raised.value)
        assert f"null/empty {missing}" in str(raised.value)

    async def test_a_hook_error_that_echoes_a_value_is_not_repeated(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        # The synthetic hook's ValueError embeds the tlsMode it read.
        def mutate(node: dict[str, Any]) -> None:
            node["upstream"]["tlsMode"] = self._PLANTED

        self._serve(respx_mock, mutate)
        with pytest.raises(TGAPIError, match=_MALFORMED_LISTING) as raised:
            await list_resources(tg)
        assert self._PLANTED not in str(raised.value)

    async def test_an_unparseable_port_is_not_repeated(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        def mutate(node: dict[str, Any]) -> None:
            node["upstream"]["port"] = self._PLANTED

        self._serve(respx_mock, mutate)
        with pytest.raises(TGAPIError, match=_MALFORMED_LISTING) as raised:
            await list_resources(tg)
        assert self._PLANTED not in str(raised.value)

    async def test_a_gateway_node_with_an_empty_id_does_not_echo_the_node(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        planted_address = "gw-planted-4f2a.internal"
        payload = {
            "data": {
                "remoteNetwork": {
                    "gateways": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "edges": [{"node": {"id": "", "address": planted_address}}],
                    }
                }
            }
        }
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(TGAPIError, match=r"ListGateways returned a malformed") as raised:
            await ops.find_gateway_by_address(tg, "rn-1", planted_address)
        assert planted_address not in str(raised.value)


class TestCreate:
    def test_mutation_text_requires_upstream_and_declares_extra_args(self) -> None:
        text = ops._create_mutation(WEBAPP)
        assert "$upstream: WebAppUpstreamInput!, $groupIds: [ID], $securityPolicyId: ID, " in text
        assert "$downstream: WebAppDownstreamInput!" in text
        assert "$requestHeaderRewrites: [KeyValueInputObject!]" in text
        assert "securityPolicyId: $securityPolicyId, downstream: $downstream," in text
        assert "requestHeaderRewrites: $requestHeaderRewrites" in text
        assert "webAppResourceCreate(" in text

    async def test_sends_the_kinds_create_variables(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn-1"}}}}),
            _ok("webAppResourceCreate", entity={"id": "res-9"}),
        ]
        extras: Mapping[str, Any] = {
            "upstream_tls": "NONE",
            "downstream": (80, "NONE"),
            "rewrites": (("X-User", "{{username}}"),),
        }
        new_id = await create_resource(
            tg, WEBAPP, "app", "app.internal", "gw-1", upstream_port=8080, extras=extras
        )
        assert new_id == "res-9"
        create = _sent(route)[1]
        assert create["variables"] == {
            "name": "app",
            "address": "app.internal",
            "remoteNetworkId": "rn-1",
            "gatewayId": "gw-1",
            "upstream": {"port": 8080, "tlsMode": "NONE"},
            "downstream": {"port": 80, "tlsMode": "NONE"},
            "requestHeaderRewrites": [{"key": "X-User", "value": "{{username}}"}],
        }


class TestUpdatesDispatchThroughTheKind:
    async def test_address_uses_update_mutation(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=_ok("webAppResourceUpdate"))
        await update_resource_address(tg, "webapp", "res-1", "new.internal")
        [sent] = _sent(route)
        assert "webAppResourceUpdate(id: $id, address: $address)" in sent["query"]
        assert sent["query"].startswith("\nmutation UpdateResourceAddress(")
        assert sent["variables"] == {"id": "res-1", "address": "new.internal"}

    async def test_address_error_is_unwrapped_from_the_kinds_field(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"webAppResourceUpdate": {"ok": False, "error": "nope"}}}
            )
        )
        with pytest.raises(TGAPIError, match="nope"):
            await update_resource_address(tg, "webapp", "res-1", "new.internal")

    async def test_access_uses_update_mutation_with_the_same_delta_semantics(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=_ok("webAppResourceUpdate"))
        await update_resource_access(
            tg, "webapp", "res-1", added_group_ids=["g-1"], removed_group_ids=[]
        )
        [sent] = _sent(route)
        assert "webAppResourceUpdate(\n    id: $id, addedGroupIds: $addedGroupIds" in sent["query"]
        query = sent["query"].replace("addedGroupIds: $addedGroupIds", "")
        assert "groupIds: $groupIds" not in query
        assert sent["variables"] == {"id": "res-1", "addedGroupIds": ["g-1"]}


class TestUpdateResourceSettings:
    async def test_sends_declared_keys_and_distinguishes_absent_from_null(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=_ok("webAppResourceUpdate"))
        await update_resource_settings(
            tg,
            "webapp",
            "res-1",
            {
                "alias": None,
                "requestHeaderRewrites": [],
                "upstream": {"port": 81, "tlsMode": "NONE"},
            },
        )
        [sent] = _sent(route)
        assert sent["query"] == (
            "\nmutation UpdateWebAppResourceSettings($id: ID!, $upstream: WebAppUpstreamInput, "
            "$downstream: WebAppDownstreamInput, $alias: String, "
            "$requestHeaderRewrites: [KeyValueInputObject!]) {\n"
            "  webAppResourceUpdate(id: $id, upstream: $upstream, downstream: $downstream, "
            "alias: $alias, requestHeaderRewrites: $requestHeaderRewrites) {\n"
            "    ok\n    error\n  }\n}\n"
        )
        assert sent["variables"] == {
            "id": "res-1",
            "alias": None,
            "requestHeaderRewrites": [],
            "upstream": {"port": 81, "tlsMode": "NONE"},
        }
        assert "downstream" not in sent["variables"]

    async def test_error_is_unwrapped(self, tg: TGClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"webAppResourceUpdate": {"ok": False, "error": "bad alias"}}}
            )
        )
        with pytest.raises(TGAPIError, match="bad alias") as exc_info:
            await update_resource_settings(tg, "webapp", "res-1", {"alias": "x"})
        assert exc_info.value.query_name == "UpdateWebAppResourceSettings"

    async def test_undeclared_key_is_refused_without_a_request(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="undeclared settings"):
            await update_resource_settings(tg, "webapp", "res-1", {"name": "x"})
        assert route.call_count == 0

    async def test_empty_variables_are_refused(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="no settings to update"):
            await update_resource_settings(tg, "webapp", "res-1", {})
        assert route.call_count == 0

    @pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
    async def test_kinds_without_settings_refuse_every_key(
        self, tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="undeclared settings"):
            await update_resource_settings(tg, kind_key, "res-1", {"alias": "x"})
        assert route.call_count == 0


class TestCreateVariablesRefusal:
    """`create_resource` refuses variables the kind's create mutation cannot carry."""

    _EXTRAS: Mapping[str, Any] = {
        "upstream_tls": "NONE",
        "downstream": (80, "NONE"),
        "rewrites": (),
    }

    async def _create(self, tg: TGClient, kind: ResourceKind) -> str:
        return await create_resource(
            tg, kind, "app", "app.internal", "gw-1", upstream_port=8080, extras=self._EXTRAS
        )

    async def test_an_undeclared_key_is_refused_without_a_request(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        kind = replace(
            WEBAPP, create_variables=lambda port, extras: {"upstream": {"port": port}, "bogus": 1}
        )
        with pytest.raises(ValueError, match=r"undeclared variables \['bogus'\]"):
            await self._create(tg, kind)
        assert route.call_count == 0

    @pytest.mark.parametrize("shared", ["name", "address", "remoteNetworkId", "gatewayId",
                                        "groupIds", "securityPolicyId"])
    async def test_a_key_shadowing_a_shared_variable_is_refused(
        self, tg: TGClient, respx_mock: respx.MockRouter, shared: str
    ) -> None:
        route = respx_mock.post(_URL)
        # Even declared as an extra argument, a shared name would overwrite the real value.
        kind = replace(
            WEBAPP,
            extra_create_args=(*WEBAPP.extra_create_args, (shared, "String")),
            create_variables=lambda port, extras: {"upstream": {"port": port}, shared: "evil"},
        )
        with pytest.raises(ValueError, match=rf"overlaps the shared variables \['{shared}'\]"):
            await self._create(tg, kind)
        assert route.call_count == 0

    async def test_upstream_alone_and_declared_extras_are_accepted(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn-1"}}}}),
            _ok("sshResourceCreate", entity={"id": "res-1"}),
            _ok("webAppResourceCreate", entity={"id": "res-2"}),
        ]
        assert await self._create(tg, SSH) == "res-1"  # default hook: `upstream` only
        assert await self._create(tg, WEBAPP) == "res-2"  # upstream + declared extras
