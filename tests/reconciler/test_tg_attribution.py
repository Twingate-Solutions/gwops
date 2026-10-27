"""`tg_attribution` (kinds and TLS sources for the TG User-Agent) and its use by a pass."""

import re
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, get_args

import httpx
import pytest
import respx
from pydantic import BaseModel

from gwops._version import __version__
from gwops.configmodel.schema import AcmePublicCertificate, FilePublicCertificate
from gwops.kinds import KINDS
from gwops.reconciler.core import tg_attribution
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient, build_user_agent
from tests.api.acme_support import acme_block, acme_cert
from tests.public_tls_support import (
    ZONE,
    k8s,
    load,
    public_cert,
    public_seed,
    ssh,
    tls_block,
    webapp,
)

from .conftest import FakeTGServer
from .test_core import _SSH_SEED, Env

_TG_URL = "https://acme.twingate.com/api/graphql/"
_TWINGATE = {"network": "acme", "gateway_id": "g-1"}
_LIB = f"python-httpx/{httpx.__version__}"


def _private_seed(**top: Any) -> dict[str, Any]:
    return {"twingate": dict(_TWINGATE), **top}


class TestKinds:
    def test_no_entries_gives_no_kinds(self, tmp_path: Path) -> None:
        assert tg_attribution(load(tmp_path, _private_seed())) == ([], [])

    def test_one_kind(self, tmp_path: Path) -> None:
        state = load(tmp_path, _private_seed(ssh_upstreams=[ssh("a", "10.0.0.5:22")]))
        assert tg_attribution(state) == (["ssh"], [])

    def test_several_kinds_are_all_reported(self, tmp_path: Path) -> None:
        state = load(
            tmp_path,
            _private_seed(
                web_apps=[webapp("w", "w.internal")],
                k8s_clusters=[k8s("p", "p.k8s.internal")],
                ssh_upstreams=[ssh("a", "10.0.0.5:22")],
            ),
        )
        kinds, tls = tg_attribution(state)
        assert set(kinds) == {"ssh", "kubernetes", "webapp"}
        assert len(kinds) == 3
        assert tls == []
        assert build_user_agent(version="1", kinds=kinds, tls=tls) == (
            f"twingate-gwops-gateway/1 (kinds=kubernetes,ssh,webapp; tls=none) {_LIB}"
        )

    def test_a_kind_with_no_entries_is_left_out(self, tmp_path: Path) -> None:
        state = load(tmp_path, _private_seed(web_apps=[webapp("w", "w.internal")]))
        assert tg_attribution(state)[0] == ["webapp"]


class TestAttributionTokensAreUserAgentSafe:
    """A new kind key or cert source must not break `build_user_agent` at runtime."""

    _SAFE = re.compile(r"[a-z0-9._-]+")

    def test_every_kind_key_is_safe(self) -> None:
        assert KINDS
        for kind in KINDS:
            assert self._SAFE.fullmatch(kind.key), kind.key

    @pytest.mark.parametrize("model", [FilePublicCertificate, AcmePublicCertificate])
    def test_every_certificate_source_literal_is_safe(self, model: type[BaseModel]) -> None:
        sources = get_args(model.model_fields["source"].annotation)
        assert sources, f"{model.__name__}.source is not a Literal"
        for source in sources:
            assert self._SAFE.fullmatch(source), source

    def test_the_keys_and_sources_build_a_user_agent(self) -> None:
        sources = [
            s
            for model in (FilePublicCertificate, AcmePublicCertificate)
            for s in get_args(model.model_fields["source"].annotation)
        ]
        ua = build_user_agent(version="1", kinds=[k.key for k in KINDS], tls=sources)
        assert ua.startswith("twingate-gwops-gateway/1 (kinds=")


class TestTlsSources:
    def test_no_public_tls_block_gives_an_empty_tls_set(self, tmp_path: Path) -> None:
        state = load(tmp_path, _private_seed(ssh_upstreams=[ssh("a", "10.0.0.5:22")]))
        assert state.public_tls is None
        assert tg_attribution(state)[1] == []

    def test_all_file_certificates(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[
                public_cert("one", [f"*.{ZONE}"]),
                public_cert("two", [f"*.apps.{ZONE}"]),
            ]
        )
        state = load(tmp_path, public_seed(tls))
        assert tg_attribution(state)[1] == ["file"]

    def test_all_acme_certificates(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[acme_cert()], acme=acme_block())
        state = load(tmp_path, public_seed(tls))
        assert tg_attribution(state)[1] == ["acme"]

    def test_mixed_sources_are_sorted(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[public_cert("wild", [f"*.{ZONE}"]), acme_cert()],
            acme=acme_block(),
        )
        state = load(tmp_path, public_seed(tls))
        assert tg_attribution(state)[1] == ["acme", "file"]

    def test_kinds_and_tls_are_reported_together(self, tmp_path: Path) -> None:
        seed = public_seed(ssh_upstreams=[ssh("a", f"host1.{ZONE}:22")])
        assert tg_attribution(load(tmp_path, seed)) == (["ssh"], ["file"])


@pytest.fixture
async def tg_client() -> AsyncIterator[TGClient]:
    client = TGClient(network="acme", api_key="test-key")
    yield client
    await client.aclose()


class TestPassSendsRefreshedUserAgent:
    async def test_every_call_of_a_pass_carries_the_config_attribution_and_via_reconcile(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
        respx_mock: respx.MockRouter,
    ) -> None:
        server = FakeTGServer()
        user_agents: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            user_agents.append(request.headers["User-Agent"])
            return server.handler(request)

        respx_mock.post(_TG_URL).mock(side_effect=handler)
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert user_agents, "the pass made no TG calls"
        lib = f"python-httpx/{httpx.__version__}"
        pattern = re.compile(
            re.escape(f"twingate-gwops-gateway/{__version__} (kinds=ssh; tls=none; op=")
            + r"(read|write)"
            + re.escape(f"; via=reconcile) {lib}")
        )
        assert all(pattern.fullmatch(ua) for ua in user_agents), user_agents
        ops_seen = {re.search(r"op=(\w+)", ua).group(1) for ua in user_agents}  # type: ignore[union-attr]
        assert ops_seen == {"read", "write"}
        # The client default carries the config-level string (no op, no via).
        assert tg_client._client.headers["User-Agent"] == (
            f"twingate-gwops-gateway/{__version__} (kinds=ssh; tls=none) {lib}"
        )
