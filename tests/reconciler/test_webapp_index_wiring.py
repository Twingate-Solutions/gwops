"""Each reconcile pass feeds the recording enrichment index (``WebAppIndex``)."""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog.testing
import yaml

from gwops.renderer.capabilities import Capabilities
from gwops.shipper.enrich import WebAppIndex
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_ADDRESS = "grafana.corp.internal"
_LINE = (
    b'{"logger":"system","message":"Authenticated connection","resource_type":"WEB_APP",'
    b'"resource_address":"grafana.corp.internal"}'
)


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


def _seed() -> str:
    doc: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": "g-1"},
        "web_apps": [{"name": "grafana", "address": _ADDRESS}],
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _gwops(index: WebAppIndex) -> dict[str, Any]:
    out = json.loads(index.enrich(_LINE, json.loads(_LINE)))["gwops"]
    assert isinstance(out, dict)
    return out


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[WebAppIndex | None, TGClient | None], Env]:
    def _make(index: WebAppIndex | None, tg: TGClient | None = tg_client) -> Env:
        return Env(
            tmp_path, _seed(), gateway_binary(), Capabilities(gateway_version="2.0.0"), tg,
            webapp_index=index,
        )

    return _make


async def test_a_listing_pass_updates_the_index(
    make_env: Callable[..., Env], tg_server: FakeTGServer
) -> None:
    index = WebAppIndex()
    env = make_env(index)

    await env.reconciler.reconcile("startup")  # creates the app
    await env.reconciler.reconcile("tick")  # lists it

    assert index.gateway_id == "g-1"
    assert _gwops(index) == {
        "schema": 1,
        "gateway_id": "g-1",
        "match": "exact",
        "app": "grafana",
        "managed": True,
        "downstream_tls": "tls13",
        "downstream_port": 443,
        "upstream_tls": "verify_full",
        "upstream_port": 443,
    }


async def test_a_pass_that_could_not_list_the_tenant_keeps_the_index(
    make_env: Callable[..., Env], tg_server: FakeTGServer
) -> None:
    index = WebAppIndex()
    env = make_env(index)
    await env.reconciler.reconcile("startup")
    await env.reconciler.reconcile("tick")
    tg_server.fail = True

    result = await env.reconciler.reconcile("tick")

    assert result.remote_web_apps is None
    assert _gwops(index)["match"] == "exact"


async def test_a_pass_without_an_api_key_records_the_gateway_id_only(
    make_env: Callable[..., Env],
) -> None:
    index = WebAppIndex()
    env = make_env(index, None)

    await env.reconciler.reconcile("startup")

    assert index.gateway_id == "g-1"
    assert _gwops(index) == {"schema": 1, "gateway_id": "g-1", "match": "none"}


async def test_a_failing_index_update_never_fails_the_pass(
    make_env: Callable[..., Env], tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = WebAppIndex()

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("index exploded")

    monkeypatch.setattr(index, "update", boom)
    env = make_env(index)

    result = await env.reconciler.reconcile("startup")

    assert result.ok is True
    assert result.local_ok is True


async def test_a_failing_index_update_is_recorded_as_a_web_app_warning(
    make_env: Callable[..., Env], tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = WebAppIndex()

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("index exploded")

    monkeypatch.setattr(index, "update", boom)
    env = make_env(index)

    result = await env.reconciler.reconcile("startup")

    [warning] = [w for w in result.webapp_warnings if "enrichment index" in w]
    assert "RuntimeError" in warning
    assert "index exploded" not in warning
    assert result.ok is True and result.errors == []
    assert env.reconciler.last_result is result


async def test_a_failing_index_update_marks_the_index_stale(
    make_env: Callable[..., Env], tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = WebAppIndex()
    env = make_env(index)
    await env.reconciler.reconcile("startup")
    await env.reconciler.reconcile("tick")
    assert index.active

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("index exploded")

    monkeypatch.setattr(index, "update", boom)
    with structlog.testing.capture_logs() as logs:
        await env.reconciler.reconcile("tick")

    assert [e["event"] for e in logs if e["event"].startswith("enrich.")] == ["enrich.index_stale"]
