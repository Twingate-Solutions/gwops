"""A refusal raised by a TG op for one resource is that resource's error, not the pass's.

``ops.create_resource`` (and ``ops.update_resource_settings``) raise ``ValueError`` before
any request when a kind's variables do not fit its mutation. That must be recorded per
resource by ``_sync_tg``; an escaping ``ValueError`` would abort the whole reconcile and
skip the local render/apply.
"""

from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from gwops.kindhooks import Extras
from gwops.kinds import SSH, ResourceKind
from gwops.reconciler import core
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:2222
  - name: web-2
    address: 10.0.0.6
"""


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


def _bad_for_port_2222(port: int, extras: Extras) -> dict[str, Any]:
    """Create variables that carry an undeclared key for one resource only."""
    variables: dict[str, Any] = {"upstream": {"port": port}}
    if port == 2222:
        variables["notDeclared"] = True
    return variables


class TestCreateVariableRefusal:
    async def test_a_refused_create_is_a_per_resource_error_and_the_pass_continues(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        picky: ResourceKind = replace(SSH, create_variables=_bad_for_port_2222)
        monkeypatch.setattr(core, "by_key", lambda key: picky)
        env = Env(tmp_path, _SEED, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        # web-1 is refused, recorded against web-1, and never reached the tenant ...
        [refusal] = result.resource_errors["ssh/web-1"]
        assert "undeclared variables ['notDeclared']" in refusal
        assert f"TG sync: ssh/web-1: {refusal}" in result.errors
        assert "ssh/web-1" not in result.tg_synced
        assert tg_server.calls.count("CreateSSHResource") == 1  # web-2's only
        assert {r.name for r in tg_server.resources.values()} == {"web-2"}
        # ... web-2, later in the same pass, is created normally ...
        assert "ssh/web-2" not in result.resource_errors
        assert "ssh/web-2" in result.tg_synced
        # ... and the local steps still ran: this is a TG-side error, not a local one.
        assert result.ok is False
        assert result.local_ok is True
        assert env.config_path.is_file()
        assert env.process.calls == ["start"]
