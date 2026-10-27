"""The uvicorn serving path: a real socket, a real HTTP round-trip, clean shutdown."""

from pathlib import Path

import httpx
import pytest

from gwops.api.app import create_app
from gwops.supervisor.main import start_admin_server

from .conftest import ADMIN_TOKEN, make_deps


class TestStartAdminServer:
    async def test_serves_over_a_real_socket_and_stops_cleanly(
        self, tmp_path: Path
    ) -> None:
        bundle = make_deps(tmp_path)
        app = create_app(bundle.deps)
        admin = start_admin_server(app, "127.0.0.1", 0)  # 0 = ephemeral test port
        try:
            base = f"http://127.0.0.1:{admin.port}"
            async with httpx.AsyncClient() as client:
                health = await client.get(f"{base}/healthz")
                assert health.status_code in (200, 503)
                unauthed = await client.get(f"{base}/status")
                assert unauthed.status_code == 401
                authed = await client.get(
                    f"{base}/status",
                    headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
                )
                assert authed.status_code == 200
        finally:
            await admin.stop()
        assert admin.task.done()

    async def test_bind_conflict_fails_loud(self, tmp_path: Path) -> None:
        bundle = make_deps(tmp_path)
        app = create_app(bundle.deps)
        first = start_admin_server(app, "127.0.0.1", 0)
        try:
            with pytest.raises(OSError):
                start_admin_server(app, "127.0.0.1", first.port)
        finally:
            await first.stop()
