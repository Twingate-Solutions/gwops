"""`/status` `tg.ok` and `tg.attempted`: a pass that aborted before TG sync proves nothing."""

from pathlib import Path
from typing import Any

import httpx
import pytest

from gwops.api.app import create_app
from gwops.reconciler.core import ReconcileResult
from gwops.tgapi.client import TGClient

from .conftest import ADMIN_TOKEN, make_deps, ok_result


async def _tg_block(
    tmp_path: Path, result: ReconcileResult | None, *, configured: bool = True
) -> dict[str, Any]:
    bundle = make_deps(tmp_path)
    tg = TGClient(network="acme", api_key="k") if configured else None
    bundle.deps.tg = tg
    bundle.reconciler.last_result = result
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    ) as client:
        body = (await client.get("/status")).json()
    if tg is not None:
        await tg.aclose()
    block: dict[str, Any] = body["tg"]
    return block


def _failed(*errors: str, local_ok: bool = False) -> ReconcileResult:
    result = ok_result("api")
    result.ok = False
    result.local_ok = local_ok
    result.errors = list(errors)
    return result


class TestAbortedBeforeSync:
    @pytest.mark.parametrize(
        "error",
        [
            "web-app policy: web_apps entry 'x': header 'Host' is denied (Host header)",
            "effective state failed to load: effective config is invalid",
        ],
    )
    async def test_an_aborted_pass_reports_null_and_not_attempted(
        self, tmp_path: Path, error: str
    ) -> None:
        block = await _tg_block(tmp_path, _failed(error))
        assert block["ok"] is None
        assert block["attempted"] is False
        assert block["errors"] == []

    async def test_an_explicit_tg_attempted_false_wins(self, tmp_path: Path) -> None:
        result = _failed("gateway start failed: boom")
        result.tg_attempted = False  # type: ignore[attr-defined]
        block = await _tg_block(tmp_path, result)
        assert (block["ok"], block["attempted"]) == (None, False)

    async def test_an_explicit_tg_attempted_true_wins(self, tmp_path: Path) -> None:
        result = _failed("web-app policy: web_apps entry 'x': bad")
        result.tg_attempted = True  # type: ignore[attr-defined]
        block = await _tg_block(tmp_path, result)
        assert (block["ok"], block["attempted"]) == (True, True)


class TestReachedSync:
    async def test_a_clean_pass_is_ok_and_attempted(self, tmp_path: Path) -> None:
        block = await _tg_block(tmp_path, ok_result("tick"))
        assert (block["ok"], block["attempted"]) == (True, True)

    async def test_a_tg_sync_error_is_not_ok_but_attempted(self, tmp_path: Path) -> None:
        block = await _tg_block(
            tmp_path, _failed("TG sync failed: could not list resources: x", local_ok=True)
        )
        assert (block["ok"], block["attempted"]) == (False, True)
        assert len(block["errors"]) == 1

    async def test_a_local_failure_after_sync_keeps_ok_true(self, tmp_path: Path) -> None:
        block = await _tg_block(tmp_path, _failed("gateway start failed: boom"))
        assert (block["ok"], block["attempted"]) == (True, True)


class TestNothingToReport:
    async def test_unconfigured_is_not_ok_and_not_attempted(self, tmp_path: Path) -> None:
        block = await _tg_block(tmp_path, ok_result("tick"), configured=False)
        assert (block["configured"], block["ok"], block["attempted"]) == (False, False, False)

    async def test_before_the_first_pass_is_not_ok_and_not_attempted(
        self, tmp_path: Path
    ) -> None:
        block = await _tg_block(tmp_path, None)
        assert (block["ok"], block["attempted"]) == (False, False)
