"""WebAppIndex: the ``gwops`` object spliced into ``Authenticated connection`` lines."""

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import structlog.testing

from gwops.reconciler.core import RemoteWebApp
from gwops.shipper.counters import FailureLog
from gwops.shipper.enrich import WebAppIndex

GW = "R2F0ZXdheToxMjk0"
ADDRESS = "verifier-a.example.test"

_AUTH_LINE = (
    b'{"levelname":"info","ts":"2026-10-08T18:56:48.385Z","logger":"system",'
    b'"caller":"frontend/conn.go:226","message":"Authenticated connection",'
    b'"version":"2.0.0","user":{"username":"u@example.test"},'
    b'"conn_id":"8026911c","resource_type":"WEB_APP","resource_address":"verifier-a.example.test"}'
)


def _app(name: str = "verifier-a", **fields: Any) -> RemoteWebApp:
    values: dict[str, Any] = {
        "id": f"r-{name}",
        "name": name,
        "gateway_id": GW,
        "address": ADDRESS,
        "upstream_port": 8443,
        "alias": None,
        "upstream_tls": "verify_full",
        "downstream_tls": "tls13",
        "downstream_port": 443,
        "header_rewrite_names": (),
        "managed": True,
    }
    values.update(fields)
    return RemoteWebApp(**values)


def _index(apps: list[RemoteWebApp] | None, gateway_id: str | None = GW, **kw: Any) -> WebAppIndex:
    index = WebAppIndex()
    index.update(apps, gateway_id, **kw)
    return index


def _run(index: WebAppIndex, line: bytes = _AUTH_LINE) -> bytes:
    return index.enrich(line, json.loads(line))


def _gwops(index: WebAppIndex, line: bytes = _AUTH_LINE) -> dict[str, Any]:
    out = json.loads(_run(index, line))["gwops"]
    assert isinstance(out, dict)
    return out


class TestMatch:
    def test_exact_carries_the_app_fields(self) -> None:
        assert _gwops(_index([_app()])) == {
            "schema": 1,
            "gateway_id": GW,
            "match": "exact",
            "app": "verifier-a",
            "managed": True,
            "downstream_tls": "tls13",
            "downstream_port": 443,
            "upstream_tls": "verify_full",
            "upstream_port": 8443,
        }

    def test_exact_serialises_compactly_in_the_documented_order(self) -> None:
        tail = _run(_index([_app()]))[len(_AUTH_LINE) - 1 :]
        assert tail == (
            b',"gwops":{"schema":1,"gateway_id":"R2F0ZXdheToxMjk0","match":"exact",'
            b'"app":"verifier-a","managed":true,"downstream_tls":"tls13","downstream_port":443,'
            b'"upstream_tls":"verify_full","upstream_port":8443}}'
        )

    def test_no_app_at_the_address_is_none(self) -> None:
        assert _gwops(_index([_app(address="other.example.test")])) == {
            "schema": 1,
            "gateway_id": GW,
            "match": "none",
        }

    def test_two_apps_at_the_address_are_ambiguous(self) -> None:
        index = _index([_app("a"), _app("b")])
        assert _gwops(index) == {"schema": 1, "gateway_id": GW, "match": "ambiguous"}

    def test_an_app_bound_to_another_gateway_is_excluded(self) -> None:
        assert _gwops(_index([_app(gateway_id="other-gw")]))["match"] == "none"

    def test_another_gateways_app_does_not_make_this_one_ambiguous(self) -> None:
        index = _index([_app("mine"), _app("theirs", gateway_id="other-gw")])
        gwops = _gwops(index)
        assert (gwops["match"], gwops["app"]) == ("exact", "mine")

    def test_an_alias_only_address_does_not_match(self) -> None:
        index = _index([_app(address="real.example.test", alias=ADDRESS)])
        assert _gwops(index)["match"] == "none"

    def test_an_unmanaged_app_is_matched_under_its_tenant_name(self) -> None:
        index = _index([_app("tenant-name", managed=False)])
        gwops = _gwops(index)
        assert (gwops["match"], gwops["app"], gwops["managed"]) == ("exact", "tenant-name", False)

    def test_a_managed_app_is_named_by_its_declared_entry(self) -> None:
        index = _index([_app("renamed")], managed_ids={"webapp/declared": "r-renamed"})
        assert _gwops(index)["app"] == "declared"

    def test_a_managed_app_missing_from_the_registry_keeps_its_tenant_name(self) -> None:
        index = _index([_app("tenant-name")], managed_ids={"ssh/other": "r-other"})
        assert _gwops(index)["app"] == "tenant-name"

    def test_the_address_is_matched_exactly(self) -> None:
        index = _index([_app(address=ADDRESS.upper())])
        assert _gwops(index)["match"] == "none"

    @pytest.mark.parametrize("address", [None, 443, ["a"], {"a": 1}])
    def test_a_non_string_address_is_none(self, address: object) -> None:
        obj = json.loads(_AUTH_LINE)
        obj["resource_address"] = address
        out = _index([_app()]).enrich(_AUTH_LINE, obj)
        assert json.loads(out)["gwops"]["match"] == "none"

    def test_a_missing_address_is_none(self) -> None:
        obj = json.loads(_AUTH_LINE)
        del obj["resource_address"]
        out = _index([_app()]).enrich(_AUTH_LINE, obj)
        assert json.loads(out)["gwops"]["match"] == "none"


class TestGatewayId:
    def test_null_before_the_gateway_is_recorded(self) -> None:
        assert _gwops(_index([_app()], gateway_id=None)) == {
            "schema": 1,
            "gateway_id": None,
            "match": "none",
        }

    def test_the_id_is_picked_up_by_a_later_update(self) -> None:
        index = _index(None, gateway_id=None)
        index.update([_app()], GW)
        assert _gwops(index)["match"] == "exact"
        assert index.gateway_id == GW


class TestSnapshotStaleness:
    def test_never_succeeded_is_none(self) -> None:
        assert _gwops(_index(None)) == {"schema": 1, "gateway_id": GW, "match": "none"}

    def test_a_pass_without_a_listing_keeps_the_last_snapshot(self) -> None:
        index = _index([_app()])
        index.update(None, GW)
        assert _gwops(index)["match"] == "exact"

    def test_a_later_listing_replaces_the_snapshot(self) -> None:
        index = _index([_app()])
        index.update([], GW)
        assert _gwops(index)["match"] == "none"

    def test_an_empty_listing_is_a_snapshot_not_a_missing_one(self) -> None:
        index = _index([_app()])
        index.update([], GW)
        index.update(None, GW)
        assert _gwops(index)["match"] == "none"


class TestUntouchedLines:
    def test_original_bytes_are_a_prefix_up_to_the_final_brace(self) -> None:
        out = _run(_index([_app()]))
        assert out.startswith(_AUTH_LINE[:-1])
        assert out.endswith(b"}}")
        assert out[len(_AUTH_LINE) - 1 :].startswith(b',"gwops":{')

    def test_the_result_parses_and_keeps_every_gateway_field(self) -> None:
        out = json.loads(_run(_index([_app()])))
        original = json.loads(_AUTH_LINE)
        assert {k: v for k, v in out.items() if k != "gwops"} == original

    def test_trailing_whitespace_stays_after_the_final_brace(self) -> None:
        out = _run(_index([_app()]), _AUTH_LINE + b" \r\n")
        assert out.endswith(b"}}" + b" \r\n")
        assert out.startswith(_AUTH_LINE[:-1])
        assert json.loads(out)["gwops"]["match"] == "exact"

    def test_a_line_with_an_existing_gwops_key_is_unchanged(self) -> None:
        line = _AUTH_LINE[:-1] + b',"gwops":{"schema":9}}'
        assert _run(_index([_app()]), line) == line

    @pytest.mark.parametrize("resource_type", ["SSH", "KUBERNETES", None])
    def test_a_non_web_app_connection_is_unchanged(self, resource_type: str | None) -> None:
        obj = json.loads(_AUTH_LINE)
        obj["resource_type"] = resource_type
        assert _index([_app()]).enrich(_AUTH_LINE, obj) == _AUTH_LINE

    @pytest.mark.parametrize(
        "change",
        [
            {"message": "Connection closed"},
            {"logger": "gateway"},
            {"logger": "gateway.audit"},
            {"logger": "audit"},
            {"logger": "session_recording"},
            {"logger": "other"},
        ],
    )
    def test_a_different_line_is_unchanged(self, change: dict[str, str]) -> None:
        obj = {**json.loads(_AUTH_LINE), **change}
        assert _index([_app()]).enrich(_AUTH_LINE, obj) == _AUTH_LINE

    def test_a_line_not_ending_in_a_brace_is_unchanged(self) -> None:
        line = _AUTH_LINE + b" trailing"
        assert _index([_app()]).enrich(line, json.loads(_AUTH_LINE)) == line

    def test_an_odd_object_never_raises(self) -> None:
        assert _index([_app()]).enrich(b"{}", {}) == b"{}"


class TestEnrichFailure:
    @staticmethod
    def _boom(_self: object, _address: object) -> dict[str, Any]:
        raise RuntimeError("builder exploded")

    def test_a_failing_builder_returns_the_original_bytes_counts_and_logs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failed: list[int] = []
        index = WebAppIndex(on_enrich_failed=lambda: failed.append(1))
        index.update([_app()], GW)
        monkeypatch.setattr(WebAppIndex, "_gwops", self._boom)

        with structlog.testing.capture_logs() as logs:
            out = _run(index)

        assert out == _AUTH_LINE
        assert failed == [1]
        [entry] = [e for e in logs if e["event"] == "enrich.failed"]
        assert entry["log_level"] == "error"
        assert entry["error_type"] == "RuntimeError"
        assert re.fullmatch(r"test_enrich\.py:\d+", entry["location"])
        assert "u@example.test" not in repr(logs)  # no line content
        assert "builder exploded" not in repr(logs)

    def test_failures_log_once_per_type_per_interval_but_are_always_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = [0.0]
        failed: list[int] = []
        index = WebAppIndex(on_enrich_failed=lambda: failed.append(1))
        index._failures = FailureLog("enrich.failed", clock=lambda: now[0])
        monkeypatch.setattr(WebAppIndex, "_gwops", self._boom)

        with structlog.testing.capture_logs() as logs:
            for at in (0.0, 1.0, 30.0):
                now[0] = at
                _run(index)
            assert len(logs) == 1
            now[0] = 61.0
            _run(index)

        assert len(failed) == 4
        assert [e.get("suppressed") for e in logs] == [None, 2]

    def test_a_failure_of_another_type_logs_at_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        index = WebAppIndex()
        monkeypatch.setattr(WebAppIndex, "_gwops", self._boom)
        with structlog.testing.capture_logs() as logs:
            _run(index)

            def other(_self: object, _address: object) -> dict[str, Any]:
                raise KeyError("x")

            monkeypatch.setattr(WebAppIndex, "_gwops", other)
            _run(index)
        assert [e["error_type"] for e in logs] == ["RuntimeError", "KeyError"]


class TestFreshness:
    def test_a_new_index_is_inactive(self) -> None:
        index = WebAppIndex()
        assert (index.active, index.last_update_at, index.apps) == (False, None, 0)

    def test_a_listing_makes_it_active_and_stamps_utc_now(self) -> None:
        index = WebAppIndex()
        before = datetime.now(UTC)
        index.update([_app("a"), _app("b", address="other.example.test")], GW)
        assert index.active is True
        assert index.apps == 2
        assert index.last_update_at is not None
        assert before <= index.last_update_at <= datetime.now(UTC)
        assert index.last_update_at.utcoffset() == timedelta(0)

    def test_only_apps_bound_to_this_gateway_are_counted(self) -> None:
        index = WebAppIndex()
        index.update([_app("mine"), _app("theirs", gateway_id="other-gw")], GW)
        assert index.apps == 1

    def test_an_empty_listing_is_active_with_no_apps(self) -> None:
        index = _index([])
        assert (index.active, index.apps) == (True, 0)

    def test_a_pass_without_a_listing_keeps_the_stamp_and_count(self) -> None:
        index = _index([_app()])
        stamp = index.last_update_at
        index.update(None, GW)
        assert (index.last_update_at, index.apps, index.active) == (stamp, 1, True)

    def test_transitions_between_fresh_and_stale_log_once_each(self) -> None:
        index = WebAppIndex()
        with structlog.testing.capture_logs() as logs:
            index.update([_app()], GW)  # first pass fresh: nothing to report
            index.update([_app()], GW)
            index.update(None, GW)  # -> stale
            index.update(None, GW)
            index.update([_app()], GW)  # -> fresh
        assert [(e["event"], e["log_level"]) for e in logs] == [
            ("enrich.index_stale", "warning"),
            ("enrich.index_fresh", "info"),
        ]
        assert logs[0]["last_update_at"] is not None

    def test_a_stale_first_pass_is_reported_with_no_update_time(self) -> None:
        index = WebAppIndex()
        with structlog.testing.capture_logs() as logs:
            index.update(None, GW)
            index.update(None, GW)
        assert [(e["event"], e["last_update_at"]) for e in logs] == [("enrich.index_stale", None)]

    def test_mark_stale_counts_as_a_pass_without_a_listing(self) -> None:
        index = _index([_app()])
        with structlog.testing.capture_logs() as logs:
            index.mark_stale()
            index.mark_stale()
        assert [e["event"] for e in logs] == ["enrich.index_stale"]


class TestNeverAdded:
    def test_no_header_or_credential_or_group_data_reaches_the_object(self) -> None:
        app = _app(
            alias="alias.example.test",
            header_rewrite_names=("authorization", "x-api-key"),
        )
        gwops = _gwops(_index([app]))
        assert set(gwops) == {
            "schema",
            "gateway_id",
            "match",
            "app",
            "managed",
            "downstream_tls",
            "downstream_port",
            "upstream_tls",
            "upstream_port",
        }
        raw = _run(_index([app]))
        assert b"authorization" not in raw
        assert b"alias.example.test" not in raw
