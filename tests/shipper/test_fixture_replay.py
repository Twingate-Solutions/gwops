"""Scrubbed real-gateway fixture: no tenant data in it, and the filter's verdict on every line."""

import base64
import binascii
import json
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from gwops.reconciler.core import RemoteWebApp
from gwops.shipper.filter import DropReason, classify
from gwops.supervisor.main import BootstrapResult, bootstrap
from tests.drops_support import expected_drops
from tests.on_demand_support import make_settings

FIXTURE = Path(__file__).parent.parent / "fixtures" / "webapp_gateway_lines.ndjson"
RECORDING_FIXTURE = Path(__file__).parent.parent / "fixtures" / "ga_recording_lines.ndjson"
GW = "g-1"
OTHER_GW = "g-2"

_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
recording:
  enabled: true
  receiver_url: http://gatorcast.test:8000
"""

# Hand-checked against the fixture: 158 lines = 151 JSON + 7 plain text (the `Error: use of closed
# network connection` line and the cobra usage block, with its blank line, that the GA binary
# prints on SIGTERM). Of the JSON lines, 58 are `Authenticated connection` (logger `system`, all
# WEB_APP) and 55 are `API request completed` (logger `audit`): 113 kept. The other 38 are
# `system` lines: startup, shutdown (`HTTP proxy stopped with error`, `Proxy component error`),
# cert reloads, `No redirect received`, `failed to serve request`,
# `Failed to authenticate connection`, and 7 standard-library lines the GA binary routes through
# the `system` logger (`http: proxy error: ...`, `Unsolicited response received ...`).
KEPT = 113
PLAIN = 7
STDLIB = 7
DROPPED = expected_drops(not_json=PLAIN, not_allowlisted=38)

# `Authenticated connection` lines per resource_address (sums to the 58 above).
AUTH_BY_APP = {
    "echo-plain": 18,
    "echo-tls": 8,
    "echo-vca": 1,
    "echo-wrongfull": 5,
    "verifier-a": 24,
    "verifier-b": 2,
}

_CREDENTIAL_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
_TWINGATE_ID_KINDS = (
    "Resource:", "Group:", "Gateway:", "ServiceAccount", "RemoteNetwork:", "Connector:", "User:"
)  # fmt: skip


def _raw_lines() -> list[bytes]:
    return FIXTURE.read_bytes().splitlines()  # LF or CRLF, per checkout


def _headers(obj: dict[str, Any]) -> list[tuple[str, list[str]]]:
    found = []
    for side in ("request", "response"):
        block = obj.get(side)
        if isinstance(block, dict):
            found += list((block.get("headers") or {}).items())
    return found


class TestFixtureHygiene:
    """The fixture is committed, so it must carry placeholders only."""

    def test_shape_is_158_lines_of_which_7_are_plain_text(self) -> None:
        lines = _raw_lines()
        assert FIXTURE.read_bytes().endswith(b"\n")
        assert len(lines) == 158
        assert sum(not line.startswith(b"{") for line in lines) == PLAIN
        for line in lines:
            if line.startswith(b"{"):
                json.loads(line)

    def test_no_tenant_host_or_integration_run_names(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8")
        assert re.search(r"[A-Za-z0-9-]+\.twingate\.com", text) is None
        assert "gwops-it-" not in text

    def test_no_private_ip_addresses(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8")
        private = re.compile(
            r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"
        )
        assert private.findall(text) == []
        assert re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text), "expected a documentation IP"

    def test_no_email_addresses(self) -> None:
        assert "@" not in FIXTURE.read_text(encoding="utf-8")

    def test_credential_header_values_are_placeholders(self) -> None:
        seen: set[str] = set()
        for line in _raw_lines():
            if not line.startswith(b"{"):
                continue
            for name, values in _headers(json.loads(line)):
                if name.lower() in _CREDENTIAL_HEADERS:
                    seen.add(name.lower())
                    assert values
                    assert all("PLACEHOLDER" in value for value in values), (name, values)
        assert seen == {"authorization", "cookie", "x-api-key"}

    def test_twingate_ids_decode_to_placeholders(self) -> None:
        checked = 0
        for token in set(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", FIXTURE.read_text("utf-8"))):
            try:
                decoded = base64.b64decode(token, validate=True).decode("ascii")
            except (binascii.Error, UnicodeDecodeError):
                continue
            if decoded.startswith(_TWINGATE_ID_KINDS):
                checked += 1
                assert "placeholder" in decoded, decoded
        assert checked >= 2  # user/key id and the service-account group id


class TestClassifyReplay:
    """Every fixture line through the pure classifier."""

    def test_counts_per_reason_match_the_hand_checked_expectation(self) -> None:
        verdicts = [classify(line) for line in _raw_lines()]
        assert sum(v.keep for v in verdicts) == KEPT
        dropped = Counter(v.reason for v in verdicts if not v.keep)
        assert {r.value: dropped.get(r, 0) for r in DropReason} == DROPPED

    def test_every_kept_line_is_an_allowlisted_shape(self) -> None:
        shapes: Counter[tuple[str, str]] = Counter()
        for line in _raw_lines():
            verdict = classify(line)
            if verdict.keep:
                assert verdict.obj == json.loads(line)
                shapes[(verdict.obj["logger"], verdict.obj["message"])] += 1
        assert shapes == {
            ("system", "Authenticated connection"): 58,
            ("audit", "API request completed"): 55,
        }

    def test_every_plain_text_line_is_dropped_as_not_json(self) -> None:
        plain = [line for line in _raw_lines() if not line.startswith(b"{")]
        assert len(plain) == PLAIN
        assert {classify(line).reason for line in plain} == {DropReason.NOT_JSON}

    def test_stdlib_log_lines_are_system_json_lines_and_are_dropped(self) -> None:
        stdlib = [
            json.loads(line)
            for line in _raw_lines()
            if line.startswith(b"{") and (b"http: proxy error" in line or b"Unsolicited" in line)
        ]
        assert len(stdlib) == STDLIB
        assert {o["logger"] for o in stdlib} == {"system"}
        assert all(not classify(json.dumps(o).encode()).keep for o in stdlib)

    def test_service_lines_are_dropped_as_not_allowlisted(self) -> None:
        service = [
            line
            for line in _raw_lines()
            if b'"logger":"system",' in line and b"Authenticated connection" not in line
        ]
        assert len(service) == DROPPED["not_allowlisted"]
        assert {classify(line).reason for line in service} == {DropReason.NOT_ALLOWLISTED}


def _recording_lines() -> list[bytes]:
    return RECORDING_FIXTURE.read_bytes().splitlines()


class TestRecordingFixture:
    """Hand-built GA-shaped SSH (segmented) and Kubernetes sessions: placeholders only."""

    def test_shape_and_hygiene(self) -> None:
        text = RECORDING_FIXTURE.read_text(encoding="utf-8")
        lines = _recording_lines()
        assert len(lines) == 11
        assert all(json.loads(line)["version"] == "2.0.0" for line in lines)
        assert "@" not in text
        assert "gateway.audit" not in text and '"logger":"gateway"' not in text
        for token in set(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)):
            try:
                decoded = base64.b64decode(token, validate=True).decode("ascii")
            except (binascii.Error, UnicodeDecodeError):
                continue
            if decoded.startswith(_TWINGATE_ID_KINDS):
                assert "placeholder" in decoded, decoded

    def test_verdicts_per_logger_and_message(self) -> None:
        verdicts = [classify(line) for line in _recording_lines()]
        shapes: Counter[tuple[str, str]] = Counter(
            (v.obj["logger"], v.obj["message"]) for v in verdicts if v.keep and v.obj
        )
        assert shapes == {
            ("system", "Authenticated connection"): 2,
            ("audit", "API request completed"): 1,
            ("session_recording", "session recording"): 3,
            ("session_recording", "session finished"): 2,
        }
        dropped = Counter(v.reason for v in verdicts if not v.keep)
        assert dropped == {DropReason.NOT_ALLOWLISTED: 3}  # `Starting SSH proxy`, 2 SSH audit

    def test_an_ssh_session_is_several_segment_lines_then_a_final_line(self) -> None:
        ssh = [
            json.loads(line)
            for line in _recording_lines()
            if classify(line).keep and b'"logger":"session_recording"' in line and b'"ssh":' in line
        ]
        assert [o["message"] for o in ssh] == [
            "session recording",
            "session recording",
            "session finished",
        ]
        assert [o["asciicast_sequence_num"] for o in ssh] == [1, 2, 3]
        assert len({o["conn_id"] for o in ssh}) == 1
        assert all(isinstance(o["asciicast"], str) and o["asciicast"] for o in ssh)

    async def test_every_kept_line_is_spooled_as_the_original_bytes(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result = await _replay_bootstrap(fake_gateway, tmp_path)
        assert result.spool is not None
        result.webapp_index.update([_app("echo-plain")], GW)
        originals = _recording_lines()
        for line in originals:
            result.process._on_stderr_line(line)
        spooled = [s.encode() for s in result.spool.read_batch(max_lines=100)[0]]
        # No web-app line here, so enrichment touches nothing: SSH and Kubernetes starts included.
        assert spooled == [line for line in originals if classify(line).keep]
        assert result.drops.snapshot() == expected_drops(not_allowlisted=3)


def _app(name: str, gateway_id: str = GW, *, managed: bool = True) -> RemoteWebApp:
    return RemoteWebApp(
        id=f"r-{name}-{gateway_id}",
        name=name,
        gateway_id=gateway_id,
        address=f"{name}.run0001.rig.test",
        upstream_port=8443,
        alias=None,
        upstream_tls="verify_full",
        downstream_tls="tls13",
        downstream_port=443,
        header_rewrite_names=(),
        managed=managed,
    )


async def _replay_bootstrap(
    fake_gateway: Callable[..., Path], tmp_path: Path
) -> BootstrapResult:
    """Bootstrap with the gateway held down, so only the test writes to the stderr callback."""
    result = await bootstrap(make_settings(tmp_path, fake_gateway(stderr_ticks=False), _SEED))
    assert not result.gateway_started
    return result


class TestChildStderrReplay:
    """The fixture through the real stderr callback: filter, enrich, spool."""

    async def test_kept_lines_are_spooled_in_order_with_web_app_tls_data_spliced(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result = await _replay_bootstrap(fake_gateway, tmp_path)
        assert result.spool is not None
        result.webapp_index.update(
            [
                _app("echo-plain"),
                _app("echo-tls"),
                _app("echo-tls", managed=False),  # same address twice -> ambiguous
                _app("verifier-a", managed=False),
                _app("verifier-b", OTHER_GW),  # bound to another gateway -> none
            ],
            GW,
        )
        originals = _raw_lines()
        for line in originals:
            result.process._on_stderr_line(line)

        spooled = [s.encode() for s in result.spool.read_batch(max_lines=1000)[0]]
        expected = [line for line in originals if classify(line).keep]
        assert len(spooled) == len(expected) == KEPT
        assert result.drops.snapshot() == DROPPED

        matches: Counter[tuple[str, str]] = Counter()
        for got, original in zip(spooled, expected, strict=True):
            obj = json.loads(original)
            if obj["message"] != "Authenticated connection":
                assert got == original  # byte-identical
                continue
            splice = got[len(original) - 1 :]
            assert got[: len(original) - 1] == original[:-1]  # gateway bytes untouched
            assert splice.startswith(b',"gwops":{') and splice.endswith(b"}}")
            gwops = json.loads(got)["gwops"]
            assert gwops["schema"] == 1
            assert gwops["gateway_id"] == GW
            matches[(obj["resource_address"].split(".")[0], gwops["match"])] += 1
        assert matches == {
            ("echo-plain", "exact"): AUTH_BY_APP["echo-plain"],
            ("echo-tls", "ambiguous"): AUTH_BY_APP["echo-tls"],
            ("verifier-a", "exact"): AUTH_BY_APP["verifier-a"],
            ("echo-vca", "none"): AUTH_BY_APP["echo-vca"],
            ("echo-wrongfull", "none"): AUTH_BY_APP["echo-wrongfull"],
            ("verifier-b", "none"): AUTH_BY_APP["verifier-b"],
        }

    async def test_the_exact_match_carries_the_declared_fields_and_no_secrets(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result = await _replay_bootstrap(fake_gateway, tmp_path)
        assert result.spool is not None
        result.webapp_index.update([_app("verifier-a", managed=False)], GW)
        line = next(
            raw
            for raw in _raw_lines()
            if b"Authenticated connection" in raw and b"verifier-a." in raw
        )
        result.process._on_stderr_line(line)
        [spooled] = result.spool.read_batch()[0]
        assert json.loads(spooled)["gwops"] == {
            "schema": 1,
            "gateway_id": GW,
            "match": "exact",
            "app": "verifier-a",
            "managed": False,
            "downstream_tls": "tls13",
            "downstream_port": 443,
            "upstream_tls": "verify_full",
            "upstream_port": 8443,
        }

    @pytest.mark.parametrize("index_populated", [True, False])
    async def test_no_dropped_line_content_reaches_the_spool(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, index_populated: bool
    ) -> None:
        result = await _replay_bootstrap(fake_gateway, tmp_path)
        assert result.spool is not None
        if index_populated:
            result.webapp_index.update([_app("echo-plain")], GW)
        for line in _raw_lines():
            result.process._on_stderr_line(line)
        text = "\n".join(result.spool.read_batch(max_lines=1000)[0])
        for marker in ("Starting connect proxy", "proxy error", "Failed to load", "Listener"):
            assert marker not in text
