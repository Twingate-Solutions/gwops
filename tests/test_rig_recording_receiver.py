"""Offline tests for the rig's recording-receiver option (--gatorcast).

Covers the seed, compose, ingest tap and evidence checks.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
import yaml

from gwops.configmodel.schema import SeedConfig
from gwops.shipper.filter import classify
from gwops.shipper.limits import LINE_MAX_BYTES
from tests.integration.webapp import ingest_tap, run
from tests.integration.webapp.rig import dockerops, gatorcast, guards, seedgen
from tests.integration.webapp.rig.checks import RigContext
from tests.integration.webapp.rig.dockerops import CommandResult
from tests.integration.webapp.rig.results import CheckFailed, CheckFinding
from tests.test_rig_run import (
    COMPOSE_FILE,
    NAMES,
    NETWORK,
    REMOTE_NETWORK_ID,
    FakeAdmin,
    FakeTenant,
    RecordingRunner,
    _docker,
    approved_env,
)

SHIM_DIR = COMPOSE_FILE.parent / "gwops-shim"
EXPECTED = seedgen.expected_webapps(NAMES)


def _seed(**kwargs: Any) -> dict[str, Any]:
    text = seedgen.render_seed(
        NAMES,
        network=NETWORK,
        remote_network_id=REMOTE_NETWORK_ID,
        with_bundle=True,
        allow_insecure_host=True,
        **kwargs,
    )
    document = yaml.safe_load(text)
    assert isinstance(document, dict)
    return document


# --- seed, env files, compose variables ----------------------------------------------------


def test_the_default_seed_is_unchanged_by_the_option() -> None:
    document = _seed()
    assert document["recording"] == {"enabled": False}
    assert "ssh_upstreams" not in document


def test_the_gatorcast_seed_enables_recording_through_the_tap_and_validates() -> None:
    document = _seed(receiver_url=seedgen.RECEIVER_URL, ssh=True)
    recording = document["recording"]
    assert recording["enabled"] is True
    assert recording["receiver_url"] == "http://ingest-tap:8080"
    assert recording["spool_max_bytes"] >= LINE_MAX_BYTES
    ssh = document["ssh_upstreams"]
    assert ssh == [{"name": f"{NAMES.prefix}ssh", "address": f"{NAMES.ssh_host}:2222"}]
    SeedConfig.model_validate(document)


def test_env_lines_carry_the_gatorcast_secrets_only_when_asked() -> None:
    assert seedgen.gwops_env_lines("k", "t") == ["TWINGATE_API_KEY='k'", "GWOPS_ADMIN_TOKEN='t'"]
    lines = seedgen.gwops_env_lines("k", "t", "ing")
    assert lines[-1] == "GWOPS_RECORDING_TOKEN='ing'"
    gatorcast_lines = seedgen.gatorcast_env_lines("ing", "pw")
    assert gatorcast_lines == ["INGEST_TOKEN='ing'", "UI_AUTH_PASSWORD='pw'"]
    with pytest.raises(guards.GuardError):
        seedgen.gatorcast_env_lines("bad'token", "pw")
    assert seedgen.GATORCAST_ENV_FILE in seedgen.ENV_FILES


def test_compose_variables_select_the_shim_and_the_image() -> None:
    off = seedgen.compose_env(NAMES, run_dir=Path("."), network="n", admin_port=1, gwops_image="i")
    on = seedgen.compose_env(
        NAMES, run_dir=Path("."), network="n", admin_port=1, gwops_image="i", gatorcast=True
    )
    assert off["RIG_GATEWAY_SHIM"] == seedgen.SHIM_STDIO
    assert on["RIG_GATEWAY_SHIM"] == seedgen.SHIM_TEE
    assert on["RIG_GATORCAST_IMAGE"] == "ghcr.io/twingate-solutions/gatorcast:latest"
    assert on["RIG_SSH_HOST"] == NAMES.ssh_host


def test_expected_apps_follow_the_seed_modes_and_ports() -> None:
    plain = EXPECTED[NAMES.plain_host]
    assert (plain.downstream_tls, plain.downstream_port) == ("none", 80)
    assert (plain.upstream_tls, plain.upstream_port) == ("none", 80)
    vfull = EXPECTED[NAMES.tls_host]
    assert (vfull.downstream_tls, vfull.downstream_port) == ("tls13", 443)
    assert (vfull.upstream_tls, vfull.upstream_port) == ("verify_full", 443)
    assert EXPECTED[NAMES.verifier_a_host].upstream_port == 8443
    assert EXPECTED[NAMES.insecure_host].upstream_tls == "insecure"


def test_options_parse_and_ssh_implies_gatorcast() -> None:
    assert run.parse_args([]).gatorcast is False
    assert run.parse_args(["--gatorcast"]).gatorcast is True
    args = run.parse_args(["--gatorcast-ssh"])
    assert args.gatorcast is True
    assert args.gatorcast_image == seedgen.DEFAULT_GATORCAST_IMAGE


# --- compose file and shim ----------------------------------------------------------------------


def _services() -> dict[str, dict[str, Any]]:
    return dict(yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))["services"])


def test_the_new_services_are_opt_in_profiles() -> None:
    services = _services()
    assert services["gatorcast"]["profiles"] == ["gatorcast"]
    assert services["ingest-tap"]["profiles"] == ["gatorcast"]
    assert services["ssh-target"]["profiles"] == ["ssh"]
    for name in ("gwops", "connector", "echo-http", "echo-tls", "echo-wrong"):
        assert "profiles" not in services[name], name


def test_the_secrets_reach_gatorcast_by_env_file_only() -> None:
    gatorcast_service = _services()["gatorcast"]
    assert gatorcast_service["env_file"] == ["${RIG_RUN_DIR}/gatorcast.env"]
    assert "INGEST_TOKEN" not in gatorcast_service["environment"]
    assert "UI_AUTH_PASSWORD" not in gatorcast_service["environment"]


def test_the_tap_is_read_only_and_writes_only_its_log_dir() -> None:
    tap = _services()["ingest-tap"]
    assert tap["read_only"] is True
    assert any(v.endswith(":/tap") for v in tap["volumes"])


def test_the_tee_shim_keeps_stderr_and_copies_it_without_recordings() -> None:
    text = (SHIM_DIR / "gateway-tee.sh").read_text(encoding="utf-8")
    assert "mkfifo" in text and "tee /dev/stderr" in text
    assert "grep --line-buffered -v '\"asciicast\"'" in text
    assert "2> \"$fifo\"" in text
    assert "*.next*) exec /usr/local/bin/gateway \"$@\" ;;" in text
    for word in ("verbatim", "recording.enabled", "logfilter"):
        assert word in text
    dockerfile = (SHIM_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "gateway-tee" in dockerfile and dockerfile.rstrip().endswith("USER gwops")


async def test_down_removes_the_gatorcast_env_file_and_covers_every_profile(
    tmp_path: Path,
) -> None:
    (tmp_path / seedgen.GATORCAST_ENV_FILE).write_text("INGEST_TOKEN='x'\n", encoding="utf-8")
    runner = RecordingRunner()
    await _docker(tmp_path, runner).down_stack()
    assert not (tmp_path / seedgen.GATORCAST_ENV_FILE).exists()
    down = next(argv for argv, _env in runner.calls if "down" in argv)
    profiles = [down[i + 1] for i, word in enumerate(down) if word == "--profile"]
    assert profiles == ["stage2", "gatorcast", "ssh"]


# --- the tap --------------------------------------------------


def _line(**fields: Any) -> bytes:
    return json.dumps(fields).encode()


def test_the_tap_allows_exactly_what_the_filter_keeps() -> None:
    keep = [
        _line(logger="system", message="Authenticated connection", resource_type="WEB_APP"),
        _line(logger="audit", message="API request completed"),
        _line(logger="audit", message="API request failed"),
        _line(logger="session_recording", message="session finished", asciicast="x"),
        _line(logger="session_recording", message="session recording", asciicast=""),
    ]
    drop = [
        _line(logger="system", message="Starting SSH proxy"),
        _line(logger="audit", message="SSH connection established"),
        _line(logger="audit", message="session finished", asciicast="x"),
        _line(logger="session_recording", message="session recording", asciicast=None),
        _line(logger="session_recording", message="session finished"),
        _line(logger="system", message="API request completed"),
        _line(logger="gateway", message="Authenticated connection", resource_type="WEB_APP"),
        _line(logger="gateway.audit", message="API request completed"),
        _line(logger="gateway.audit", message="session finished", asciicast="x"),
        b"http: proxy error: dial tcp: refused",
        b"{not json",
        b"\xff\xfe",
    ]
    for raw in [*keep, *drop]:  # the tap's independent allowlist agrees with gwops' filter
        assert ingest_tap.describe_line(raw)["allowed"] == classify(raw).keep, raw
    assert all(classify(x).keep for x in keep)
    assert not any(classify(x).keep for x in drop)


def test_the_tap_records_metadata_never_content() -> None:
    raw = _line(
        logger="session_recording",
        message="session finished",
        asciicast_sequence_num=7,
        asciicast="A" * 1000 + "MARK",
        request={"headers": {"Authorization": ["Bearer secret-value"]}},
    )
    record = ingest_tap.describe_line(raw)
    assert record["asciicast_len"] == 1004 and "asciicast_tail" not in record
    assert record["asciicast_sequence_num"] == 7 and record["markers"] == []
    assert "AAAA" not in json.dumps(record) and "secret-value" not in json.dumps(record)
    with_gwops = ingest_tap.describe_line(
        _line(logger="system", message="Authenticated connection", gwops={"match": "exact"})
    )
    assert with_gwops["gwops"] == {"match": "exact"}


def test_the_tap_reports_the_session_end_markers_it_finds_in_a_recording() -> None:
    text = "x" * 500 + "RIG-SSH-DONE-0123456789ab" + "y" * 500 + "RIG-SSH-DONE-0123456789ab"
    record = ingest_tap.describe_line(
        _line(logger="session_recording", message="session recording", asciicast=text)
    )
    assert record["markers"] == ["RIG-SSH-DONE-0123456789ab"]
    assert "x" * 50 not in json.dumps(record)  # the marker, never the surrounding content


def test_the_tap_forwards_the_bearer_and_logs_one_record_per_line(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            seen["auth"] = self.headers.get("Authorization")
            seen["body"] = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            pass

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    log_path = tmp_path / "ingest.jsonl"
    ingest_tap.Tap.upstream = urlsplit(f"http://127.0.0.1:{upstream.server_port}")
    ingest_tap.Tap.log_path = str(log_path)
    tap = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ingest_tap.Tap)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, tap)]
    for thread in threads:
        thread.start()
    try:
        body = b"\n".join(
            [_line(logger="system", message="Starting SSH proxy"), b"plain text"]
        ) + b"\n"
        request = urllib.request.Request(
            f"http://127.0.0.1:{tap.server_port}/ingest",
            data=body,
            headers={"Authorization": "Bearer tok", "Content-Type": "application/x-ndjson"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            assert response.status == 204
    finally:
        for server in (tap, upstream):
            server.shutdown()
            server.server_close()
    assert seen["auth"] == "Bearer tok" and seen["body"] == body
    records = gatorcast.read_tap(log_path)
    assert [r["rec"] for r in records] == ["post", "line", "line"]
    assert records[0]["status"] == 204 and records[0]["lines"] == 2
    assert [r["allowed"] for r in gatorcast.shipped_lines(records)] == [False, False]
    assert "tok" not in log_path.read_text(encoding="utf-8")


def test_read_tap_ignores_a_torn_last_line_and_a_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "ingest.jsonl"
    assert gatorcast.read_tap(path) == []
    path.write_text('{"rec": "line"}\n{"rec": "li', encoding="utf-8")
    assert gatorcast.read_tap(path) == [{"rec": "line"}]


# --- evidence checks --------------------------------------------------


def _start(host: str, **gwops: Any) -> dict[str, Any]:
    app = EXPECTED[host]
    base = {
        "schema": 1,
        "gateway_id": None,
        "match": "exact",
        "app": app.name,
        "managed": True,
        "downstream_tls": app.downstream_tls,
        "downstream_port": app.downstream_port,
        "upstream_tls": app.upstream_tls,
        "upstream_port": app.upstream_port,
    }
    return {
        "rec": "line",
        "allowed": True,
        "logger": "system",
        "message": "Authenticated connection",
        "resource_type": "WEB_APP",
        "resource_address": host,
        "conn_id": f"c-{host}",
        "gwops": {**base, **gwops},
    }


MUST = (NAMES.plain_host, NAMES.tls_host)


def test_exact_start_lines_for_the_rig_apps_pass() -> None:
    lines = [_start(NAMES.plain_host), _start(NAMES.tls_host), _start(NAMES.verifier_a_host)]
    detail, verified = gatorcast.check_web_gwops(lines, EXPECTED, MUST)
    assert len(verified) == 3 and "3 start lines" in detail


@pytest.mark.parametrize(
    ("change", "text"),
    [
        ({"match": "ambiguous"}, "match"),
        ({"upstream_tls": "insecure"}, "upstream_tls"),
        ({"downstream_port": 8080}, "downstream_port"),
        ({"app": "other"}, "app"),
    ],
)
def test_a_wrong_gwops_field_fails_and_names_the_field(change: dict[str, Any], text: str) -> None:
    lines = [_start(NAMES.plain_host, **change), _start(NAMES.tls_host)]
    with pytest.raises(CheckFailed, match=text):
        gatorcast.check_web_gwops(lines, EXPECTED, MUST)


def test_none_lines_are_counted_and_do_not_fail_when_exact_lines_exist() -> None:
    none = {"schema": 1, "gateway_id": None, "match": "none"}
    early = {**_start(NAMES.plain_host), "gwops": none}
    lines = [early, _start(NAMES.plain_host), _start(NAMES.tls_host)]
    detail, verified = gatorcast.check_web_gwops(lines, EXPECTED, MUST)
    assert len(verified) == 2 and "1 with match none" in detail
    with pytest.raises(CheckFailed, match=r"no exact start line for .*1 none"):
        gatorcast.check_web_gwops([early, _start(NAMES.tls_host)], EXPECTED, MUST)


def test_a_missing_gwops_object_or_a_missing_required_app_fails() -> None:
    bare = {k: v for k, v in _start(NAMES.plain_host).items() if k != "gwops"}
    with pytest.raises(CheckFailed, match="no gwops object"):
        gatorcast.check_web_gwops([bare, _start(NAMES.tls_host)], EXPECTED, MUST)
    with pytest.raises(CheckFailed, match="no exact start line"):
        gatorcast.check_web_gwops([_start(NAMES.plain_host)], EXPECTED, MUST)


def test_the_alias_address_is_not_judged_against_the_apps() -> None:
    alias = {**_start(NAMES.tls_host), "resource_address": NAMES.alias_host}
    detail, verified = gatorcast.check_web_gwops(
        [_start(NAMES.plain_host), _start(NAMES.tls_host), alias], EXPECTED, MUST
    )
    assert len(verified) == 2


def test_allowlist_check_passes_clean_lines_and_names_every_violation() -> None:
    clean = [{"rec": "line", "allowed": True}]
    assert "all allowlisted" in gatorcast.check_allowlist(clean)
    dirty = clean + [
        {"rec": "line", "allowed": False, "kind": "text", "excerpt": "http: proxy error"},
        {"rec": "line", "allowed": False, "kind": "json", "excerpt": "gateway: Starting"},
    ]
    with pytest.raises(CheckFailed, match=r"2 of 3.*proxy error"):
        gatorcast.check_allowlist(dirty)
    with pytest.raises(CheckFailed, match="no shipped line"):
        gatorcast.check_allowlist([])


def _shipper(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "mode": "spool",
        "shipping": True,
        "pending_lines": 0,
        "dropped_lines": {"not_json": 3, "not_allowlisted": 40, "too_long": 0, "spool_failed": 0},
        "enrich_failed": 0,
        "enrichment": {"active": True, "last_update_at": "t", "apps": 7},
    }
    return {**base, **changes}


def test_counters_are_captured_as_metrics_and_judged() -> None:
    detail, metrics = gatorcast.check_counters(_shipper())
    assert json.loads(metrics["shipper.dropped_lines"])["not_allowlisted"] == 40
    assert metrics["shipper.enrich_failed"] == "0" and "active" in detail
    bad = [
        _shipper(enrich_failed=2),
        _shipper(shipping=False),
        _shipper(enrichment={"active": False}),
        _shipper(dropped_lines={"not_json": 0, "not_allowlisted": 0, "too_long": 0}),
        _shipper(dropped_lines={"not_json": 1, "not_allowlisted": 1, "spool_failed": 1}),
    ]
    for shipper in bad:
        with pytest.raises(CheckFailed):
            gatorcast.check_counters(shipper)


MIB = 1024 * 1024
KIB = 1024


def _segment(seq: int, size: int = 260 * KIB, **changes: Any) -> dict[str, Any]:
    """One shipped `session_recording` line as the tap describes it."""
    record = {
        "rec": "line",
        "logger": "session_recording",
        "message": "session recording",
        "bytes": size,
        "asciicast_len": size - 400,
        "asciicast_sequence_num": seq,
        "sha256": f"sha-{seq}",
        "markers": [],
        "allowed": True,
        "status": 204,
        "conn_id": "c1",
    }
    return {**record, **changes}


def _session(segments: int = 13, *, marker_in: int | None = None) -> list[dict[str, Any]]:
    """`segments` segment lines then the final line; the marker is in the final line by default."""
    final = segments + 1
    at = final if marker_in is None else marker_in
    lines = [_segment(seq, markers=["MARK"] if seq == at else []) for seq in range(1, final)]
    marked = ["MARK"] if at == final else []
    lines.append(_segment(final, 40 * KIB, message="session finished", markers=marked))
    return lines


def _with(seq: int, **changes: Any) -> list[dict[str, Any]]:
    """A whole session with the line of sequence number `seq` changed."""
    return [{**r, **changes} if r["asciicast_sequence_num"] == seq else r for r in _session()]


def test_an_ssh_session_is_segments_then_a_final_line_in_sequence_with_the_marker() -> None:
    summary = gatorcast.check_ssh_recording(_session(), "MARK")
    assert summary["conn_id"] == "c1"
    assert summary["segments"] == 13 and summary["lines"] == 14
    assert summary["total_bytes"] > 3 * MIB and summary["largest"] == 260 * KIB


def test_the_marker_may_sit_in_the_last_segment_when_the_final_line_holds_only_the_tail() -> None:
    assert gatorcast.check_ssh_recording(_session(marker_in=13), "MARK")["segments"] == 13


def test_a_redelivered_line_is_not_a_second_segment() -> None:
    lines = _session()
    summary = gatorcast.check_ssh_recording([*lines, lines[3], lines[-1]], "MARK")
    assert summary["lines"] == 14 and summary["total_bytes"] == sum(r["bytes"] for r in lines)


def test_the_same_sequence_with_different_content_is_not_a_redelivery() -> None:
    """Two shell channels on one connection each number their flushes from 1."""
    clash = _segment(4, sha256="sha-from-another-channel")
    with pytest.raises(CheckFailed, match=r"sequence 4 .*different content"):
        gatorcast.check_ssh_recording([*_session(), clash], "MARK")


def test_a_line_just_under_the_ceiling_passes_and_one_at_it_fails() -> None:
    cap = gatorcast.SSH_MAX_SEGMENT
    assert cap == 1 * MIB  # four times the rendered 256,000-byte cap, rounded to a MiB
    assert gatorcast.check_ssh_recording(
        [r if r["asciicast_sequence_num"] != 2 else {**r, "bytes": cap - 1} for r in _session()],
        "MARK",
    )["largest"] == cap - 1
    with pytest.raises(CheckFailed, match="segment cap"):
        gatorcast.check_ssh_recording(_with(2, bytes=cap), "MARK")


def test_other_sessions_lines_are_ignored() -> None:
    other = [_segment(1, conn_id="c2"), _segment(2, conn_id="c2", message="session finished")]
    assert gatorcast.check_ssh_recording([*other, *_session()], "MARK")["conn_id"] == "c1"


@pytest.mark.parametrize(
    ("lines", "text"),
    [
        ([], "no recording line"),
        (_session(13, marker_in=13)[:-1], "no final"),  # the `session finished` line never arrived
        ([_segment(1, 3 * MIB, message="session finished", markers=["MARK"])], "not segmented"),
        (_session(13, marker_in=0), "marker"),
        (_session()[:3] + _session()[4:], "sequence"),  # a segment is missing
        ([*_session()[:-1], {**_session()[-1], "asciicast_sequence_num": 20}], "sequence"),
        (_with(4, status=502), "502"),
        (_with(2, allowed=False), "allowlisted"),
        (_with(2, bytes=3 * MIB), "segment cap"),
        ([{**r, "asciicast_sequence_num": None} for r in _session()], "sequence"),
        (_session(2), "2 MiB"),  # too little recorded to be the 3 MiB payload
    ],
)
def test_a_broken_ssh_recording_fails_and_says_why(lines: list[dict[str, Any]], text: str) -> None:
    with pytest.raises(CheckFailed, match=text):
        gatorcast.check_ssh_recording(lines, "MARK")


def test_the_ssh_assertion_title_describes_segments_not_one_line() -> None:
    assert "segment" in gatorcast.SSH_ASSERTION[1] and "final" in gatorcast.SSH_ASSERTION[1]
    assert "whole" not in gatorcast.SSH_ASSERTION[1]


def test_the_ssh_script_feeds_an_interactive_pty_shell_never_an_exec_request() -> None:
    script = gatorcast.ssh_script("ssh-target.x.rig.test", "RIG-SSH-DONE-abc123")
    assert "ssh -tt " in script and "gateway@ssh-target.x.rig.test" in script
    assert script.index("printf '%s") < script.index("| ssh")  # payload goes in on stdin
    assert "gateway@ssh-target.x.rig.test '" not in script  # no remote command argument
    assert "base64" in script and "; exit'" in script and "tail -c 300" in script
    assert "RIG-SSH-DONE-abc123" not in script  # the typed line never holds the marker whole
    assert "DONE abc123" in script
    assert "UserKnownHostsFile=/dev/null" in script


def _evidence(tmp_path: Path, **kwargs: Any) -> gatorcast.GatorcastEvidence:
    ctx = RigContext(NAMES, None, None, None, None, None, None, None)  # type: ignore[arg-type]
    return gatorcast.GatorcastEvidence(ctx, tmp_path / "ingest.jsonl", **kwargs)


async def test_the_ssh_assertion_is_a_finding_when_the_infrastructure_is_missing(
    tmp_path: Path,
) -> None:
    evidence = _evidence(tmp_path, ssh_ready=lambda: "image build failed")
    with pytest.raises(CheckFinding, match="image build failed"):
        await evidence.recording_ssh()


async def test_the_no_service_lines_assertion_reads_the_tap_log(tmp_path: Path) -> None:
    log = tmp_path / "ingest.jsonl"
    rows = [
        {"rec": "post", "status": 204, "lines": 1},
        {"rec": "line", "allowed": True},
    ]
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    detail = await _evidence(tmp_path, ssh_ready=lambda: None).recording_no_service_lines()
    assert "1 POSTs, 0 not accepted" in detail


def test_gatorcast_runs_register_their_assertions_and_default_runs_do_not() -> None:
    def numbers(*, gatorcast: bool = False, ssh: bool = False) -> list[str]:
        rig = run.Rig.__new__(run.Rig)
        rig.gatorcast, rig.ssh = gatorcast or ssh, ssh
        return [n for n, _title in rig.expected_assertions()]

    base = numbers()
    assert "12" not in base and "16" not in base
    assert numbers(gatorcast=True)[-4:] == ["12", "13", "14", "15"]
    assert numbers(ssh=True)[-1] == "16"


async def test_stage_one_with_gatorcast_writes_the_secret_files_and_starts_the_sink(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    runner = RecordingRunner(events, {"inspect": CommandResult(0, "healthy", "")})
    env = approved_env()
    args = SimpleNamespace(image="gwops-gateway:dev", apply_timeout=None, gatorcast=True)
    rig = run.Rig(env, FakeTenant(tmp_path, events), NAMES, args)  # type: ignore[arg-type]
    rig.docker = _docker(tmp_path, runner)
    rig.admin = FakeAdmin(events, {"state_error": "stop here"})  # type: ignore[assignment]
    with pytest.raises(run.RigError, match="stop here"):
        await rig.bring_up()
    up = next(argv for argv, _env in runner.calls if "up" in argv)
    assert up[up.index("--profile") + 1] == "gatorcast"
    assert {"gatorcast", "ingest-tap"} <= set(up)
    gwops_env = (tmp_path / seedgen.GWOPS_ENV_FILE).read_text(encoding="utf-8")
    gatorcast_env = (tmp_path / seedgen.GATORCAST_ENV_FILE).read_text(encoding="utf-8")
    assert f"GWOPS_RECORDING_TOKEN='{rig.ingest_token}'" in gwops_env
    assert f"INGEST_TOKEN='{rig.ingest_token}'" in gatorcast_env
    assert f"UI_AUTH_PASSWORD='{rig.ui_password}'" in gatorcast_env
    assert rig.ingest_token != rig.ui_password
    for secret in (rig.ingest_token, rig.ui_password):
        assert rig.log.redactor.redact(f"x {secret} y") == "x [redacted] y"
    assert "receiver_url: http://ingest-tap:8080" in (tmp_path / "seed" / "seed.yaml").read_text(
        encoding="utf-8"
    )
    assert (tmp_path / seedgen.TAP_DIR).is_dir()
    await rig.admin.aclose()


async def test_a_default_stage_one_starts_no_gatorcast_service(tmp_path: Path) -> None:
    events: list[str] = []
    runner = RecordingRunner(events)
    env = approved_env()
    args = SimpleNamespace(image="gwops-gateway:dev", apply_timeout=None)
    rig = run.Rig(env, FakeTenant(tmp_path, events), NAMES, args)  # type: ignore[arg-type]
    rig.docker = _docker(tmp_path, runner)
    rig.admin = FakeAdmin(events, {"state_error": "stop here"})  # type: ignore[assignment]
    with pytest.raises(run.RigError, match="stop here"):
        await rig.bring_up()
    up = next(argv for argv, _env in runner.calls if "up" in argv)
    assert "--profile" not in up and "gatorcast" not in up
    assert not (tmp_path / seedgen.GATORCAST_ENV_FILE).exists()
    gwops_env = (tmp_path / seedgen.GWOPS_ENV_FILE).read_text(encoding="utf-8")
    assert "GWOPS_RECORDING_TOKEN" not in gwops_env
    await rig.admin.aclose()


# --- --gatorcast-build ---------------------------------------------------


def _tree(root: Path) -> Path:
    for rel, text in {
        "Dockerfile": "FROM scratch\n",
        "pyproject.toml": "x",
        "src/gatorcast/__init__.py": "",
        "src/gatorcast/__pycache__/x.pyc": "x",
        ".git/config": "secret",
        ".venv/lib/x": "x",
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }


async def test_the_local_build_uses_a_filtered_copy_and_leaves_the_source_untouched(
    tmp_path: Path,
) -> None:
    source = _tree(tmp_path / "gatorcast-src")
    before = _snapshot(source)
    seen: dict[str, Any] = {}

    async def runner(argv: Any, env: Any, timeout: float) -> CommandResult:
        context = Path(argv[-1])
        seen["argv"] = list(argv)
        files = (p for p in context.rglob("*") if p.is_file())
        seen["files"] = sorted(p.relative_to(context).as_posix() for p in files)
        seen["env"] = dict(env)
        return CommandResult(0, "sha256:abc\n", "")

    tag = await dockerops.build_local_gatorcast(
        source, runner=runner, environ={"PATH": "/bin", "IT_TWINGATE_API_KEY": "k"}
    )
    assert tag == "gwops-it-gatorcast:local"
    assert seen["argv"][:5] == ["docker", "build", "-q", "-t", "gwops-it-gatorcast:local"]
    assert seen["files"] == ["Dockerfile", "pyproject.toml", "src/gatorcast/__init__.py"]
    assert not any(k.startswith("IT_") for k in seen["env"])
    assert Path(seen["argv"][-1]) != source
    assert _snapshot(source) == before


async def test_the_local_build_refuses_a_tree_without_a_dockerfile_and_reports_a_failed_build(
    tmp_path: Path,
) -> None:
    async def failing(argv: Any, env: Any, timeout: float) -> CommandResult:
        return CommandResult(1, "", "no space left")

    with pytest.raises(guards.GuardError, match="no Dockerfile"):
        await dockerops.build_local_gatorcast(tmp_path, runner=failing)
    with pytest.raises(guards.GuardError, match="no space left"):
        await dockerops.build_local_gatorcast(_tree(tmp_path / "src2"), runner=failing)


def test_gatorcast_build_implies_gatorcast_and_defaults_stay() -> None:
    args = run.parse_args(["--gatorcast-build", "somewhere"])
    assert args.gatorcast is True and args.gatorcast_build == Path("somewhere")
    assert run.parse_args(["--gatorcast"]).gatorcast_build is None
    assert run.parse_args([]).gatorcast_image == "ghcr.io/twingate-solutions/gatorcast:latest"
