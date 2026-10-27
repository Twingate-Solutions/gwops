"""Filter tests: the allowlist keeps audit and session lines and drops everything else."""

import json
from typing import Any

import pytest

from gwops.shipper.filter import DropReason, Verdict, classify, system_fields

AUTH = {"logger": "system", "message": "Authenticated connection"}


def enc(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


KEPT = [
    pytest.param(
        {
            "logger": "session_recording",
            "message": "session recording",
            "asciicast": '{"version":2}',
            "asciicast_sequence_num": 1,
        },
        id="recording-segment",
    ),
    pytest.param(
        {
            "logger": "session_recording",
            "message": "session finished",
            "asciicast": '{"version":2}',
            "asciicast_sequence_num": 2,
        },
        id="recording-final",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "session finished", "asciicast": ""},
        id="recording-final-empty-string",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "recording", "asciicast": '{"version":2}'},
        id="recording-any-message",
    ),
    pytest.param(
        {"logger": "audit", "message": "API request completed", "status": 200},
        id="api-completed",
    ),
    pytest.param(
        {"logger": "audit", "message": "API request failed", "error": "boom"},
        id="api-failed",
    ),
    pytest.param({**AUTH, "resource_type": "WEB_APP"}, id="authenticated-connection"),
    pytest.param({**AUTH, "resource_type": "SSH"}, id="authenticated-connection-ssh"),
]

DROPPED = [
    pytest.param({"logger": "audit", "message": "Channel opened"}, id="ssh-audit-no-asciicast"),
    pytest.param(
        {"logger": "audit", "message": "SSH connection established"}, id="ssh-audit-conn"
    ),
    pytest.param({"logger": "audit"}, id="audit-no-message"),
    pytest.param({"logger": "audit", "message": ["API request failed"]}, id="list-message"),
    pytest.param(
        {"logger": "audit", "message": "API request completed", "asciicast": 1},
        id="asciicast-int-with-api-message",
    ),
    pytest.param(
        {"logger": "audit", "message": "session finished", "asciicast": "x"},
        id="audit-carrying-asciicast",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "session recording"}, id="recording-no-asciicast"
    ),
    pytest.param(
        {"logger": "session_recording", "message": "API request completed"},
        id="recording-logger-api-message",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "session recording", "asciicast": None},
        id="asciicast-null",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "session recording", "asciicast": 7},
        id="asciicast-int",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "session recording", "asciicast": {"a": 1}},
        id="asciicast-object",
    ),
    pytest.param(
        {"logger": "session_recording", "message": "Authenticated connection"},
        id="recording-logger-auth-msg",
    ),
    pytest.param({"logger": "system", "message": "Starting connect proxy"}, id="service-line"),
    pytest.param({"logger": "system", "message": "API request completed"}, id="service-api-msg"),
    pytest.param(
        {"logger": "system", "message": "session finished", "asciicast": "x"},
        id="service-logger-asciicast",
    ),
    pytest.param(
        {"logger": "system", "message": "Failed to authenticate connection"},
        id="service-auth-failure",
    ),
    pytest.param({"logger": "audit", "message": "Authenticated connection"}, id="audit-auth-msg"),
    pytest.param({"logger": "gateway", "message": "Authenticated connection"}, id="old-service"),
    pytest.param({"logger": "gateway", "message": "Starting connect proxy"}, id="old-service-line"),
    pytest.param(
        {"logger": "gateway.audit", "message": "API request completed"}, id="old-audit-api"
    ),
    pytest.param(
        {"logger": "gateway.audit", "message": "session finished", "asciicast": "x"},
        id="old-audit-recording",
    ),
    pytest.param({"logger": "other", "message": "Authenticated connection"}, id="other-logger"),
    pytest.param({"message": "Authenticated connection"}, id="no-logger"),
    pytest.param({"logger": ["system"], "message": "Authenticated connection"}, id="list-logger"),
    pytest.param({}, id="empty-object"),
]

NOT_JSON = [
    pytest.param(b"http: proxy error: dial tcp 10.0.0.1:80: connection refused", id="http"),
    pytest.param(b'Error: unknown command "x" for "gateway"', id="cobra"),
    pytest.param(b"Error: use of closed network connection", id="sigterm-error"),
    pytest.param(b"Usage:", id="cobra-usage"),
    pytest.param(b"  gateway start [flags]", id="cobra-usage-body"),
    pytest.param(b'E1008 12:00:00.000000       1 reflector.go:1] "Failed"', id="klog"),
    pytest.param(b"panic: runtime error: index out of range", id="panic"),
    pytest.param(b"", id="empty"),
    pytest.param(b" " + enc(AUTH), id="leading-space"),
    pytest.param(b"\t" + enc(AUTH), id="leading-tab"),
    pytest.param(b"\n", id="newline-only"),
    pytest.param(b"[]", id="array"),
    pytest.param(enc([AUTH]), id="array-of-objects"),
    pytest.param(b'"{"', id="string"),
    pytest.param(b"{", id="truncated"),
    pytest.param(b'{"logger":"system"', id="unterminated"),
    pytest.param(enc(AUTH) + b" trailing", id="trailing-garbage"),
    pytest.param(b'{"a":"\xff"}', id="invalid-utf8"),
    pytest.param(b'{"a":"\xc3"}', id="truncated-utf8"),
    pytest.param(b"\xef\xbb\xbf{}", id="bom"),
    pytest.param(b"{" * 100_000, id="deep-open"),
    pytest.param(b'{"a":' * 100_000 + b"1" + b"}" * 100_000, id="deep-nesting"),
    pytest.param(b'{"a":' + b"9" * 5000 + b"}", id="huge-int"),
]


@pytest.mark.parametrize("obj", KEPT)
def test_kept_shapes(obj: dict[str, Any]) -> None:
    assert classify(enc(obj)) == Verdict(keep=True, reason=None, obj=obj)


@pytest.mark.parametrize("obj", DROPPED)
def test_not_allowlisted(obj: dict[str, Any]) -> None:
    assert classify(enc(obj)) == Verdict(keep=False, reason=DropReason.NOT_ALLOWLISTED, obj=None)


@pytest.mark.parametrize("line", NOT_JSON)
def test_not_json(line: bytes) -> None:
    assert classify(line) == Verdict(keep=False, reason=DropReason.NOT_JSON, obj=None)


def test_invalid_utf8_drops_even_with_allowlisted_shape() -> None:
    line = b'{"logger":"system","message":"Authenticated connection","x":"\xff"}'
    assert classify(line).reason is DropReason.NOT_JSON


def test_kept_obj_is_the_parsed_dict() -> None:
    line = b'{"logger":"system","message":"Authenticated connection","n":{"a":[1,2]}}'
    verdict = classify(line)
    assert verdict.keep
    assert verdict.obj == {**AUTH, "n": {"a": [1, 2]}}


def test_non_ascii_utf8_is_kept() -> None:
    obj = {**AUTH, "user": "zoë"}
    assert classify(json.dumps(obj, ensure_ascii=False).encode()).obj == obj


def test_a_forged_authenticated_line_inside_a_system_error_message_stays_one_dropped_line() -> None:
    """A proxy error quoting a hostile certificate name is one JSON line: the newline is escaped."""
    forged = enc({**AUTH, "resource_type": "WEB_APP"}).decode()
    message = (
        "http: proxy error: tls: failed to verify certificate: x509: certificate is valid for "
        f"a.test\n{forged}, not b.test"
    )
    line = enc({"levelname": "error", "logger": "system", "message": message, "version": "2.0.0"})
    assert b"\n" not in line
    assert b'a.test\\n{\\"logger\\"' in line  # backslash-n and escaped quotes, inside the string
    assert classify(line) == Verdict(keep=False, reason=DropReason.NOT_ALLOWLISTED, obj=None)
    # The same text as a real second line would be kept: only the escaping protects it.
    assert classify(forged.encode()).keep


def test_drop_reason_keys() -> None:
    assert {r: 0 for r in DropReason} == {
        "not_json": 0,
        "not_allowlisted": 0,
        "too_long": 0,
        "spool_failed": 0,
    }


def test_verdict_is_frozen() -> None:
    with pytest.raises(AttributeError):
        classify(b"x").keep = True  # type: ignore[misc]


def test_a_drop_without_a_reason_cannot_be_built() -> None:
    with pytest.raises(ValueError, match="needs a reason"):
        Verdict(keep=False)
    with pytest.raises(ValueError, match="needs a reason"):
        Verdict(keep=False, reason=None, obj={"a": 1})


def test_system_fields_returns_a_system_line_whole() -> None:
    obj = {"logger": "system", "message": "Starting HTTP proxy", "levelname": "info", "n": 1}
    assert system_fields(enc(obj)) == obj


@pytest.mark.parametrize(
    "line",
    [
        enc({"logger": "audit", "message": "API request completed"}),
        enc({"logger": "session_recording", "asciicast": "x"}),
        enc({"logger": "system", "message": "x", "asciicast": "x"}),
        enc({"logger": "systemx"}),
        enc({"message": "no logger"}),
        enc(["system"]),
        b"plain",
        b'{"logger":"system"',
        b'{"logger":"system","m":"\xff"}',
        b"",
    ],
)
def test_system_fields_is_none_for_everything_else(line: bytes) -> None:
    assert system_fields(line) is None
