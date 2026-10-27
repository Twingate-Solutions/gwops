"""Tests for gwops.logging: structlog JSON output and secret redaction."""

import json

import structlog

from gwops.logging import configure_logging, redact_secrets


class TestRedactSecrets:
    def test_redacts_matching_keys(self) -> None:
        event = {
            "event": "auth",
            "api_key": "sk-12345",
            "token": "abc",
            "recording_token": "def",
            "password": "hunter2",
            "client_secret": "shh",
        }
        out = redact_secrets(None, "info", event)
        assert out["api_key"] == "[REDACTED]"
        assert out["token"] == "[REDACTED]"
        assert out["recording_token"] == "[REDACTED]"
        assert out["password"] == "[REDACTED]"
        assert out["client_secret"] == "[REDACTED]"

    def test_keeps_non_secret_keys(self) -> None:
        event = {"event": "sync", "status": 200, "url": "https://x.example/api"}
        out = redact_secrets(None, "info", event)
        assert out == {"event": "sync", "status": 200, "url": "https://x.example/api"}

    def test_matches_case_insensitively(self) -> None:
        out = redact_secrets(None, "info", {"event": "e", "API_KEY": "x", "Token": "y"})
        assert out["API_KEY"] == "[REDACTED]"
        assert out["Token"] == "[REDACTED]"

    def test_recurses_into_nested_dicts(self) -> None:
        event = {"event": "e", "request": {"headers": {"x-api-key": "x"}, "path": "/p"}}
        out = redact_secrets(None, "info", event)
        assert out["request"]["headers"]["x-api-key"] == "[REDACTED]"
        assert out["request"]["path"] == "/p"

    def test_never_redacts_the_event_key_itself(self) -> None:
        out = redact_secrets(None, "info", {"event": "rotated signing key"})
        assert out["event"] == "rotated signing key"

    def test_secret_key_taints_entire_nested_dict_subtree(self) -> None:
        # A dict value under a secret-named key must be redacted wholesale, not
        # descended into (which would forget the parent secret key).
        out = redact_secrets(None, "info", {"event": "e", "api_key": {"value": "sk"}})
        assert out["api_key"] == "[REDACTED]"

    def test_authorization_header_dict_is_redacted(self) -> None:
        event = {"event": "e", "headers": {"authorization": "Bearer x", "accept": "*/*"}}
        out = redact_secrets(None, "info", event)
        assert out["headers"]["authorization"] == "[REDACTED]"
        assert out["headers"]["accept"] == "*/*"

    def test_secret_key_taints_list_of_dicts(self) -> None:
        event = {"event": "e", "credentials": [{"user": "a", "pw": "b"}, {"user": "c"}]}
        out = redact_secrets(None, "info", event)
        assert out["credentials"] == "[REDACTED]"

    def test_list_of_dicts_under_non_secret_key_still_scrubs_inner_secrets(self) -> None:
        event = {"event": "e", "items": [{"name": "a", "token": "t1"}, {"name": "b"}]}
        out = redact_secrets(None, "info", event)
        assert out["items"][0]["name"] == "a"
        assert out["items"][0]["token"] == "[REDACTED]"
        assert out["items"][1] == {"name": "b"}

    def test_broadened_denylist_matches_new_secret_names(self) -> None:
        event = {
            "event": "e",
            "authorization": "Bearer x",
            "auth": "y",
            "credential": "z",
            "bearer": "b",
            "passphrase": "p",
            "cookie": "c",
            "signature": "s",
        }
        out = redact_secrets(None, "info", event)
        for k in event:
            if k == "event":
                continue
            assert out[k] == "[REDACTED]", k


class TestConfigureLogging:
    def test_emits_json_lines_to_stdout_with_redaction(self, capsys) -> None:  # type: ignore[no-untyped-def]
        configure_logging()
        log = structlog.get_logger("gwops.test")
        log.info("tg_api_error", status=500, api_key="sk-999")
        line = capsys.readouterr().out.strip()
        record = json.loads(line)
        assert record["event"] == "tg_api_error"
        assert record["status"] == 500
        assert record["api_key"] == "[REDACTED]"
        assert record["level"] == "info"
        assert "timestamp" in record
        assert "sk-999" not in line
