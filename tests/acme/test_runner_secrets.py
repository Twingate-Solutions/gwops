"""The DNS token never leaves lego's hands and lego's output is redacted.

``TestRedactOutput`` pins the rules of ``redact_output`` and runs everywhere. The sentinel tests
run the real runner against the fake lego (POSIX): ``TOKEN_SENTINEL`` is the content of the token
file, and must appear in no argv, no logged event, no snapshot, no ``state.json`` and no file
under the data directory or the public store. The fake itself fails a run (exit 97) when the token
reaches its argv or environment values, so a clean install also proves that.
"""

import dataclasses
import json
import os
import sys
from pathlib import Path

import pytest
import structlog

from gwops.acme.runner import AcmeConfig, AcmeRunner, redact_output, summarize_output
from gwops.acme.state import INITIAL_BACKOFF, MAX_EXCERPT_CHARS, STATE_FILENAME, AcmeErrorClass
from gwops.certs.store import MaterialStore
from gwops.settings import GwopsSettings
from tests.acme.fake_lego_support import TOKEN_SENTINEL, FakeLego, TokenFile, failure
from tests.acme.runner_support import (
    CERT,
    RunnerFactory,
    entry,
    wait_attempts,
)
from tests.public_chain_support import NOW

# --- redact_output --------------------------------------------------------------------------

PEM_SHORT = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
    "-----END PRIVATE KEY-----"
)
PEM_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
    "ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVl\n"
    "-----END PRIVATE KEY-----"
)


class TestRedactOutput:
    def test_a_pem_block_is_replaced_and_its_surroundings_are_kept(self) -> None:
        result = redact_output(f"before\n{PEM_KEY}\nafter")

        assert result == "before\n[redacted: PEM block]\nafter"

    @pytest.mark.parametrize(
        "label", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "CERTIFICATE", "PUBLIC KEY"]
    )
    def test_any_pem_label_is_replaced(self, label: str) -> None:
        block = f"-----BEGIN {label}-----\nAAAABBBB\n-----END {label}-----"

        assert redact_output(f"x {block} y") == "x [redacted: PEM block] y"

    def test_several_blocks_are_all_replaced(self) -> None:
        result = redact_output(f"{PEM_KEY}\nmiddle\n{PEM_KEY}")

        assert result == "[redacted: PEM block]\nmiddle\n[redacted: PEM block]"

    def test_an_unterminated_block_is_replaced_to_the_end_of_the_text(self) -> None:
        result = redact_output("log line\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\nmore body")

        assert result == "log line\n[redacted: PEM block]"
        assert "MIIEvQ" not in result

    @pytest.mark.parametrize(
        "line",
        [
            "Authorization: Bearer abc.def.ghi",
            "authorization: basic dXNlcjpwYXNz",
            "  Authorization : Bearer abc",
            "request header Authorization: Bearer abc",
            "bearer abc.def",
            "X-Auth-Key: 0123456789abcdef",
            "x-auth-email: ops@example.com",
            "CF-API-KEY: 0123",
            '{"authorization": "0123456789abcdef0123456789"}',
            "authorization=0123456789abcdef0123456789",
            "Authorization: 0123456789abcdef0123456789abcdef",
        ],
        ids=[
            "bearer-header",
            "basic-header",
            "indented-spaced-header",
            "bearer-after-text",
            "bare-bearer",
            "x-auth-key",
            "x-auth-email",
            "cf-api-key",
            "json-key-long-value",
            "assignment-long-value",
            "header-long-token-no-scheme",
        ],
    )
    def test_a_header_shaped_credential_line_is_withheld_whole(self, line: str) -> None:
        text = f"first\n{line}\nlast"

        assert redact_output(text) == "first\n[line withheld: credential pattern]\nlast"

    @pytest.mark.parametrize(
        "line",
        [
            "invalid authorization: acme: error: 403 :: urn:ietf:params:acme:error:unauthorized "
            ":: Incorrect TXT record",
            "obtain certificate: authorization: acme: error: 400 :: "
            "urn:ietf:params:acme:error:malformed",
            "authorization: acme: error: 403",
            "invalid authorization: https://acme-v02.api.letsencrypt.org/acme/authz-v3/1234567890",
            "[*.example.com: invalid challenge: acme: error: 403 :: some problem]",
        ],
        ids=[
            "unauthorized-problem",
            "malformed-problem",
            "line-start-without-a-scheme",
            "authz-url",
            "invalid-challenge",
        ],
    )
    def test_a_plain_invalid_authorization_message_is_kept(self, line: str) -> None:
        """lego's failed-validation text says ``invalid authorization:``; it is not a header."""
        assert redact_output(line) == line

    def test_a_kept_authorization_message_does_not_hide_a_credential_on_the_next_line(
        self,
    ) -> None:
        text = (
            "invalid authorization: acme: error: 403 :: x\n"
            "Authorization: Bearer abc.def.ghi\n"
            "done"
        )

        assert redact_output(text) == (
            "invalid authorization: acme: error: 403 :: x\n"
            "[line withheld: credential pattern]\n"
            "done"
        )

    @pytest.mark.parametrize(
        "line",
        [
            "A" * 48,
            "A" * 64,
            "Ab1+/" * 10,
            "Ab1+/" * 10 + "=",
            "Ab1+/" * 10 + "==",
            f"  {'Q' * 60}  ",
        ],
        ids=["48", "64", "plus-and-slash", "one-pad", "two-pads", "whitespace-around"],
    )
    def test_a_line_that_is_only_base64_of_48_or_more_characters_is_withheld(
        self, line: str
    ) -> None:
        result = redact_output(f"before\n{line}\nafter")

        assert result == "before\n[line withheld: possible PEM body]\nafter"
        assert line.strip() not in result

    @pytest.mark.parametrize("length", [10, 40, 47])
    def test_a_shorter_base64_line_is_not_taken_for_a_pem_body(self, length: int) -> None:
        line = "k" * length

        assert "possible PEM body" not in redact_output(f"x\n{line}\ny")

    def test_a_long_base64_run_inside_a_sentence_is_not_a_whole_line(self) -> None:
        line = f"fingerprint {'R' * 64} recorded"

        assert redact_output(line) == line

    def test_a_pem_body_line_does_not_need_its_begin_marker(self) -> None:
        """A window that cut the BEGIN line off still withholds the body."""
        body = "\n".join(["S" * 64, "T" * 64, "-----END PRIVATE KEY-----"])

        result = redact_output(body)

        assert "SSSS" not in result
        assert "TTTT" not in result
        assert result.count("[line withheld: possible PEM body]") == 2

    def test_withholding_keeps_the_line_count(self) -> None:
        text = "a\nAuthorization: Bearer x\nb\nBearer y z\nc"

        assert redact_output(text).count("\n") == text.count("\n")

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("token=abc123", "token=[redacted]"),
            ("token: abc123", "token: [redacted]"),
            ("TOKEN=Abc123", "TOKEN=[redacted]"),
            ("api_key=k-1", "api_key=[redacted]"),
            ("api-key: k-1", "api-key: [redacted]"),
            ("apikey=k1", "apikey=[redacted]"),
            ("password=hunter2", "password=[redacted]"),
            ("passwd: hunter2", "passwd: [redacted]"),
            ("secret=s3cr3t", "secret=[redacted]"),
            ("client_secret=s3cr3t", "client_secret=[redacted]"),
            ("credential=blob", "credential=[redacted]"),
            ("CF_DNS_API_TOKEN=abc", "CF_DNS_API_TOKEN=[redacted]"),
            ('{"api_token": "abc def"}', '{"api_token": [redacted]}'),
            ("token='abc def'", "token=[redacted]"),
            ('token="a b c" next=1', "token=[redacted] next=1"),
            ("token=abc,next=1", "token=[redacted],next=1"),
            ("token=abc;next=1", "token=[redacted];next=1"),
            ("token=abc}", "token=[redacted]}"),
            ("a token=one and secret=two", "a token=[redacted] and secret=[redacted]"),
        ],
    )
    def test_the_value_of_a_secret_assignment_is_replaced(self, text: str, expected: str) -> None:
        assert redact_output(text) == expected

    @pytest.mark.parametrize("prefix", ["cfut_", "cfat_", "cfk_"])
    def test_cloudflare_token_prefixes_are_replaced(self, prefix: str) -> None:
        token = prefix + "AbCdEfGh0123456789_-xyz"

        result = redact_output(f"bad key {token} rejected")

        assert result == "bad key [redacted] rejected"

    def test_the_sentinel_token_is_replaced_wherever_it_sits(self) -> None:
        for text in (
            TOKEN_SENTINEL,
            f"x {TOKEN_SENTINEL} y",
            f"[{TOKEN_SENTINEL}]",
            f"({TOKEN_SENTINEL}).",
            f'"{TOKEN_SENTINEL}"',
        ):
            assert TOKEN_SENTINEL not in redact_output(text), text

    def test_a_short_cloudflare_prefixed_word_is_left_alone(self) -> None:
        assert redact_output("see cfut_short for details") == "see cfut_short for details"

    def test_a_forty_character_string_is_replaced(self) -> None:
        legacy = "0123456789abcdef0123456789abcdef01234567"
        assert len(legacy) == 40

        assert redact_output(f"key {legacy} rejected") == "key [redacted] rejected"

    @pytest.mark.parametrize("alphabet", ["A", "z", "_", "-", "9"])
    def test_every_character_of_the_token_alphabet_counts(self, alphabet: str) -> None:
        legacy = (alphabet + "b") * 20

        assert redact_output(f"({legacy})") == "([redacted])"

    def test_strings_of_other_lengths_are_left_alone(self) -> None:
        for length in (39, 41, 64):
            text = "k" * length

            assert redact_output(f"value {text} end") == f"value {text} end"

    def test_a_forty_character_string_next_to_punctuation_is_still_replaced(self) -> None:
        legacy = "ab" * 20

        assert redact_output(f"value={legacy}.") == "value=[redacted]."

    @pytest.mark.parametrize(
        "line",
        [
            "Obtaining bundled SAN certificate",
            "[*.example.com] acme: use dns-01 solver",
            "dns01: waiting for record propagation.",
            "Writing file. filepath=/data/acme/lego/certificates/wildcard.crt",
            "acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: "
            "urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued",
            "cloudflare: failed to find zone example.com: "
            "[status code 403] 9109: Invalid access token",
            "retry after 2026-10-21 10:00:00 UTC: see "
            "https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers",
            "Skip renewal: The certificate expires at 2027-01-01 00:00:00 +0000 UTC",
            "email=ops@example.com server=https://acme-staging-v02.api.letsencrypt.org/directory",
            "dns01: time limit exceeded: last error: recursive nameservers: NS 127.0.0.11:53 "
            "did not return the expected TXT record [fqdn: _acme-challenge.example.com., "
            "value: ZmFrZS10eHQtdmFsdWUtMDEyMzQ1Njc4OWFiY2RlZmc]",
        ],
    )
    def test_ordinary_lego_lines_pass_through_unchanged(self, line: str) -> None:
        assert redact_output(line) == line

    def test_the_ca_problem_of_a_failed_validation_is_not_withheld(self) -> None:
        """``invalid authorization: acme: error: ...`` is the CA's problem text, not a header."""
        line = (
            "[*.example.com: invalid authorization: acme: error: 403 :: "
            "urn:ietf:params:acme:error:unauthorized :: Incorrect TXT record]"
        )

        assert redact_output(line) == line

    def test_empty_text_stays_empty(self) -> None:
        assert redact_output("") == ""

    def test_the_replacement_never_contains_what_it_replaced(self) -> None:
        secrets = ["hunter2", "cfut_AbCdEfGh0123456789_-xyz", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"]
        text = f"password={secrets[0]} {secrets[1]}\n-----BEGIN PRIVATE KEY-----\n{secrets[2]}\n"

        result = redact_output(text)

        assert not any(secret in result for secret in secrets)


class TestSummarizeRedacts:
    def test_a_token_in_an_info_line_of_an_unstructured_tail_is_redacted(self) -> None:
        text = "\n".join(
            [
                json.dumps({"level": "INFO", "msg": f"using key {TOKEN_SENTINEL} for zone"}),
                json.dumps({"level": "INFO", "msg": "waiting"}),
            ]
        )

        result = summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0)

        assert TOKEN_SENTINEL not in result
        assert "[redacted]" in result

    def test_a_token_in_the_final_error_is_redacted(self) -> None:
        text = json.dumps(
            {"level": "ERROR", "msg": "Error", "error": f"cloudflare: rejected {TOKEN_SENTINEL}"}
        )

        result = summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0)

        assert result == "cloudflare: rejected [redacted]"

    def test_a_base64_body_line_in_the_tail_is_withheld_not_shown(self) -> None:
        body = "U" * 64
        text = f"starting\n{body}\nstopping"

        result = summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0)

        assert body not in result
        assert result == "starting | [line withheld: possible PEM body] | stopping"

    def test_the_whole_output_is_redacted_before_the_last_three_lines_are_taken(self) -> None:
        """A block whose BEGIN line is outside the window cannot leak its body into it."""
        body = ["V" * 64, "W" * 64, "X" * 64]
        text = "\n".join(
            ["x", "-----BEGIN PRIVATE KEY-----", *body, "-----END PRIVATE KEY-----", "y", "z"]
        )

        result = summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0)

        assert result == "[redacted: PEM block] | y | z"

    def test_a_pem_block_inside_the_tail_window_is_redacted(self) -> None:
        result = summarize_output(
            f"noise\n{PEM_SHORT}", exit_code=1, timed_out=False, timeout_seconds=600.0
        )

        assert "MIIEvQ" not in result

    def test_the_excerpt_stays_bounded_after_redaction(self) -> None:
        text = json.dumps({"level": "ERROR", "error": ("token=abc " * 2000)})

        result = summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0)

        assert len(result) <= MAX_EXCERPT_CHARS


# --- the sentinel through the real runner -------------------------------------------------------

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="requires the POSIX fake lego")

_watching = False
_token_opens: list[str] = []


def _audit(event: str, args: tuple[object, ...]) -> None:
    """Record any in-process ``open`` of a file named like the token file (not lego's child)."""
    if not _watching or event != "open":
        return
    target = args[0]
    if isinstance(target, str | bytes | os.PathLike) and (
        os.path.basename(os.fsdecode(target)) == "cloudflare-token"
    ):
        _token_opens.append(os.fsdecode(target))


sys.addaudithook(_audit)


def tree_files(*roots: Path) -> list[Path]:
    return [p for root in roots for p in root.rglob("*") if p.is_file() and not p.is_symlink()]


def assert_sentinel_absent(
    *,
    logs: list[dict[str, object]],
    runner: AcmeRunner,
    settings: GwopsSettings,
    roots: tuple[Path, ...],
    fake: FakeLego,
) -> None:
    """The token content appears in no channel gwops controls."""
    sentinel = TOKEN_SENTINEL
    assert sentinel not in json.dumps(logs, default=str), "logs"
    assert sentinel not in runner.snapshot().model_dump_json(), "snapshot"
    assert sentinel not in (settings.acme_dir / STATE_FILENAME).read_text(), "state.json"
    for path in tree_files(*roots):
        assert sentinel.encode() not in path.read_bytes(), f"file {path}"
    for call in fake.invocations():
        assert sentinel not in " ".join(call.argv), "argv"
        assert all(sentinel not in value for value in call.env.values()), "environment values"
    for event in logs:
        excerpt = event.get("excerpt")
        if isinstance(excerpt, str):
            assert len(excerpt) <= MAX_EXCERPT_CHARS


@posix_only
class TestSentinel:
    async def test_a_successful_production_run_leaves_the_token_nowhere(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        tmp_path: Path,
    ) -> None:
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(production_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert lego_token.path.read_text().strip() == TOKEN_SENTINEL
        assert recorded.installed_serial is not None, "a violation would have exited 97"
        assert_sentinel_absent(
            logs=logs,
            runner=runner,
            settings=lego_settings,
            roots=(tmp_path / "data",),
            fake=fake_lego,
        )
        (call,) = fake_lego.invocations()
        assert call.env["CF_DNS_API_TOKEN_FILE"] == os.path.realpath(lego_token.path)
        assert "CF_DNS_API_TOKEN" not in call.env_keys
        assert str(lego_token.path) not in " ".join(call.args), "the path is env-only"

    async def test_the_attempt_log_names_the_token_file_path_only(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            await wait_attempts(lego_settings, runner, 1)

        (started,) = [e for e in logs if e["event"] == "acme.runner.attempt_started"]
        assert started["token_file"] == str(lego_token.path)
        assert TOKEN_SENTINEL not in json.dumps(logs, default=str)

    async def test_gwops_never_opens_the_token_file(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        global _watching
        _token_opens.clear()
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(production_config)
        _watching = True
        try:
            runner.start()
            await wait_attempts(lego_settings, runner, 1)
            runner.snapshot()
            runner.request_issue(CERT)
            await wait_attempts(lego_settings, runner, 2)
        finally:
            _watching = False

        assert _token_opens == []
        assert entry(lego_settings).attempts == 2

    async def test_lego_is_given_the_symlink_resolved_token_path(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        acme_root: Path,
        staging_config: AcmeConfig,
        tmp_path: Path,
    ) -> None:
        mounted = acme_root / "..2026_10_20" / "cloudflare-token"
        mounted.parent.mkdir(parents=True)
        mounted.write_text(TOKEN_SENTINEL + "\n")
        link = acme_root / "linked-token"
        link.symlink_to(mounted)
        settings = staging_config.settings.model_copy(update={"token_file": str(link)})
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(dataclasses.replace(staging_config, settings=settings))

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        (call,) = fake_lego.invocations()
        assert recorded.error_code is None
        assert call.env["CF_DNS_API_TOKEN_FILE"] == os.path.realpath(mounted)
        assert call.env["CF_ZONE_API_TOKEN_FILE"] == os.path.realpath(mounted)
        assert call.env["CF_DNS_API_TOKEN_FILE"] != str(link)
        (started,) = [e for e in logs if e["event"] == "acme.runner.attempt_started"]
        assert started["token_file"] == str(link), "the log names the configured path"

    async def test_a_token_link_that_leaves_the_acme_root_is_refused_and_never_opened(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
        tmp_path: Path,
    ) -> None:
        global _watching
        outside = tmp_path / "outside" / "cloudflare-token"
        outside.parent.mkdir()
        outside.write_text("OUTSIDE-SECRET-CONTENT\n")
        lego_token.path.unlink()
        lego_token.path.symlink_to(outside)
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)
        _token_opens.clear()
        _watching = True
        try:
            with structlog.testing.capture_logs() as logs:
                runner.start()
                recorded = await wait_attempts(lego_settings, runner, 1)
                snap = runner.snapshot().get(CERT)
        finally:
            _watching = False

        excerpt = recorded.error_excerpt or ""
        assert recorded.error_code is AcmeErrorClass.CONFIG
        assert "outside" in excerpt
        assert os.path.realpath(outside) in excerpt, "paths are named, contents never"
        assert recorded.consecutive_failures == 1
        assert recorded.next_attempt_at == NOW + INITIAL_BACKOFF
        assert fake_lego.invocations() == [], "lego was never started"
        assert _token_opens == []
        assert snap is not None
        assert snap.readiness_codes == (
            f"public_cert_pending:{CERT}",
            "acme_failed:config",
            "acme_backoff",
        )
        assert "OUTSIDE-SECRET-CONTENT" not in json.dumps(logs, default=str)
        assert "OUTSIDE-SECRET-CONTENT" not in (lego_settings.acme_dir / STATE_FILENAME).read_text()
        assert "OUTSIDE-SECRET-CONTENT" not in runner.snapshot().model_dump_json()

    FORMS = {
        "authorization-header": (
            f"cloudflare: request failed: Authorization: Bearer {TOKEN_SENTINEL}"
        ),
        "bearer-only": f"bearer {TOKEN_SENTINEL}",
        "x-auth-key-header": f"X-Auth-Key: {TOKEN_SENTINEL}",
        "token-assignment": f"cloudflare: bad config token={TOKEN_SENTINEL}",
        "json-key": f'cloudflare: payload {{"api_token": "{TOKEN_SENTINEL}"}}',
        "bare-in-text": f"cloudflare: unexpected body {TOKEN_SENTINEL} while listing zones",
        "bracketed": f"cloudflare: failed [{TOKEN_SENTINEL}]",
    }

    @pytest.mark.parametrize("form", list(FORMS))
    async def test_lego_echoing_the_token_never_reaches_state_logs_or_the_snapshot(
        self,
        form: str,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        tmp_path: Path,
    ) -> None:
        fake_lego.configure(failure("custom", error=self.FORMS[form]))
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        excerpt = recorded.error_excerpt or ""
        assert recorded.error_code is not None
        assert "[redacted]" in excerpt or "withheld" in excerpt
        assert_sentinel_absent(
            logs=logs,
            runner=runner,
            settings=lego_settings,
            roots=(tmp_path / "data",),
            fake=fake_lego,
        )
        snapshot_cert = runner.snapshot().get(CERT)
        assert snapshot_cert is not None
        assert TOKEN_SENTINEL not in (snapshot_cert.error_excerpt or "")

    async def test_host_credentials_in_the_environment_never_reach_lego(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        host = {
            "PATH": os.environ["PATH"],
            "CF_API_KEY": "global-key",
            "CF_API_EMAIL": "ops@example.com",
            "CF_DNS_API_TOKEN": TOKEN_SENTINEL,
            "CLOUDFLARE_DNS_API_TOKEN": TOKEN_SENTINEL,
            "CLOUDFLARE_BASE_URL": "http://evil.example",
            "LEGO_PATH": "/elsewhere",
            "LEGO_DISABLE_CNAME_SUPPORT": "true",
            "TWINGATE_API_KEY": "tg-key",
            "GWOPS_ADMIN_TOKEN": "admin",
            "GWOPS_AUTOMATION_TOKEN": "automation",
            "GWOPS_RECORDING_TOKEN": "gator",
        }
        fake_lego.succeed()
        runner = new_runner(environ=host)
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        (call,) = fake_lego.invocations()
        assert recorded.error_code is None, "the fake exits 97 on a stray credential variable"
        assert call.exit_code == 0
        assert (set(host) - {"PATH"}) & set(call.env_keys) == set()
        assert TOKEN_SENTINEL not in json.dumps(call.env)

    async def test_the_token_file_is_untouched_by_a_run(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
    ) -> None:
        before = (lego_token.path.read_bytes(), lego_token.path.stat().st_mtime_ns)
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()

        await wait_attempts(lego_settings, runner, 1)

        assert (lego_token.path.read_bytes(), lego_token.path.stat().st_mtime_ns) == before

    async def test_a_state_error_snapshot_carries_the_message_but_no_token(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        (lego_settings.acme_dir / STATE_FILENAME).write_text(f"{{ broken {TOKEN_SENTINEL}")
        runner = new_runner()
        runner.configure(staging_config)

        snapshot = runner.snapshot().model_dump_json()

        assert "corrupt" in snapshot
        assert TOKEN_SENTINEL not in snapshot
