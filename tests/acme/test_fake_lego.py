"""Self-test of the fake lego (``tests/fakes/fake_lego.py``) against ``build_argv`` output.

Not a test of gwops: it pins what the runner tests rely on, namely that the fake accepts the
real argv (``--flag=value`` form included), writes lego v5's layout under the directory's host
subdirectory, fails with lego's recorded failure texts, hangs or dies from a signal on request, and
rejects a token in argv, a stray credential variable (``GODEBUG`` included) or a ``--path`` that
is not the directory's own subdirectory.
"""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from gwops.acme.lego import build_argv
from gwops.certs.public import PublicMaterialError, validate_public_material
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings
from gwops.settings import GwopsSettings
from tests.acme.fake_lego_support import (
    ACCOUNT_KEY_MARKER,
    CONTROL_EXIT,
    TOKEN_SENTINEL,
    VIOLATION_EXIT,
    FakeLego,
    TokenFile,
    failure,
    hang,
    output,
    posix_only,
    rate_limit_hang,
    run_lego,
    signal_death,
    success,
)
from tests.public_chain_support import NOW, ZONES, other_hierarchy, rsa_hierarchy

pytestmark = posix_only

HOST_DIR = "acme-staging-v02.api.letsencrypt.org"


class Harness:
    """Builds the real argv and runs the fake with exactly the environment build_argv returns."""

    def __init__(
        self,
        fake: FakeLego,
        settings: GwopsSettings,
        acme: AcmeSettings,
        cert: AcmePublicCertificate,
    ) -> None:
        self.fake, self.settings, self.acme, self.cert = fake, settings, acme, cert

    def argv_env(self, *, force: bool = False) -> tuple[list[str], dict[str, str]]:
        return build_argv(
            self.acme,
            self.cert,
            gwops=self.settings,
            force=force,
            environ={"PATH": os.environ["PATH"]},
        )

    def run(self, *, force: bool = False) -> subprocess.CompletedProcess[str]:
        argv, env = self.argv_env(force=force)
        return run_lego(argv, env)

    @property
    def storage(self) -> Path:
        """lego's ``--path`` for the configured directory: the host subdirectory."""
        return self.settings.lego_storage_dir(self.acme.directory_url)

    @property
    def certs(self) -> Path:
        return self.storage / "certificates"


@pytest.fixture
def harness(
    fake_lego: FakeLego,
    lego_settings: GwopsSettings,
    acme_settings: AcmeSettings,
    acme_cert: AcmePublicCertificate,
) -> Harness:
    return Harness(fake_lego, lego_settings, acme_settings, acme_cert)


def error_record(stdout: str) -> dict[str, str]:
    record = json.loads(stdout.strip().splitlines()[-1])
    assert record["level"] == "ERROR"
    return record


class TestSuccess:
    def test_real_argv_writes_lego_v5_layout_and_exits_zero(self, harness: Harness) -> None:
        harness.fake.succeed()

        result = harness.run()

        assert result.returncode == 0, result.stdout
        assert result.stderr == ""
        for suffix in ("crt", "issuer.crt", "key", "json"):
            assert (harness.certs / f"wildcard.{suffix}").is_file()
        account = harness.storage / "accounts" / HOST_DIR / "ops@example.com"
        assert (account / "account.json").is_file()
        assert ACCOUNT_KEY_MARKER in (account / "ops@example.com.key").read_text()

    def test_output_is_json_records_on_stdout(self, harness: Harness) -> None:
        harness.fake.succeed()

        result = harness.run()

        records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        assert records
        assert all({"time", "level", "msg"} <= record.keys() for record in records)
        assert any(record["msg"] == "Writing file." for record in records)

    def test_files_are_private(self, harness: Harness) -> None:
        harness.fake.succeed()
        harness.run()

        for path in harness.certs.iterdir():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path

    def test_default_hierarchy_output_passes_the_public_validator(self, harness: Harness) -> None:
        harness.fake.succeed()
        harness.run()

        material = validate_public_material(
            harness.cert,
            (harness.certs / "wildcard.crt").read_bytes(),
            (harness.certs / "wildcard.key").read_bytes(),
            zones=ZONES,
            root=rsa_hierarchy().root,
            now=NOW,
        )
        assert material.chain[0].subject is not None

    def test_other_hierarchy_output_fails_the_public_validator(self, harness: Harness) -> None:
        harness.fake.succeed(other_hierarchy().issue((f"*.{ZONES[0]}",)))
        harness.run()

        with pytest.raises(PublicMaterialError):
            validate_public_material(
                harness.cert,
                (harness.certs / "wildcard.crt").read_bytes(),
                (harness.certs / "wildcard.key").read_bytes(),
                zones=ZONES,
                root=rsa_hierarchy().root,
                now=NOW,
            )

    def test_text_log_format_when_json_flags_are_absent(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        start = argv.index("--log.format")
        trimmed = argv[:start] + argv[start + 4 :]

        result = run_lego(trimmed, env)

        assert result.returncode == 0
        assert result.stdout.startswith("time=")


class TestRenewal:
    def test_existing_certificate_not_due_exits_zero_and_writes_nothing(
        self, harness: Harness
    ) -> None:
        harness.fake.succeed()
        harness.run()
        before = {p.name: p.read_bytes() for p in harness.certs.iterdir()}
        harness.fake.succeed()

        result = harness.run()

        assert result.returncode == 0
        assert "Skip renewal" in result.stdout
        assert "Writing file." not in result.stdout
        assert {p.name: p.read_bytes() for p in harness.certs.iterdir()} == before

    def test_renew_force_rewrites_the_files(self, harness: Harness) -> None:
        harness.fake.succeed()
        harness.run()
        second = harness.fake.succeed()

        result = harness.run(force=True)

        assert result.returncode == 0
        assert (harness.certs / "wildcard.crt").read_text() == second["crt"]

    def test_changed_declared_names_reissue_without_force(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        harness.fake.succeed()
        harness.run()
        harness.fake.succeed()
        harness.cert = harness.cert.model_copy(update={"names": [f"*.{ZONES[0]}", ZONES[0]]})

        result = harness.run()

        assert "Writing file." in result.stdout
        stored = json.loads((harness.certs / "wildcard.json").read_text())
        assert stored["domains"] == [f"*.{ZONES[0]}", ZONES[0]]


FAILURES = [
    ("rate_limited", "urn:ietf:params:acme:error:rateLimited"),
    ("dns_auth", "cloudflare: failed to find zone example.com: [status code 403]"),
    ("dns_propagation", "dns01: time limit exceeded: last error: recursive nameservers"),
    ("unauthorized", "urn:ietf:params:acme:error:unauthorized"),
    ("acme_unreachable", "connect: connection refused"),
    ("dns_zone", 'cloudflare: could not find zone for domain "example.com"'),
    ("config", "some credentials information are missing"),
    ("internal", "could not save the resource"),
]


class TestFailures:
    @pytest.mark.parametrize(("kind", "text"), FAILURES)
    def test_failure_class_exits_one_with_its_error_text_on_stdout(
        self, harness: Harness, kind: str, text: str
    ) -> None:
        harness.fake.fail(kind)

        result = harness.run()

        assert result.returncode == 1
        assert result.stderr == ""
        assert text in error_record(result.stdout)["error"]

    def test_dns_auth_401_variant_reports_status_401(self, harness: Harness) -> None:
        harness.fake.fail("dns_auth", status=401)

        assert "[status code 401]" in error_record(harness.run().stdout)["error"]

    def test_dns_auth_400_variant_reports_status_400(self, harness: Harness) -> None:
        harness.fake.fail("dns_auth", status=400)

        assert "[status code 400]" in error_record(harness.run().stdout)["error"]

    @pytest.mark.parametrize(
        "variant",
        [
            "invalidContact",
            "rejectedIdentifier",
            "malformed",
            "accountDoesNotExist",
            "userActionRequired",
            "badNonce",
            "serverInternal",
        ],
    )
    def test_an_acme_problem_document_carries_its_urn(
        self, harness: Harness, variant: str
    ) -> None:
        harness.fake.fail("acme_problem", variant=variant)

        result = harness.run()

        assert result.returncode == 1
        assert f"urn:ietf:params:acme:error:{variant}" in error_record(result.stdout)["error"]

    def test_a_wrapped_acme_problem_sits_inside_invalid_authorization(
        self, harness: Harness
    ) -> None:
        harness.fake.fail("acme_problem", variant="malformed", wrapped=True)

        error = error_record(harness.run().stdout)["error"]

        assert "invalid authorization: acme: error: 400" in error
        assert "urn:ietf:params:acme:error:malformed" in error

    @pytest.mark.parametrize(
        ("options", "text"),
        [
            ({"variant": "rate"}, "[status code 429]"),
            ({"variant": "5xx"}, "[status code 503]"),
            ({"variant": "5xx", "status": 502}, "[status code 502]"),
            ({"variant": "network"}, "no such host"),
        ],
    )
    def test_a_transient_cloudflare_failure_names_the_cloudflare_call(
        self, harness: Harness, options: dict[str, object], text: str
    ) -> None:
        harness.fake.fail("cloudflare_transient", **options)

        result = harness.run()

        assert result.returncode == 1
        error = error_record(result.stdout)["error"]
        assert "cloudflare:" in error
        assert text in error

    def test_rate_limit_warns_before_the_error_and_carries_retry_after(
        self, harness: Harness
    ) -> None:
        harness.fake.fail("rate_limited", retry_after="2026-11-01 08:30:00 UTC")

        lines = [json.loads(x) for x in harness.run().stdout.splitlines() if x.strip()]

        warn = next(r for r in lines if r["level"] == "WARN")
        assert warn["msg"].startswith("retry: acme: error: 429")
        assert "retry after 2026-11-01 08:30:00 UTC" in warn["msg"]
        assert lines.index(warn) < len(lines) - 1

    def test_rate_limit_without_retry_after_omits_the_clause(self, harness: Harness) -> None:
        harness.fake.fail("rate_limited", retry_after=None)

        assert "retry after" not in harness.run().stdout

    def test_failed_run_after_registration_leaves_account_but_no_certificate(
        self, harness: Harness
    ) -> None:
        harness.fake.fail("unauthorized")

        harness.run()

        assert (harness.storage / "accounts" / HOST_DIR).is_dir()
        assert not harness.certs.exists()

    def test_custom_failure_uses_the_given_error_and_exit_code(self, harness: Harness) -> None:
        harness.fake.configure(failure("custom", error="boom", exit_code=2))

        result = harness.run()

        assert result.returncode == 2
        assert error_record(result.stdout)["error"] == "boom"

    def test_noise_lines_are_emitted_before_the_outcome(self, harness: Harness) -> None:
        harness.fake.configure(failure("internal", noise_lines=50, noise_line_bytes=200))

        result = harness.run()

        assert result.stdout.count("filler ") == 50
        assert len(result.stdout) > 50 * 200


class TestHangs:
    def test_rate_limit_hang_prints_the_warn_line_then_blocks(self, harness: Harness) -> None:
        harness.fake.configure(rate_limit_hang())
        argv, env = harness.argv_env()

        with pytest.raises(subprocess.TimeoutExpired) as caught:
            run_lego(argv, env, timeout=2.0)

        output = caught.value.stdout
        text = output.decode() if isinstance(output, bytes) else (output or "")
        assert "urn:ietf:params:acme:error:rateLimited" in text
        assert "ERROR" not in text
        assert harness.fake.invocations()[0].exit_code is None

    def test_generic_hang_stops_after_the_propagation_line(self, harness: Harness) -> None:
        harness.fake.configure(hang())
        argv, env = harness.argv_env()

        with pytest.raises(subprocess.TimeoutExpired) as caught:
            run_lego(argv, env, timeout=2.0)

        output = caught.value.stdout
        text = output.decode() if isinstance(output, bytes) else (output or "")
        assert text.rstrip().endswith('dns01: waiting for record propagation."}')


class TestSignalAndOutput:
    def test_signal_death_has_a_negative_return_code_and_no_exit_record(
        self, harness: Harness
    ) -> None:
        harness.fake.configure(signal_death())

        result = harness.run()

        assert result.returncode == -9
        assert "Obtaining bundled SAN certificate" in result.stdout
        assert "ERROR" not in result.stdout
        (invocation,) = harness.fake.invocations()
        assert invocation.exit_code is None
        assert not harness.certs.exists()

    def test_another_signal_number_is_used(self, harness: Harness) -> None:
        harness.fake.configure(signal_death(15))

        assert harness.run().returncode == -15

    def test_output_lines_are_printed_verbatim_with_no_error_record(self, harness: Harness) -> None:
        harness.fake.configure(output("first line", "second line", exit_code=3))

        result = harness.run()

        assert result.returncode == 3
        assert result.stdout == "first line\nsecond line\n"
        assert result.stderr == ""

    def test_output_defaults_to_exit_one(self, harness: Harness) -> None:
        harness.fake.configure(output("only"))

        assert harness.run().returncode == 1

    def test_output_with_lines_that_are_not_a_list_is_a_control_error(
        self, harness: Harness
    ) -> None:
        harness.fake.configure({"scenario": "output", "lines": "not a list"})

        result = harness.run()

        assert result.returncode == CONTROL_EXIT
        assert "FAKE-LEGO-CONTROL" in result.stdout


class TestSequence:
    def test_steps_run_in_order_and_the_last_repeats(self, harness: Harness) -> None:
        harness.fake.configure(failure("rate_limited"), success())

        codes = [harness.run().returncode for _ in range(3)]

        # Third run finds the certificate written by the second, so it is a not-due exit 0.
        assert codes == [1, 0, 0]


class TestTokenContract:
    def test_token_in_argv_is_a_violation_and_never_echoed(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego([*argv, "--email", TOKEN_SENTINEL], env)

        assert result.returncode == VIOLATION_EXIT
        assert "FAKE-LEGO-VIOLATION[token_in_argv]" in result.stdout
        assert TOKEN_SENTINEL not in result.stdout + result.stderr

    def test_token_as_a_direct_variable_is_a_violation(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego(argv, {**env, "CF_DNS_API_TOKEN": TOKEN_SENTINEL})

        assert result.returncode == VIOLATION_EXIT
        assert "token_in_env" in result.stdout
        assert TOKEN_SENTINEL not in result.stdout + result.stderr

    def test_missing_token_file_variable_is_a_violation(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        env.pop("CF_DNS_API_TOKEN_FILE")

        result = run_lego(argv, env)

        assert result.returncode == VIOLATION_EXIT
        assert "token_file_missing" in result.stdout

    def test_unreadable_token_file_is_a_violation(
        self, harness: Harness, lego_token: TokenFile
    ) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        lego_token.path.unlink()

        result = run_lego(argv, env)

        assert result.returncode == VIOLATION_EXIT
        assert "token_file_unreadable" in result.stdout

    @pytest.mark.parametrize(
        "name", ["LEGO_PATH", "CF_API_KEY", "CLOUDFLARE_BASE_URL", "GODEBUG"]
    )
    def test_stray_credential_or_lego_variable_is_a_violation(
        self, harness: Harness, name: str
    ) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego(argv, {**env, name: "x"})

        assert result.returncode == VIOLATION_EXIT
        assert "env_name_forbidden" in result.stdout

    def test_missing_path_flag_is_a_violation(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        at = argv.index("--path")

        result = run_lego(argv[:at] + argv[at + 2 :], env)

        assert result.returncode == VIOLATION_EXIT
        assert "path_missing" in result.stdout


class TestEqualsForm:
    def test_the_real_argv_passes_the_seed_values_in_the_equals_form(
        self, harness: Harness
    ) -> None:
        harness.fake.succeed()

        result = harness.run()

        assert result.returncode == 0, result.stdout
        (invocation,) = harness.fake.invocations()
        assert invocation.uses_equals_form("--cert.name")
        assert invocation.uses_equals_form("--domains")
        assert invocation.value("--cert.name") == "wildcard"
        assert invocation.value("--domains") == f"*.{ZONES[0]}"
        assert (harness.certs / "wildcard.crt").is_file()

    def test_the_separated_form_is_accepted_and_means_the_same(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        separated: list[str] = []
        for argument in argv:
            if argument.startswith(("--cert.name=", "--domains=")):
                flag, _, value = argument.partition("=")
                separated += [flag, value]
            else:
                separated.append(argument)

        result = run_lego(separated, env)

        assert result.returncode == 0, result.stdout
        (invocation,) = harness.fake.invocations()
        assert not invocation.uses_equals_form("--cert.name")
        assert invocation.value("--cert.name") == "wildcard"
        assert (harness.certs / "wildcard.json").is_file()

    def test_a_comma_separated_domains_value_names_every_domain(self, harness: Harness) -> None:
        harness.fake.succeed()
        harness.cert = harness.cert.model_copy(update={"names": [f"*.{ZONES[0]}", ZONES[0]]})

        harness.run()

        stored = json.loads((harness.certs / "wildcard.json").read_text())
        assert stored["domains"] == [f"*.{ZONES[0]}", ZONES[0]]

    def test_the_certificate_name_defaults_to_the_sanitised_first_domain_without_the_flag(
        self, harness: Harness
    ) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        without_name = [a for a in argv if not a.startswith("--cert.name=")]

        result = run_lego(without_name, env)

        assert result.returncode == 0, result.stdout
        assert (harness.certs / f"_.{ZONES[0]}.crt").is_file()

    def test_an_unknown_flag_in_the_equals_form_is_rejected(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego([*argv, "--bogus=1"], env)

        assert result.returncode == 1
        assert result.stderr.startswith("Incorrect Usage: flag provided but not defined: -bogus")

    def test_a_value_flag_without_a_value_is_rejected(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego([*argv, "--email"], env)

        assert result.returncode == 1
        assert "flag needs an argument: -email" in result.stderr


class TestStorageDirectory:
    def test_files_are_written_under_the_host_subdirectory_only(self, harness: Harness) -> None:
        harness.fake.succeed()

        harness.run()

        assert harness.storage == harness.settings.lego_path_dir / HOST_DIR
        assert (harness.storage / "certificates" / "wildcard.crt").is_file()
        assert (harness.storage / "accounts" / HOST_DIR).is_dir()
        assert sorted(p.name for p in harness.settings.lego_path_dir.iterdir()) == [HOST_DIR]

    def test_two_directories_never_share_certificate_files(self, harness: Harness) -> None:
        first = harness.fake.succeed()
        harness.run()
        production = harness.acme.model_copy(update={"directory": "production"})
        staging_certs = harness.certs
        harness.acme = production
        second = harness.fake.succeed()

        result = harness.run()

        assert result.returncode == 0
        assert "Skip renewal" not in result.stdout, "production starts from a first issuance"
        assert harness.certs != staging_certs
        assert (staging_certs / "wildcard.crt").read_text() == first["crt"]
        assert (harness.certs / "wildcard.crt").read_text() == second["crt"]
        assert harness.certs.parent.name == "acme-v02.api.letsencrypt.org"

    def test_a_port_in_the_directory_url_is_part_of_the_directory_name(
        self, harness: Harness
    ) -> None:
        harness.fake.succeed()
        harness.acme = harness.acme.model_copy(
            update={"directory": "https://acme.example.test:14000/dir"}
        )

        result = harness.run()

        assert result.returncode == 0, result.stdout
        assert harness.storage.name == "acme.example.test_14000"
        assert (harness.storage / "certificates" / "wildcard.crt").is_file()
        assert (harness.storage / "accounts" / "acme.example.test_14000").is_dir()

    def test_the_bare_lego_base_path_is_a_violation(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        argv[argv.index("--path") + 1] = harness.settings.lego_path_dir.as_posix()

        result = run_lego(argv, env)

        assert result.returncode == VIOLATION_EXIT
        assert "FAKE-LEGO-VIOLATION[path_not_host_dir]" in result.stdout
        assert not harness.settings.lego_path_dir.exists() or not any(
            harness.settings.lego_path_dir.iterdir()
        )

    def test_another_hosts_directory_name_is_a_violation(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        other = harness.settings.lego_path_dir / "other.example"
        argv[argv.index("--path") + 1] = other.as_posix()

        result = run_lego(argv, env)

        assert result.returncode == VIOLATION_EXIT
        assert "path_not_host_dir" in result.stdout
        assert "acme-staging-v02.api.letsencrypt.org" in result.stdout


class TestFlagParsing:
    def test_unknown_flag_exits_one_with_incorrect_usage_on_stderr(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego([*argv, "--bogus"], env)

        assert result.returncode == 1
        assert result.stderr.startswith("Incorrect Usage: flag provided but not defined: -bogus")

    def test_path_before_run_is_rejected_like_lego(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()
        run_at = argv.index("run")
        moved = [*argv[:run_at], "--path", "/tmp/x", *argv[run_at:]]

        result = run_lego(moved, env)

        assert result.returncode == 1
        assert "flag provided but not defined: -path" in result.stderr

    def test_global_flag_after_run_is_rejected_like_lego(self, harness: Harness) -> None:
        harness.fake.succeed()
        argv, env = harness.argv_env()

        result = run_lego([*argv, "--log.level", "debug"], env)

        assert result.returncode == 1
        assert "flag provided but not defined: -log.level" in result.stderr

    def test_renew_is_not_a_command(self, harness: Harness) -> None:
        argv, env = harness.argv_env()
        argv[argv.index("run")] = "renew"

        result = run_lego(argv, env)

        assert result.returncode == 1
        assert "No help topic for 'renew'" in result.stdout

    def test_unconfigured_fake_exits_with_the_control_code(self, harness: Harness) -> None:
        result = harness.run()

        assert result.returncode == CONTROL_EXIT
        assert "FAKE-LEGO-CONTROL" in result.stdout


class TestInvocationLog:
    def test_records_argv_and_selected_env_but_never_the_token(
        self, harness: Harness, lego_token: TokenFile
    ) -> None:
        harness.fake.succeed()
        argv, _ = harness.argv_env()
        harness.run()

        (invocation,) = harness.fake.invocations()

        assert invocation.args == argv[1:]
        assert invocation.value("--cert.name") == "wildcard"
        assert invocation.exit_code == 0
        assert invocation.env["CF_DNS_API_TOKEN_FILE"] == str(lego_token.path)
        assert "CF_DNS_API_TOKEN" not in invocation.env_keys
        assert TOKEN_SENTINEL not in harness.fake.invocations_path.read_text()

    def test_runs_do_not_overlap_and_are_listed_in_start_order(self, harness: Harness) -> None:
        harness.fake.configure(failure("internal"))
        harness.run()
        harness.run()

        first, second = harness.fake.invocations()

        assert first.ended_at is not None
        assert first.ended_at <= second.started_at
