"""Tests for lego output classification and excerpts (``classify_output``, ``final_error``,
``summarize_output``) in ``gwops.acme.runner``.

The first half is table-driven over lego v5.5.2's failure shapes and runs on every
platform. ``TestAgainstTheFake`` runs the real fake lego (POSIX only) for each failure class and
variant the fake can print and feeds its actual output through the same functions.
"""

import inspect
import json
import os

import pytest

from gwops.acme.lego import build_argv
from gwops.acme.runner import classify_output, final_error, summarize_output
from gwops.acme.state import MAX_EXCERPT_CHARS, AcmeErrorClass
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings
from gwops.settings import GwopsSettings
from tests.acme.fake_lego_support import FakeLego, output, posix_only, run_lego, signal_death

RATE = "urn:ietf:params:acme:error:rateLimited"
CA = "https://acme-v02.api.letsencrypt.org"


def record(level: str, msg: str, **fields: object) -> str:
    """One lego ``--log.format json`` line."""
    return json.dumps({"time": "2026-10-20T12:00:00Z", "level": level, "msg": msg, **fields})


def failed(chain: str, *before: str) -> str:
    """lego output of a failed run: `before` lines, then the final ``Error`` record."""
    return "\n".join([*before, record("ERROR", "Error", error=chain)])


def as_slog_text(chain: str) -> str:
    """The same failure in lego's text log format (no JSON, no ``final_error``)."""
    return f"time=2026-10-20T12:00:00.000Z level=ERROR msg=Error error={json.dumps(chain)}"


def per_domain(cause: str, name: str = "*.example.com") -> str:
    return f"obtain certificate: resolver: one or more domains had a problem: [{name}: {cause}]"


# id -> (final error chain, expected class); shapes recorded from lego v5.5.2
CASES: dict[str, tuple[str, AcmeErrorClass]] = {
    "rate-limited-after-retries": (
        f"obtain certificate: POST {CA}/acme/new-order giving up after 6 attempt(s): "
        f"acme: error: 429 :: POST :: {CA}/acme/new-order :: {RATE} :: too many certificates (5) "
        "already issued for this exact set of identifiers in the last 168h0m0s, "
        "retry after 2026-10-21 10:00:00 UTC",
        AcmeErrorClass.RATE_LIMITED,
    ),
    "rate-limited-renewal": (
        'renew certificate: could not obtain the certificate for "wildcard": '
        f"acme: error: 429 :: {RATE} :: slow down",
        AcmeErrorClass.RATE_LIMITED,
    ),
    "rate-limited-lowercase": (
        "acme: error: 429 :: urn:ietf:params:acme:error:ratelimited",
        AcmeErrorClass.RATE_LIMITED,
    ),
    "dns-auth-zone-lookup-403": (
        per_domain(
            "cloudflare: failed to find zone example.com: "
            "[status code 403] 9109: Invalid access token"
        ),
        AcmeErrorClass.DNS_AUTH,
    ),
    "dns-auth-zone-lookup-401": (
        per_domain(
            "cloudflare: failed to find zone example.com: "
            "[status code 401] 10000: Authentication error"
        ),
        AcmeErrorClass.DNS_AUTH,
    ),
    "dns-auth-create-record": (
        per_domain(
            "cloudflare: failed to create TXT record: [status code 403] 9109: Invalid access token"
        ),
        AcmeErrorClass.DNS_AUTH,
    ),
    "dns-auth-delete-record": (
        "cloudflare: failed to delete TXT record: [status code 403] 9109: Invalid access token",
        AcmeErrorClass.DNS_AUTH,
    ),
    "dns-zone-soa": (
        per_domain('cloudflare: could not find zone for domain "example.com"'),
        AcmeErrorClass.DNS_ZONE,
    ),
    "dns-zone-token-cannot-see": (
        per_domain("cloudflare: failed to find zone example.com: zone could not be found"),
        AcmeErrorClass.DNS_ZONE,
    ),
    "dns-propagation-recursive": (
        per_domain(
            "dns01: time limit exceeded: last error: recursive nameservers: NS 127.0.0.11:53 "
            "did not return the expected TXT record "
            "[fqdn: _acme-challenge.example.com., value: abc]: "
        ),
        AcmeErrorClass.DNS_PROPAGATION,
    ),
    "dns-propagation-authoritative": (
        per_domain(
            "dns01: time limit exceeded: last error: authoritative nameservers: "
            "NS ns1.example.net.:53 "
            "did not return the expected TXT record "
            "[fqdn: _acme-challenge.example.com., value: abc]: "
        ),
        AcmeErrorClass.DNS_PROPAGATION,
    ),
    "dns-propagation-rcode": (
        per_domain(
            "dns01: time limit exceeded: last error: authoritative nameservers: "
            "NS ns1.example.net.:53 "
            "returned NXDOMAIN for _acme-challenge.example.com."
        ),
        AcmeErrorClass.DNS_PROPAGATION,
    ),
    "unauthorized-incorrect-txt": (
        per_domain(
            "invalid authorization: acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: "
            "Incorrect TXT record found at _acme-challenge.example.com"
        ),
        AcmeErrorClass.UNAUTHORIZED,
    ),
    "unauthorized-invalid-challenge": (
        per_domain("invalid challenge: acme: error: 403 :: some problem"),
        AcmeErrorClass.UNAUTHORIZED,
    ),
    "unauthorized-dns-problem": (
        per_domain("acme: error: 403 :: urn:ietf:params:acme:error:dns :: DNS problem: NXDOMAIN"),
        AcmeErrorClass.UNAUTHORIZED,
    ),
    "unauthorized-caa": (
        per_domain(
            "acme: error: 403 :: urn:ietf:params:acme:error:caa :: CAA record prevents issuance"
        ),
        AcmeErrorClass.UNAUTHORIZED,
    ),
    "unauthorized-connection": (
        per_domain(
            "acme: error: 403 :: urn:ietf:params:acme:error:connection :: Timeout during connect"
        ),
        AcmeErrorClass.UNAUTHORIZED,
    ),
    "unreachable-refused": (
        f"registration: get directory at '{CA}/directory': unable to communicate with the API "
        "server: giving up after 6 attempt(s): dial tcp 127.0.0.1:1: connect: connection refused",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "unreachable-5xx": (
        f"obtain certificate: GET {CA}/directory giving up after 6 attempt(s): "
        "unexpected HTTP status 503",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "unreachable-5xx-502": ("unexpected HTTP status 502", AcmeErrorClass.ACME_UNREACHABLE),
    "unreachable-tls": (
        f'Get "{CA}/directory": tls: failed to verify certificate: '
        "x509: certificate signed by unknown authority",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "unreachable-x509-expired": (
        "x509: certificate has expired or is not yet valid",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "config-bad-flag": ("flag provided but not defined: -path", AcmeErrorClass.CONFIG),
    "config-incorrect-usage": (
        "Incorrect Usage: flag needs an argument: -server",
        AcmeErrorClass.CONFIG,
    ),
    "config-no-domains": ("please specify '--cert.name' and/or '--domains'", AcmeErrorClass.CONFIG),
    "config-tos": ("You did not accept the TOS. Unable to proceed.", AcmeErrorClass.CONFIG),
    "config-console": ("Could not read from the console", AcmeErrorClass.CONFIG),
    "config-read-only": ("mkdir /.lego: read-only file system", AcmeErrorClass.CONFIG),
    "config-credentials": (
        "cloudflare: some credentials information are missing: CLOUDFLARE_DNS_API_TOKEN",
        AcmeErrorClass.CONFIG,
    ),
    "config-provider": ("unrecognized DNS provider: route53", AcmeErrorClass.CONFIG),
    "dns-auth-bad-request-400": (
        per_domain(
            "cloudflare: failed to create TXT record: [status code 400] 6003: "
            "Invalid request headers"
        ),
        AcmeErrorClass.DNS_AUTH,
    ),
    "cloudflare-rate-limited-429": (
        per_domain(
            "cloudflare: failed to find zone example.com: [status code 429] 10000: "
            "Too many requests"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-500": (
        per_domain("cloudflare: failed to find zone example.com: [status code 500] 0: oops"),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-502": (
        per_domain("cloudflare: failed to create TXT record: [status code 502] 0: bad gateway"),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-503": (
        per_domain("cloudflare: failed to create TXT record: [status code 503] 0: unavailable"),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-no-such-host": (
        per_domain(
            "cloudflare: failed to find zone example.com: "
            'Get "https://api.cloudflare.com/client/v4/zones?name=example.com": '
            "dial tcp: lookup api.cloudflare.com: no such host"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-deadline-exceeded": (
        per_domain(
            "cloudflare: failed to create TXT record: "
            'Post "https://api.cloudflare.com/client/v4/zones/z/dns_records": '
            "context deadline exceeded"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-io-timeout": (
        per_domain(
            "cloudflare: failed to find zone example.com: "
            "read tcp 10.0.0.2:51234->104.19.1.1:443: i/o timeout"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-connection-reset": (
        per_domain(
            "cloudflare: failed to create TXT record: "
            "read tcp 10.0.0.2:51234->104.19.1.1:443: connection reset by peer"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-unexpected-eof": (
        per_domain("cloudflare: failed to find zone example.com: unexpected EOF"),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-tls-handshake-timeout": (
        per_domain(
            "cloudflare: failed to create TXT record: net/http: TLS handshake timeout"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "cloudflare-host-without-the-provider-prefix": (
        'Get "https://api.cloudflare.com/client/v4/zones": dial tcp 104.19.1.1:443: '
        "connect: connection refused",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "config-invalid-contact": (
        f"registration: acme: error: 400 :: POST :: {CA}/acme/new-acct :: "
        "urn:ietf:params:acme:error:invalidContact :: Error validating contact(s)",
        AcmeErrorClass.CONFIG,
    ),
    "config-rejected-identifier": (
        f"obtain certificate: acme: error: 400 :: POST :: {CA}/acme/new-order :: "
        "urn:ietf:params:acme:error:rejectedIdentifier :: Invalid identifiers requested",
        AcmeErrorClass.CONFIG,
    ),
    "config-malformed": (
        f"obtain certificate: acme: error: 400 :: POST :: {CA}/acme/new-order :: "
        "urn:ietf:params:acme:error:malformed :: JWS verification error",
        AcmeErrorClass.CONFIG,
    ),
    "config-account-does-not-exist": (
        f"obtain certificate: acme: error: 400 :: POST :: {CA}/acme/new-order :: "
        "urn:ietf:params:acme:error:accountDoesNotExist :: Account does not exist",
        AcmeErrorClass.CONFIG,
    ),
    "config-user-action-required": (
        f"obtain certificate: acme: error: 403 :: POST :: {CA}/acme/new-order :: "
        "urn:ietf:params:acme:error:userActionRequired :: Terms of service have changed",
        AcmeErrorClass.CONFIG,
    ),
    "config-problem-nested-in-invalid-authorization": (
        per_domain(
            "invalid authorization: acme: error: 400 :: "
            "urn:ietf:params:acme:error:malformed :: bad request"
        ),
        AcmeErrorClass.CONFIG,
    ),
    "unreachable-bad-nonce": (
        f"obtain certificate: acme: error: 400 :: POST :: {CA}/acme/new-order :: "
        "urn:ietf:params:acme:error:badNonce :: JWS has an invalid anti-replay nonce",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "unreachable-server-internal": (
        f"obtain certificate: acme: error: 500 :: POST :: {CA}/acme/new-order :: "
        "urn:ietf:params:acme:error:serverInternal :: Internal error",
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "unreachable-bad-nonce-nested-in-invalid-authorization": (
        per_domain(
            "invalid authorization: acme: error: 400 :: "
            "urn:ietf:params:acme:error:badNonce :: stale nonce"
        ),
        AcmeErrorClass.ACME_UNREACHABLE,
    ),
    "internal-save": (
        "could not save the resource: open /data/acme/lego/certificates/x.crt: "
        "no space left on device",
        AcmeErrorClass.INTERNAL,
    ),
    "internal-read": (
        "error while reading the certificate: open x.crt: permission denied",
        AcmeErrorClass.INTERNAL,
    ),
    "internal-order": (
        "obtain certificate: invalid order: acme: error: 403 :: "
        'urn:ietf:params:acme:error:orderNotReady :: Order\'s status ("invalid") was not ready',
        AcmeErrorClass.INTERNAL,
    ),
    "internal-unrecognised": ("something nobody anticipated", AcmeErrorClass.INTERNAL),
}


class TestClassifyTable:
    @pytest.mark.parametrize("case", list(CASES))
    def test_a_json_final_error_is_classified(self, case: str) -> None:
        chain, expected = CASES[case]

        assert classify_output(failed(chain)) is expected

    @pytest.mark.parametrize("case", list(CASES))
    def test_the_same_failure_in_text_log_format_is_classified(self, case: str) -> None:
        chain, expected = CASES[case]

        assert classify_output(as_slog_text(chain)) is expected

    @pytest.mark.parametrize("case", list(CASES))
    def test_preceding_progress_lines_do_not_change_the_class(self, case: str) -> None:
        chain, expected = CASES[case]
        progress = (
            record("INFO", "[*.example.com] acme: Obtaining bundled SAN certificate"),
            record("INFO", "[*.example.com] acme: use dns-01 solver"),
            record("INFO", "dns01: waiting for record propagation."),
        )

        assert classify_output(failed(chain, *progress)) is expected

    def test_a_raw_usage_text_without_a_final_error_is_a_config_failure(self) -> None:
        text = "Incorrect Usage: flag provided but not defined: -bogus\n\nNAME:\n   lego run"

        assert classify_output(text) is AcmeErrorClass.CONFIG

    def test_the_final_error_decides_over_an_earlier_warning(self) -> None:
        """A WARN with a rate-limit URN, then a different final error: the final error wins."""
        text = failed(
            per_domain("cloudflare: failed to find zone x: [status code 403] 9109: nope"),
            record("WARN", f"retry: acme: error: 429 :: {RATE} :: slow down"),
        )

        assert classify_output(text) is AcmeErrorClass.DNS_AUTH

    def test_an_unrecognised_final_error_falls_back_to_a_rate_limit_seen_just_before(self) -> None:
        text = failed(
            "could not save the resource",
            record("WARN", f"retry: acme: error: 429 :: {RATE} :: slow down"),
        )

        assert classify_output(text) is AcmeErrorClass.RATE_LIMITED

    def test_the_signature_takes_the_text_and_a_keyword_only_timed_out(self) -> None:
        parameters = inspect.signature(classify_output).parameters

        assert list(parameters) == ["text", "timed_out"]
        assert parameters["timed_out"].kind is inspect.Parameter.KEYWORD_ONLY
        assert "saw_rate_limit" not in parameters

    def test_a_saw_rate_limit_argument_is_no_longer_accepted(self) -> None:
        with pytest.raises(TypeError):
            classify_output("x", saw_rate_limit=True)  # type: ignore[call-arg]

    def test_empty_output_is_internal(self) -> None:
        assert classify_output("") is AcmeErrorClass.INTERNAL

    def test_matching_ignores_case(self) -> None:
        assert (
            classify_output(failed("CLOUDFLARE: failed to find zone x: [STATUS CODE 403] nope"))
            is AcmeErrorClass.DNS_AUTH
        )


# first match wins, in this order: (label, class, a fragment that matches only that row)
ORDER: list[tuple[str, AcmeErrorClass, str]] = [
    ("rate", AcmeErrorClass.RATE_LIMITED, f"acme: error: 429 :: {RATE}"),
    (
        "cf-auth",
        AcmeErrorClass.DNS_AUTH,
        "cloudflare: failed to create TXT record: [status code 403] 9109: x",
    ),
    (
        "cf-zone",
        AcmeErrorClass.DNS_ZONE,
        'cloudflare: could not find zone for domain "x.example"',
    ),
    (
        "cf-transient",
        AcmeErrorClass.ACME_UNREACHABLE,
        "cloudflare: failed to create TXT record: [status code 503] 0: upstream",
    ),
    (
        "propagation",
        AcmeErrorClass.DNS_PROPAGATION,
        "dns01: time limit exceeded: last error: recursive nameservers",
    ),
    (
        "acme-config",
        AcmeErrorClass.CONFIG,
        "acme: error: 400 :: urn:ietf:params:acme:error:malformed :: bad",
    ),
    (
        "acme-transient",
        AcmeErrorClass.ACME_UNREACHABLE,
        "acme: error: 400 :: urn:ietf:params:acme:error:badNonce :: stale",
    ),
    ("unauthorized", AcmeErrorClass.UNAUTHORIZED, "invalid authorization: acme: error: 403"),
    (
        "unreachable",
        AcmeErrorClass.ACME_UNREACHABLE,
        "get directory at 'https://x': unable to communicate",
    ),
    ("config", AcmeErrorClass.CONFIG, "some credentials information are missing: X"),
]
# Two rows of one class cannot show a precedence; only distinct-class pairs are compared.
PAIRS = [
    (ORDER[i], ORDER[j])
    for i in range(len(ORDER))
    for j in range(i + 1, len(ORDER))
    if ORDER[i][1] is not ORDER[j][1]
]


class TestPrecedence:
    @pytest.mark.parametrize(
        ("winner", "loser"), PAIRS, ids=[f"{w[0]}-over-{x[0]}" for w, x in PAIRS]
    )
    def test_the_earlier_row_wins_whatever_the_order_in_the_text(
        self, winner: tuple[str, AcmeErrorClass, str], loser: tuple[str, AcmeErrorClass, str]
    ) -> None:
        both = (f"{winner[2]} | {loser[2]}", f"{loser[2]} | {winner[2]}")

        assert [classify_output(failed(chain)) for chain in both] == [winner[1], winner[1]]

    @pytest.mark.parametrize("row", ORDER, ids=[label for label, _, _ in ORDER])
    def test_each_fragment_alone_maps_to_its_own_class(
        self, row: tuple[str, AcmeErrorClass, str]
    ) -> None:
        assert classify_output(failed(row[2])) is row[1]

    def test_the_table_covers_every_class_the_classifier_can_return_from_output(self) -> None:
        reachable = {error_class for _, error_class, _ in ORDER}

        assert reachable == {
            AcmeErrorClass.RATE_LIMITED,
            AcmeErrorClass.DNS_AUTH,
            AcmeErrorClass.DNS_ZONE,
            AcmeErrorClass.ACME_UNREACHABLE,
            AcmeErrorClass.DNS_PROPAGATION,
            AcmeErrorClass.CONFIG,
            AcmeErrorClass.UNAUTHORIZED,
        }


def progress(count: int) -> list[str]:
    """`count` ordinary INFO records (each is one non-empty output line)."""
    return [record("INFO", f"progress {n}") for n in range(count)]


HANG_TEXT = "\n".join(
    [
        record("INFO", "[*.example.com] acme: Trying to solve DNS-01"),
        record("INFO", "dns01: waiting for record propagation."),
    ]
)
WARN_429 = record(
    "WARN", f"retry: acme: error: 429 :: POST :: {CA}/acme/new-order :: {RATE} :: slow"
)
# (timed_out, text, expected)
TIMEOUT_CASES = {
    "empty": (True, "", AcmeErrorClass.TIMEOUT),
    "propagation-hang": (True, HANG_TEXT, AcmeErrorClass.TIMEOUT),
    "pattern-text-ignored": (
        True,
        failed(per_domain("dns01: time limit exceeded: last error: x")),
        AcmeErrorClass.TIMEOUT,
    ),
    "dns-auth-text-ignored": (
        True,
        failed("cloudflare: failed to find zone x: [status code 403] nope"),
        AcmeErrorClass.TIMEOUT,
    ),
    "marker-in-text": (True, WARN_429, AcmeErrorClass.RATE_LIMITED),
    "marker-uppercase": (True, WARN_429.upper(), AcmeErrorClass.RATE_LIMITED),
    "marker-after-progress": (True, f"{HANG_TEXT}\n{WARN_429}", AcmeErrorClass.RATE_LIMITED),
    "marker-inside-the-last-twenty-lines": (
        True,
        "\n".join([WARN_429, *progress(19)]),
        AcmeErrorClass.RATE_LIMITED,
    ),
    "marker-older-than-the-last-twenty-lines": (
        True,
        "\n".join([WARN_429, *progress(20)]),
        AcmeErrorClass.TIMEOUT,
    ),
    "marker-in-a-final-error-chain": (
        True,
        failed(f"obtain certificate: acme: error: 429 :: {RATE}", *progress(40)),
        AcmeErrorClass.RATE_LIMITED,
    ),
}


class TestTimeoutRules:
    @pytest.mark.parametrize("case", list(TIMEOUT_CASES))
    def test_a_killed_run_is_a_timeout_unless_a_rate_limit_is_near_the_end(
        self, case: str
    ) -> None:
        timed_out, text, expected = TIMEOUT_CASES[case]

        assert classify_output(text, timed_out=timed_out) is expected

    def test_timed_out_defaults_to_false(self) -> None:
        assert classify_output(HANG_TEXT) is AcmeErrorClass.INTERNAL

    def test_without_a_timeout_an_unclassified_error_is_internal(self) -> None:
        assert classify_output(failed("boom")) is AcmeErrorClass.INTERNAL


class TestRateLimitFallbackWindow:
    """The ``rateLimited`` marker rescues an unclassified failure only near the end."""

    def test_a_marker_nineteen_records_before_the_final_error_still_counts(self) -> None:
        text = failed("boom", WARN_429, *progress(18))  # 20 lines in all

        assert classify_output(text) is AcmeErrorClass.RATE_LIMITED

    def test_a_marker_that_is_more_than_twenty_lines_from_the_end_does_not(self) -> None:
        text = failed("boom", WARN_429, *progress(19))  # 21 lines in all

        assert classify_output(text) is AcmeErrorClass.INTERNAL

    def test_blank_lines_do_not_push_a_marker_out_of_the_window(self) -> None:
        text = failed("boom", WARN_429, *(["", "  "] * 30), *progress(18))

        assert classify_output(text) is AcmeErrorClass.RATE_LIMITED

    def test_a_marker_in_a_long_run_far_from_the_end_does_not_make_it_a_rate_limit(self) -> None:
        text = failed("could not save the resource", WARN_429, *progress(200))

        assert classify_output(text) is AcmeErrorClass.INTERNAL

    def test_without_a_final_error_the_marker_must_also_be_near_the_end(self) -> None:
        assert classify_output("\n".join([WARN_429, *progress(5)])) is AcmeErrorClass.RATE_LIMITED
        assert classify_output("\n".join([WARN_429, *progress(20)])) is AcmeErrorClass.INTERNAL

    def test_a_marker_in_the_final_error_chain_wins_however_long_the_run_was(self) -> None:
        text = failed(f"obtain certificate: acme: error: 429 :: {RATE}", *progress(200))

        assert classify_output(text) is AcmeErrorClass.RATE_LIMITED

    def test_a_classified_final_error_is_not_overridden_by_a_marker_near_the_end(self) -> None:
        text = failed("cloudflare: failed to find zone x: [status code 403] nope", WARN_429)

        assert classify_output(text) is AcmeErrorClass.DNS_AUTH

    def test_a_marker_far_from_the_end_does_not_change_a_classified_final_error(self) -> None:
        text = failed("cloudflare: failed to find zone x: [status code 403] nope", WARN_429,
                      *progress(100))  # fmt: skip

        assert classify_output(text) is AcmeErrorClass.DNS_AUTH


# --- final_error ------------------------------------------------------------------------------


class TestFinalError:
    def test_the_error_chain_of_the_last_error_record_is_returned(self) -> None:
        text = "\n".join(
            [
                record("ERROR", "Error", error="first"),
                record("INFO", "between"),
                record("ERROR", "Error", error="second"),
            ]
        )

        assert final_error(text) == "second"

    def test_output_without_json_has_no_final_error(self) -> None:
        assert final_error("time=x level=ERROR msg=Error error=boom\nplain line") is None

    def test_empty_output_has_no_final_error(self) -> None:
        assert final_error("") is None

    def test_only_error_level_records_count(self) -> None:
        text = record("WARN", "retry", error="not final") + "\n" + record("INFO", "x", error="no")

        assert final_error(text) is None

    def test_the_level_is_case_insensitive(self) -> None:
        assert final_error(json.dumps({"level": "error", "error": "lower"})) == "lower"

    def test_records_without_a_string_error_are_ignored(self) -> None:
        text = "\n".join(
            [
                record("ERROR", "Error", error="kept"),
                json.dumps({"level": "ERROR", "msg": "Error", "error": 7}),
                json.dumps({"level": "ERROR", "msg": "Error"}),
            ]
        )

        assert final_error(text) == "kept"

    def test_malformed_and_non_object_lines_are_skipped(self) -> None:
        text = "\n".join(
            [
                '{"level": "ERROR", "error": "cut',
                "[1, 2]",
                '"string"',
                "{}",
                record("ERROR", "E", error="ok"),
            ]
        )

        assert final_error(text) == "ok"

    def test_indented_json_lines_are_read(self) -> None:
        assert final_error("   " + record("ERROR", "Error", error="indented")) == "indented"

    def test_windows_line_endings_are_read(self) -> None:
        assert final_error(record("ERROR", "Error", error="crlf") + "\r\n") == "crlf"


# --- summarize_output -----------------------------------------------------------------------


def summary(
    text: str, *, exit_code: int | None = 1, timed_out: bool = False, limit: float = 600.0
) -> str:
    return summarize_output(text, exit_code=exit_code, timed_out=timed_out, timeout_seconds=limit)


class TestSummarize:
    def test_the_final_error_chain_is_the_excerpt(self) -> None:
        text = failed("obtain certificate: boom", record("INFO", "noise before"))

        assert summary(text) == "obtain certificate: boom"

    def test_without_a_final_error_the_last_three_lines_are_rendered(self) -> None:
        lines = [record("INFO", f"line {n}") for n in range(1, 6)]

        result = summary("\n".join(lines))

        assert result == "INFO line 3 | INFO line 4 | INFO line 5"

    def test_a_json_record_with_an_error_field_renders_level_message_and_error(self) -> None:
        text = record("WARN", "retry", error="x")

        assert summary(text) == "WARN retry: x"

    def test_plain_lines_are_kept_verbatim_and_blank_lines_are_skipped(self) -> None:
        assert summary("one\n\n  two  \n\nthree\n") == "one | two | three"

    def test_a_text_log_line_is_not_reinterpreted(self) -> None:
        assert summary("time=x level=INFO msg=hello") == "time=x level=INFO msg=hello"

    def test_empty_output_gives_an_empty_excerpt(self) -> None:
        assert summary("") == ""

    def test_a_timed_out_run_is_prefixed_with_the_limit(self) -> None:
        assert summary(HANG_TEXT, exit_code=None, timed_out=True).startswith(
            "killed after 600s without finishing; "
        )

    def test_a_fractional_limit_is_shown_without_trailing_zeros(self) -> None:
        assert summary("x", exit_code=None, timed_out=True, limit=1.5).startswith(
            "killed after 1.5s "
        )
        assert summary("x", exit_code=None, timed_out=True, limit=30.0).startswith(
            "killed after 30s "
        )

    @pytest.mark.parametrize("code", [2, 3, 99, 137])
    def test_an_unusual_exit_code_is_a_prefix(self, code: int) -> None:
        assert summary("boom", exit_code=code) == f"exit {code}: boom"

    @pytest.mark.parametrize("code", [-1, -6, -9, -11, -15])
    def test_a_death_by_signal_is_named_as_such(self, code: int) -> None:
        assert summary("boom", exit_code=code) == f"terminated by signal {-code}: boom"

    def test_a_signal_death_with_no_output_still_says_so(self) -> None:
        assert summary("", exit_code=-9) == "terminated by signal 9:"

    @pytest.mark.parametrize("code", [0, 1, None])
    def test_the_usual_exit_codes_have_no_prefix(self, code: int | None) -> None:
        assert summary("boom", exit_code=code) == "boom"

    def test_the_timeout_prefix_wins_over_the_exit_code_prefix(self) -> None:
        result = summary("boom", exit_code=-9, timed_out=True)

        assert result.startswith("killed after")
        assert "exit -9" not in result
        assert "terminated by signal" not in result

    def test_the_excerpt_is_bounded_and_marked_when_cut(self) -> None:
        result = summary(failed("a long failure chain " * 10_000))

        assert len(result) == MAX_EXCERPT_CHARS
        assert result.endswith("...")

    def test_a_chain_that_is_one_long_base64_looking_word_is_withheld_not_shown(self) -> None:
        """A bare 48+ character alphanumeric line reads as a PEM body and is replaced."""
        result = summary(failed("x" * 100_000))

        assert result == "[line withheld: possible PEM body]"

    def test_a_very_long_line_without_a_final_error_is_bounded_too(self) -> None:
        result = summary("y" * 500_000)

        assert len(result) <= MAX_EXCERPT_CHARS

    def test_the_excerpt_is_a_single_line(self) -> None:
        result = summary(failed("first line\nsecond line\r\nthird"))

        assert "\n" not in result
        assert "\r" not in result

    def test_control_characters_are_removed(self) -> None:
        result = summary(failed("red \x1b[31mtext\x1b[0m bell \x07 nul \x00 end"))

        assert "\x1b" not in result
        assert "\x07" not in result
        assert "\x00" not in result
        assert "text" in result

    def test_a_cloudflare_token_in_the_final_error_is_redacted(self) -> None:
        token = "cfut_" + "A1b2C3d4" * 4
        result = summary(failed(f"cloudflare: bad request, key {token} rejected"))

        assert token not in result
        assert "[redacted]" in result

    def test_a_credential_in_an_unstructured_tail_is_redacted(self) -> None:
        result = summary("starting\nAuthorization: Bearer abc.def.ghi\nstopping")

        assert "abc.def.ghi" not in result
        assert "withheld" in result

    def test_a_pem_block_in_the_tail_is_redacted(self) -> None:
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"

        result = summary(f"before\n{pem}")

        assert "MIIEvQIBADANBgkq" not in result

    def test_the_pem_body_lines_of_a_block_cannot_slip_into_the_tail_window(self) -> None:
        """The whole output is redacted before the last three lines are taken."""
        body = ["A" * 64, "B" * 64, "C" * 64]
        text = "\n".join(
            ["noise", "-----BEGIN PRIVATE KEY-----", *body, "-----END PRIVATE KEY-----", "after"]
        )

        result = summary(text)

        assert result == "noise | [redacted: PEM block] | after"
        assert not any(line in result for line in body)

    def test_a_pem_block_cut_off_by_the_end_of_the_output_is_redacted(self) -> None:
        text = "\n".join(["noise", "-----BEGIN PRIVATE KEY-----", "D" * 64, "E" * 64, "F" * 64])

        result = summary(text)

        assert result == "noise | [redacted: PEM block]"

    def test_a_bare_base64_line_is_withheld_when_its_begin_marker_is_out_of_view(self) -> None:
        body = "G" * 64

        result = summary(f"first\n{body}\nlast")

        assert result == "first | [line withheld: possible PEM body] | last"
        assert body not in result

    def test_a_bare_base64_line_in_a_json_message_is_not_a_whole_line_and_is_kept(self) -> None:
        """Only a line that is nothing but base64 is a PEM body; a sentence is left alone."""
        text = record("INFO", f"saw {'H' * 64} in the response")

        assert "H" * 64 in summary(text)

    def test_the_ca_problem_survives_in_an_unstructured_tail_too(self) -> None:
        problem = (
            "[*.example.com: invalid authorization: acme: error: 403 :: "
            "urn:ietf:params:acme:error:unauthorized :: Incorrect TXT record]"
        )

        result = summary(record("WARN", "retry", error=problem))

        assert "invalid authorization: acme: error: 403" in result
        assert "urn:ietf:params:acme:error:unauthorized" in result
        assert "withheld" not in result

    def test_the_ca_problem_of_a_failed_validation_survives_into_the_excerpt(self) -> None:
        """The ``unauthorized`` shape: ``invalid authorization: acme: error: ...``."""
        chain = per_domain(
            "invalid authorization: acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: "
            "Incorrect TXT record found at _acme-challenge.example.com"
        )

        result = summary(failed(chain))

        assert "urn:ietf:params:acme:error:unauthorized" in result


# --- against the real fake ---------------------------------------------------------------------

# kind, fake options, expected class, text that must survive into the excerpt
FAKE_CASES = {
    "rate-limited": ("rate_limited", {}, AcmeErrorClass.RATE_LIMITED, RATE),
    "rate-limited-no-hint": (
        "rate_limited",
        {"retry_after": None},
        AcmeErrorClass.RATE_LIMITED,
        RATE,
    ),
    "dns-auth-403": ("dns_auth", {}, AcmeErrorClass.DNS_AUTH, "[status code 403]"),
    "dns-auth-401": ("dns_auth", {"status": 401}, AcmeErrorClass.DNS_AUTH, "[status code 401]"),
    "dns-auth-create-record": (
        "dns_auth",
        {"variant": "create_record"},
        AcmeErrorClass.DNS_AUTH,
        "failed to create TXT record",
    ),
    "dns-auth-400": ("dns_auth", {"status": 400}, AcmeErrorClass.DNS_AUTH, "[status code 400]"),
    "cloudflare-429": (
        "cloudflare_transient",
        {"variant": "rate"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "[status code 429]",
    ),
    "cloudflare-503": (
        "cloudflare_transient",
        {"variant": "5xx"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "[status code 503]",
    ),
    "cloudflare-502": (
        "cloudflare_transient",
        {"variant": "5xx", "status": 502},
        AcmeErrorClass.ACME_UNREACHABLE,
        "[status code 502]",
    ),
    "cloudflare-network": (
        "cloudflare_transient",
        {"variant": "network"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "no such host",
    ),
    "acme-invalid-contact": (
        "acme_problem",
        {"variant": "invalidContact"},
        AcmeErrorClass.CONFIG,
        "urn:ietf:params:acme:error:invalidContact",
    ),
    "acme-rejected-identifier": (
        "acme_problem",
        {"variant": "rejectedIdentifier"},
        AcmeErrorClass.CONFIG,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    ),
    "acme-malformed": (
        "acme_problem",
        {"variant": "malformed"},
        AcmeErrorClass.CONFIG,
        "urn:ietf:params:acme:error:malformed",
    ),
    "acme-account-does-not-exist": (
        "acme_problem",
        {"variant": "accountDoesNotExist"},
        AcmeErrorClass.CONFIG,
        "urn:ietf:params:acme:error:accountDoesNotExist",
    ),
    "acme-user-action-required": (
        "acme_problem",
        {"variant": "userActionRequired"},
        AcmeErrorClass.CONFIG,
        "urn:ietf:params:acme:error:userActionRequired",
    ),
    "acme-bad-nonce": (
        "acme_problem",
        {"variant": "badNonce"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "urn:ietf:params:acme:error:badNonce",
    ),
    "acme-server-internal": (
        "acme_problem",
        {"variant": "serverInternal"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "urn:ietf:params:acme:error:serverInternal",
    ),
    "acme-malformed-nested-in-invalid-authorization": (
        "acme_problem",
        {"variant": "malformed", "wrapped": True},
        AcmeErrorClass.CONFIG,
        "invalid authorization: acme: error: 400",
    ),
    "acme-bad-nonce-nested-in-invalid-authorization": (
        "acme_problem",
        {"variant": "badNonce", "wrapped": True},
        AcmeErrorClass.ACME_UNREACHABLE,
        "invalid authorization: acme: error: 400",
    ),
    "dns-propagation-recursive": (
        "dns_propagation",
        {},
        AcmeErrorClass.DNS_PROPAGATION,
        "dns01: time limit exceeded",
    ),
    "dns-propagation-authoritative": (
        "dns_propagation",
        {"variant": "authoritative"},
        AcmeErrorClass.DNS_PROPAGATION,
        "authoritative nameservers",
    ),
    "dns-propagation-rcode": (
        "dns_propagation",
        {"variant": "rcode"},
        AcmeErrorClass.DNS_PROPAGATION,
        "returned NXDOMAIN",
    ),
    "unauthorized": (
        "unauthorized",
        {},
        AcmeErrorClass.UNAUTHORIZED,
        "urn:ietf:params:acme:error:unauthorized",
    ),
    "unauthorized-invalid-challenge": (
        "unauthorized",
        {"variant": "invalid_challenge"},
        AcmeErrorClass.UNAUTHORIZED,
        "invalid challenge",
    ),
    "unauthorized-dns": (
        "unauthorized",
        {"variant": "dns"},
        AcmeErrorClass.UNAUTHORIZED,
        "urn:ietf:params:acme:error:dns",
    ),
    "unauthorized-caa": (
        "unauthorized",
        {"variant": "caa"},
        AcmeErrorClass.UNAUTHORIZED,
        "urn:ietf:params:acme:error:caa",
    ),
    "unauthorized-connection": (
        "unauthorized",
        {"variant": "connection"},
        AcmeErrorClass.UNAUTHORIZED,
        "urn:ietf:params:acme:error:connection",
    ),
    "unreachable-refused": (
        "acme_unreachable",
        {},
        AcmeErrorClass.ACME_UNREACHABLE,
        "unable to communicate with the API server",
    ),
    "unreachable-5xx": (
        "acme_unreachable",
        {"variant": "5xx"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "unexpected HTTP status 503",
    ),
    "unreachable-tls": (
        "acme_unreachable",
        {"variant": "tls"},
        AcmeErrorClass.ACME_UNREACHABLE,
        "tls: failed to verify certificate",
    ),
    "dns-zone-soa": ("dns_zone", {}, AcmeErrorClass.DNS_ZONE, "could not find zone for domain"),
    "dns-zone-token": (
        "dns_zone",
        {"variant": "token"},
        AcmeErrorClass.DNS_ZONE,
        "zone could not be found",
    ),
    "config-no-domains": (
        "config",
        {"variant": "no_domains"},
        AcmeErrorClass.CONFIG,
        "please specify",
    ),
    "config-tos": ("config", {"variant": "tos"}, AcmeErrorClass.CONFIG, "did not accept the TOS"),
    "config-console": (
        "config",
        {"variant": "console"},
        AcmeErrorClass.CONFIG,
        "Could not read from the console",
    ),
    "config-readonly": (
        "config",
        {"variant": "readonly"},
        AcmeErrorClass.CONFIG,
        "read-only file system",
    ),
    "config-credentials": (
        "config",
        {},
        AcmeErrorClass.CONFIG,
        "some credentials information are missing",
    ),
    "internal-save": ("internal", {}, AcmeErrorClass.INTERNAL, "could not save the resource"),
    "internal-read": (
        "internal",
        {"variant": "read"},
        AcmeErrorClass.INTERNAL,
        "error while reading the certificate",
    ),
    "internal-order": (
        "internal",
        {"variant": "order"},
        AcmeErrorClass.INTERNAL,
        "invalid order",
    ),
}


@posix_only
class TestAgainstTheFake:
    @staticmethod
    def output_of(
        fake: FakeLego,
        settings: GwopsSettings,
        acme: AcmeSettings,
        cert: AcmePublicCertificate,
        kind: str,
        options: dict[str, object],
    ) -> str:
        fake.fail(kind, **options)
        argv, env = build_argv(acme, cert, gwops=settings, environ={"PATH": os.environ["PATH"]})
        result = run_lego(argv, env)
        assert result.returncode == 1, result.stdout
        return result.stdout + result.stderr

    @pytest.mark.parametrize("case", list(FAKE_CASES))
    def test_the_fakes_output_is_classified(
        self,
        case: str,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        acme_settings: AcmeSettings,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        kind, options, expected, _ = FAKE_CASES[case]

        text = self.output_of(fake_lego, lego_settings, acme_settings, acme_cert, kind, options)

        assert classify_output(text) is expected

    @pytest.mark.parametrize("case", list(FAKE_CASES))
    def test_the_fakes_excerpt_is_bounded_single_line_and_keeps_the_cause(
        self,
        case: str,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        acme_settings: AcmeSettings,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        kind, options, _, survives = FAKE_CASES[case]
        text = self.output_of(fake_lego, lego_settings, acme_settings, acme_cert, kind, options)

        result = summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0)

        assert 0 < len(result) <= MAX_EXCERPT_CHARS
        assert "\n" not in result
        assert survives in result

    def test_a_signal_death_is_internal_and_named_in_the_excerpt(
        self,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        acme_settings: AcmeSettings,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        fake_lego.configure(signal_death())
        argv, env = build_argv(
            acme_settings, acme_cert, gwops=lego_settings, environ={"PATH": os.environ["PATH"]}
        )
        result = run_lego(argv, env)
        text = result.stdout + result.stderr

        assert result.returncode == -9
        assert classify_output(text) is AcmeErrorClass.INTERNAL
        excerpt = summarize_output(
            text, exit_code=result.returncode, timed_out=False, timeout_seconds=600.0
        )
        assert excerpt.startswith("terminated by signal 9: ")
        assert len(excerpt) <= MAX_EXCERPT_CHARS

    def test_raw_output_with_no_final_error_is_summarised_from_its_last_lines(
        self,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        acme_settings: AcmeSettings,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        body = "J" * 64
        fake_lego.configure(output("line one", body, "line three", "line four", exit_code=1))
        argv, env = build_argv(
            acme_settings, acme_cert, gwops=lego_settings, environ={"PATH": os.environ["PATH"]}
        )
        text = run_lego(argv, env).stdout

        assert final_error(text) is None
        assert summarize_output(text, exit_code=1, timed_out=False, timeout_seconds=600.0) == (
            "[line withheld: possible PEM body] | line three | line four"
        )

    def test_a_custom_exit_code_two_is_noted_in_the_excerpt(
        self,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        acme_settings: AcmeSettings,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        fake_lego.configure(
            {"scenario": "fail", "failure": "custom", "error": "boom", "exit_code": 2}
        )
        argv, env = build_argv(
            acme_settings, acme_cert, gwops=lego_settings, environ={"PATH": os.environ["PATH"]}
        )
        result = run_lego(argv, env)

        text = result.stdout + result.stderr

        assert result.returncode == 2
        assert classify_output(text) is AcmeErrorClass.INTERNAL
        assert summarize_output(text, exit_code=2, timed_out=False, timeout_seconds=600.0) == (
            "exit 2: boom"
        )
