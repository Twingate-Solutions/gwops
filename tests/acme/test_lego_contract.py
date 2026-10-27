"""Contract between `build_argv` and the recorded lego v5.5.2 help.

lego v5 rewrote its CLI. These tests parse the recorded help text and fail when any flag the
builder can emit is missing from it, sits on the wrong side of `run`, or has the wrong arity,
so a lego bump that changes the CLI fails here and the fixtures are regenerated deliberately
(`tests/fixtures/lego/README.md`).

What the fixtures cannot prove (behaviour, not syntax): the `_FILE` environment convention and
the stdout error shapes come from the lego source, not from help text.
"""

import itertools
import re
from pathlib import Path
from typing import Any

import pytest

from gwops.acme.lego import LEGO_ENV_STRIP_PREFIXES, TOKEN_ENV_VARS, build_argv
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings
from gwops.settings import GwopsSettings

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "lego"

_FLAG_RE = re.compile(r"(?<![\w.-])(--?[A-Za-z][\w.-]*)")
_VALUE_TYPE_RE = re.compile(r"^--[\w.-]+ (?:string|int|duration|time)\b")
_ENV_RE = re.compile(r"\[\$([A-Z0-9_]+)\]")


def _normalise(raw: bytes) -> str:
    """Decode a fixture and normalise line endings (`* text=auto` may give a checkout CRLF)."""
    return raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def _read(name: str) -> str:
    return _normalise((FIXTURES / name).read_bytes())


class _Flag:
    """One flag of a help section: its names, whether it takes a value, its env variable.

    `text` is the flag line plus its wrapped continuation lines; lego prints the
    ``[$LEGO_...]`` variable at the end of the description, which can be on a later line.
    """

    def __init__(self, text: str) -> None:
        first = text.split("\n", 1)[0]
        spec = re.split(r"\s{2,}", first.strip(), maxsplit=1)[0]
        self.names: frozenset[str] = frozenset(_FLAG_RE.findall(spec))
        self.long = next(n for n in sorted(self.names) if n.startswith("--"))
        self.takes_value = _VALUE_TYPE_RE.match(spec) is not None
        env = _ENV_RE.search(text)
        self.env = env.group(1) if env else None


def _parse_flags(section: str) -> dict[str, _Flag]:
    """Every flag of a help section (indented lines starting with ``-``), keyed by long name."""
    blocks: list[list[str]] = []
    in_flag = False
    for line in section.split("\n"):
        if re.match(r"^\s+--?[A-Za-z]", line):
            blocks.append([line])
            in_flag = True
        elif in_flag and line.strip() and not line.strip().startswith("Flags related to"):
            blocks[-1].append(line)  # a wrapped description line
        else:
            in_flag = False
    flags: dict[str, _Flag] = {}
    for block in blocks:
        flag = _Flag("\n".join(block))
        flags[flag.long] = flag
    return flags


def _split_run_help(text: str) -> tuple[str, str]:
    options, marker, global_options = text.partition("\nGLOBAL OPTIONS:\n")
    assert marker, "run help has no GLOBAL OPTIONS section"
    return options, global_options


RUN_HELP = _read("v5.5.2-run-help.txt")
TOP_HELP = _read("v5.5.2-help.txt")
_RUN_OPTIONS_TEXT, _RUN_GLOBALS_TEXT = _split_run_help(RUN_HELP)
RUN_FLAGS = _parse_flags(_RUN_OPTIONS_TEXT.partition("OPTIONS:\n")[2])
RUN_GLOBAL_FLAGS = _parse_flags(_RUN_GLOBALS_TEXT)
TOP_GLOBAL_FLAGS = _parse_flags(TOP_HELP.partition("\nGLOBAL OPTIONS:\n")[2])


def _make_settings(**fields: Any) -> AcmeSettings:
    data: dict[str, Any] = {"email": "ops@example.com", "accept_tos": True}
    data.update(fields)
    return AcmeSettings.model_validate(data)


def _make_cert(names: list[str], **fields: Any) -> AcmePublicCertificate:
    data: dict[str, Any] = {"name": "wildcard", "names": names, "source": "acme"}
    data.update(fields)
    return AcmePublicCertificate.model_validate(data)


_GWOPS = GwopsSettings(data_dir=Path("/data"), lego_binary=Path("/usr/local/bin/lego"))

_COMBINATIONS = list(
    itertools.product(
        ["staging", "production", "https://acme.example.org/dir"],
        ["resolver", "authoritative"],
        [False, True],
        [["*.example.com"], ["*.example.com", "example.com"]],
        [None, "acme.delegated.example.net"],
    )
)


def _all_argvs() -> list[list[str]]:
    argvs = []
    for directory, propagation, force, names, alias in _COMBINATIONS:
        argv, _env = build_argv(
            _make_settings(directory=directory, propagation=propagation),
            _make_cert(names, challenge_alias=alias),
            gwops=_GWOPS,
            force=force,
            environ={},
        )
        argvs.append(argv)
    return argvs


ALL_ARGVS = _all_argvs()
ARGV_IDS = [
    f"{d.split('//')[-1][:12]}-{p}-force{f}-{len(n)}names-alias{a is not None}"
    for d, p, f, n, a in _COMBINATIONS
]
EMITTED_FLAGS = sorted(
    {a.partition("=")[0] for argv in ALL_ARGVS for a in argv if a.startswith("-")}
)
EQUALS_FORM_FLAGS = sorted(
    {a.partition("=")[0] for argv in ALL_ARGVS for a in argv if a.startswith("-") and "=" in a}
)


class TestFixtureParsing:
    """Guards the parser, so an empty or malformed fixture cannot make the contract vacuous."""

    def test_the_fixtures_are_recorded_for_v5_5_2(self) -> None:
        assert "lego run - Get or renew a certificate" in RUN_HELP
        assert "VERSION:\n   5.5.2" in TOP_HELP

    def test_line_endings_are_normalised(self) -> None:
        assert "\r" not in RUN_HELP
        assert "\r" not in TOP_HELP

    def test_crlf_checkouts_parse_identically(self) -> None:
        raw = (FIXTURES / "v5.5.2-run-help.txt").read_bytes().replace(b"\r\n", b"\n")
        crlf = _normalise(raw.replace(b"\n", b"\r\n"))

        assert crlf == RUN_HELP
        assert _parse_flags(_split_run_help(crlf)[0].partition("OPTIONS:\n")[2]).keys() == (
            RUN_FLAGS.keys()
        )

    def test_wrapped_descriptions_still_yield_their_environment_variable(self) -> None:
        assert RUN_FLAGS["--server"].env == "LEGO_SERVER"
        assert RUN_FLAGS["--renew-days"].env == "LEGO_RENEW_DAYS"

    def test_the_run_options_are_parsed_in_full(self) -> None:
        assert len(RUN_FLAGS) > 40
        for known in ("--accept-tos", "--domains", "--server", "--dns", "--path", "--cert.name"):
            assert known in RUN_FLAGS

    def test_global_sections_are_parsed(self) -> None:
        assert {"--log.level", "--log.format"} <= RUN_GLOBAL_FLAGS.keys()
        assert {"--log.level", "--log.format", "--config", "--help", "--version"} <= (
            TOP_GLOBAL_FLAGS.keys()
        )

    def test_flag_arity_is_read_from_the_help(self) -> None:
        assert RUN_FLAGS["--accept-tos"].takes_value is False
        assert RUN_FLAGS["--renew-force"].takes_value is False
        assert RUN_FLAGS["--dns.propagation.disable-ans"].takes_value is False
        assert RUN_FLAGS["--email"].takes_value is True
        assert RUN_FLAGS["--domains"].takes_value is True
        assert RUN_FLAGS["--cert.name"].takes_value is True
        assert RUN_FLAGS["--dns.resolvers"].takes_value is True

    def test_short_aliases_are_captured_with_the_long_name(self) -> None:
        assert {"--accept-tos", "-a"} == RUN_FLAGS["--accept-tos"].names
        assert {"--domains", "-d"} == RUN_FLAGS["--domains"].names

    def test_the_argv_combinations_cover_every_option(self) -> None:
        assert len(_COMBINATIONS) == 3 * 2 * 2 * 2 * 2
        assert {"--renew-force", "--dns.propagation.disable-ans"} <= set(EMITTED_FLAGS)

    def test_emitted_flags_are_names_without_values(self) -> None:
        assert all("=" not in flag for flag in EMITTED_FLAGS)
        assert {"--cert.name", "--domains"} <= set(EMITTED_FLAGS)


class TestEveryEmittedFlagIsInTheHelp:
    def test_the_builder_emits_a_known_set_of_flags(self) -> None:
        expected = sorted(
            [
                "--accept-tos",
                "--cert.name",
                "--dns",
                "--dns.propagation.disable-ans",
                "--domains",
                "--email",
                "--force-cert-domains",
                "--key-type",
                "--log.format",
                "--log.level",
                "--no-random-sleep",
                "--path",
                "--renew-force",
                "--server",
            ]
        )
        assert expected == EMITTED_FLAGS

    @pytest.mark.parametrize("flag", EMITTED_FLAGS)
    def test_the_flag_is_a_long_option_of_run_or_a_global_option(self, flag: str) -> None:
        documented = set(RUN_FLAGS) | set(RUN_GLOBAL_FLAGS) | set(TOP_GLOBAL_FLAGS)

        assert flag in documented, (
            f"build_argv can emit {flag}, which the recorded lego v5.5.2 help does not list; "
            "regenerate tests/fixtures/lego deliberately or fix the builder"
        )

    def test_no_short_option_is_emitted(self) -> None:
        assert [f for f in EMITTED_FLAGS if not f.startswith("--")] == []

    def test_the_equals_form_is_used_for_exactly_the_seed_derived_value_flags(self) -> None:
        assert EQUALS_FORM_FLAGS == ["--cert.name", "--domains"]

    def test_the_equals_form_is_used_only_for_flags_that_take_a_value(self) -> None:
        """``--bool=x`` would set the flag from the text; only value flags may use it."""
        for flag in EQUALS_FORM_FLAGS:
            assert RUN_FLAGS[flag].takes_value is True

    def test_the_subcommand_exists_in_the_top_level_help(self) -> None:
        commands = TOP_HELP.partition("COMMANDS:\n")[2].partition("\nGLOBAL OPTIONS:")[0]

        assert re.search(r"^\s+run\s+Get or renew a certificate$", commands, re.MULTILINE)

    def test_there_is_no_renew_command_to_call(self) -> None:
        """v5 dropped `renew`; `run` renews when a certificate exists under `--path`."""
        commands = TOP_HELP.partition("COMMANDS:\n")[2].partition("\nGLOBAL OPTIONS:")[0]

        assert not re.search(r"^\s+renew\b", commands, re.MULTILINE)
        assert all("renew" not in argv[: argv.index("run") + 1] for argv in ALL_ARGVS)


class TestFlagPlacement:
    def test_path_is_a_run_flag_and_not_a_global_one(self) -> None:
        """Before `run` it fails with `flag provided but not defined: -path`."""
        assert "--path" in RUN_FLAGS
        assert "--path" not in RUN_GLOBAL_FLAGS
        assert "--path" not in TOP_GLOBAL_FLAGS

    def test_the_log_flags_are_global(self) -> None:
        for flag in ("--log.format", "--log.level"):
            assert flag in RUN_GLOBAL_FLAGS
            assert flag in TOP_GLOBAL_FLAGS
            assert flag not in RUN_FLAGS

    @pytest.mark.parametrize("argv", ALL_ARGVS, ids=ARGV_IDS)
    def test_global_flags_precede_run_and_run_flags_follow_it(self, argv: list[str]) -> None:
        run = argv.index("run")

        for position, argument in enumerate(argv):
            if not argument.startswith("--"):
                continue
            flag = argument.partition("=")[0]
            if flag in TOP_GLOBAL_FLAGS and flag not in RUN_FLAGS:
                assert position < run, f"global flag {flag} must precede `run`"
            else:
                assert flag in RUN_FLAGS, f"{flag} is not a run flag"
                assert position > run, f"run flag {flag} must follow `run`"

    def test_the_binary_is_first_and_run_is_the_only_bare_word_before_run_flags(self) -> None:
        for argv in ALL_ARGVS:
            run = argv.index("run")
            assert argv[0] == "/usr/local/bin/lego"
            assert argv[1:run] == ["--log.format", "json", "--log.level", "info"]


class TestFlagArity:
    @pytest.mark.parametrize("argv", ALL_ARGVS, ids=ARGV_IDS)
    def test_value_flags_are_followed_by_a_value_and_boolean_flags_are_not(
        self, argv: list[str]
    ) -> None:
        documented = {**TOP_GLOBAL_FLAGS, **RUN_GLOBAL_FLAGS, **RUN_FLAGS}
        for position, argument in enumerate(argv):
            if not argument.startswith("--"):
                continue
            flag, equals, _inline = argument.partition("=")
            following = argv[position + 1] if position + 1 < len(argv) else None
            if equals:
                assert documented[flag].takes_value, f"{flag} is a boolean flag in the lego help"
                assert following is None or following.startswith("--"), (
                    f"{flag}=value is complete; nothing may follow it as a value"
                )
            elif documented[flag].takes_value:
                assert following is not None and not following.startswith("--"), (
                    f"{flag} takes a value in the lego help"
                )
            else:
                assert following is None or following.startswith("--"), (
                    f"{flag} is a boolean flag in the lego help"
                )

    def test_every_value_argument_belongs_to_a_value_flag(self) -> None:
        documented = {**TOP_GLOBAL_FLAGS, **RUN_GLOBAL_FLAGS, **RUN_FLAGS}
        for argv in ALL_ARGVS:
            for position, argument in enumerate(argv[1:], start=1):
                if argument == "run" or argument.startswith("--"):
                    continue
                previous = argv[position - 1]
                assert "=" not in previous, f"{argument!r} follows the complete {previous}"
                assert documented[previous].takes_value, (
                    f"{argument!r} follows {previous}, which takes no value"
                )


class TestEnvironmentContract:
    def test_every_environment_variable_in_the_help_is_lego_prefixed(self) -> None:
        names = {f.env for f in (*RUN_FLAGS.values(), *RUN_GLOBAL_FLAGS.values()) if f.env}

        assert len(names) > 40
        assert all(n.startswith("LEGO_") for n in names)

    def test_the_prefix_guard_covers_every_one_of_them(self) -> None:
        names = {f.env for f in (*RUN_FLAGS.values(), *RUN_GLOBAL_FLAGS.values()) if f.env}
        assert all(n.startswith(LEGO_ENV_STRIP_PREFIXES) for n in names)

    def test_every_emitted_flag_has_a_lego_variable_the_child_must_not_inherit(self) -> None:
        for flag in EMITTED_FLAGS:
            parsed = {**TOP_GLOBAL_FLAGS, **RUN_GLOBAL_FLAGS, **RUN_FLAGS}[flag]
            assert parsed.env is not None
            assert parsed.env.startswith("LEGO_")

    def test_the_token_variables_are_the_cloudflare_names_with_the_file_suffix(self) -> None:
        dnshelp = _read("v5.5.2-dnshelp-cloudflare.txt")

        for variable in TOKEN_ENV_VARS:
            assert variable.endswith("_FILE")
            assert f'"{variable.removesuffix("_FILE")}"' in dnshelp

    def test_the_prefix_guard_covers_every_cloudflare_variable_lego_reads(self) -> None:
        dnshelp = _read("v5.5.2-dnshelp-cloudflare.txt")
        names = re.findall(r'^\s+- "([A-Z0-9_]+)":', dnshelp, re.MULTILINE)

        assert "CF_API_KEY" in names
        assert "CLOUDFLARE_BASE_URL" in names
        assert all(n.startswith(LEGO_ENV_STRIP_PREFIXES) for n in names)
