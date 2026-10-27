"""Tests for ``gwops.acme.state``: persistence, backoff policy and the failed-validation limiter.

Pure policy functions take ``now`` as an argument and the store never reads a clock, so every
test here is deterministic. Only the POSIX permission bits are skipped on Windows.
"""

import hashlib
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import structlog

from gwops.acme import state as state_module
from gwops.acme.state import (
    INITIAL_BACKOFF,
    MAX_BACKOFF,
    MAX_EXCERPT_CHARS,
    MAX_RETRY_AFTER,
    PRUNE_RETENTION,
    RATE_LIMIT_FLOOR,
    STATE_FILENAME,
    VALIDATION_WINDOW,
    AcmeErrorClass,
    AcmeStateError,
    AcmeStateStore,
    FailureOutcome,
    backoff_delay,
    bound_excerpt,
    limiter_not_before,
    names_hash,
    next_attempt_after_failure,
    parse_retry_after,
    prune_validation_failures,
)

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
MINUTE = timedelta(minutes=1)
HOUR = timedelta(hours=1)
CERT = "wildcard"
NAMES = ["*.example.com"]
DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"

posix_perms = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


@pytest.fixture
def acme_dir(tmp_path: Path) -> Path:
    return tmp_path / "data" / "acme"


@pytest.fixture
def store(acme_dir: Path) -> AcmeStateStore:
    return AcmeStateStore(acme_dir)


def start_attempt(
    store: AcmeStateStore,
    now: datetime = T0,
    *,
    name: str = CERT,
    names: list[str] | None = None,
    reason: str = "missing",
) -> None:
    store.record_attempt_start(
        name,
        now=now,
        names=NAMES if names is None else names,
        directory=DIRECTORY,
        reason=reason,
    )


def read_doc(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


# --- error classes ----------------------------------------------------------------------------


class TestErrorClasses:
    def test_the_stored_codes_are_stable(self) -> None:
        """The values are written to state.json and shown as ``acme_failed:<code>``."""
        assert {c.value for c in AcmeErrorClass} == {
            "rate_limited",
            "dns_auth",
            "dns_zone",
            "dns_propagation",
            "unauthorized",
            "acme_unreachable",
            "timeout",
            "invalid_output",
            "config",
            "internal",
        }

    def test_a_class_is_its_string_code(self) -> None:
        assert AcmeErrorClass.RATE_LIMITED == "rate_limited"
        assert f"acme_failed:{AcmeErrorClass.DNS_AUTH}" == "acme_failed:dns_auth"


# --- backoff policy ---------------------------------------------------------------------------


class TestBackoffDelay:
    @pytest.mark.parametrize(
        ("failures", "expected"),
        [
            (1, timedelta(minutes=15)),
            (2, timedelta(minutes=30)),
            (3, timedelta(hours=1)),
            (4, timedelta(hours=2)),
            (5, timedelta(hours=4)),
            (6, timedelta(hours=8)),
            (7, timedelta(hours=16)),
            (8, timedelta(hours=24)),
        ],
    )
    def test_it_doubles_from_fifteen_minutes(self, failures: int, expected: timedelta) -> None:
        assert backoff_delay(failures) == expected

    @pytest.mark.parametrize("failures", [8, 9, 10, 50, 1000, 10**9])
    def test_it_is_capped_at_twenty_four_hours(self, failures: int) -> None:
        assert backoff_delay(failures) == MAX_BACKOFF == timedelta(hours=24)

    @pytest.mark.parametrize("failures", [0, -1, -100])
    def test_no_failures_means_no_delay(self, failures: int) -> None:
        assert backoff_delay(failures) == timedelta(0)

    def test_the_first_delay_is_the_initial_backoff(self) -> None:
        assert backoff_delay(1) == INITIAL_BACKOFF

    def test_it_never_decreases(self) -> None:
        delays = [backoff_delay(n) for n in range(0, 40)]

        assert delays == sorted(delays)


class TestNextAttemptAfterFailure:
    def next_at(self, error_class: AcmeErrorClass, failures: int = 1, **kwargs: object) -> datetime:
        return next_attempt_after_failure(
            now=T0,
            error_class=error_class,
            consecutive_failures=failures,
            **kwargs,  # type: ignore[arg-type]
        )

    def test_an_ordinary_failure_waits_the_backoff(self) -> None:
        assert self.next_at(AcmeErrorClass.INTERNAL) == T0 + 15 * MINUTE
        assert self.next_at(AcmeErrorClass.INTERNAL, 3) == T0 + HOUR

    def test_zero_failures_is_treated_as_one(self) -> None:
        assert self.next_at(AcmeErrorClass.DNS_AUTH, 0) == T0 + INITIAL_BACKOFF

    def test_a_rate_limit_waits_at_least_an_hour(self) -> None:
        assert self.next_at(AcmeErrorClass.RATE_LIMITED) == T0 + RATE_LIMIT_FLOOR == T0 + HOUR

    def test_a_rate_limit_with_a_short_retry_after_still_waits_the_floor(self) -> None:
        assert self.next_at(AcmeErrorClass.RATE_LIMITED, retry_after=T0 + 10 * MINUTE) == T0 + HOUR

    def test_a_rate_limit_honours_a_longer_retry_after(self) -> None:
        retry = T0 + timedelta(hours=5, minutes=3)

        assert self.next_at(AcmeErrorClass.RATE_LIMITED, retry_after=retry) == retry

    def test_a_rate_limit_retry_after_is_capped_at_seven_days(self) -> None:
        far = T0 + timedelta(days=30)

        assert self.next_at(AcmeErrorClass.RATE_LIMITED, retry_after=far) == T0 + MAX_RETRY_AFTER

    def test_a_rate_limit_takes_the_larger_of_backoff_and_retry_after(self) -> None:
        assert (
            self.next_at(AcmeErrorClass.RATE_LIMITED, 8, retry_after=T0 + 2 * HOUR)
            == T0 + MAX_BACKOFF
        )

    def test_other_classes_ignore_a_retry_after(self) -> None:
        assert (
            self.next_at(AcmeErrorClass.INTERNAL, retry_after=T0 + timedelta(hours=5))
            == T0 + 15 * MINUTE
        )

    def test_the_limiter_raises_the_floor_in_production(self) -> None:
        failures = [T0 - 40 * MINUTE, T0 - 30 * MINUTE, T0 - 20 * MINUTE, T0]

        result = self.next_at(AcmeErrorClass.UNAUTHORIZED, validation_failures=failures)

        assert result == failures[0] + VALIDATION_WINDOW == T0 + 20 * MINUTE

    def test_the_limiter_is_ignored_for_staging(self) -> None:
        failures = [T0 - 3 * MINUTE, T0 - 2 * MINUTE, T0 - MINUTE, T0]

        result = self.next_at(
            AcmeErrorClass.UNAUTHORIZED, validation_failures=failures, production=False
        )

        assert result == T0 + INITIAL_BACKOFF


# --- parse_retry_after ------------------------------------------------------------------------


class TestParseRetryAfter:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                "too many certificates (5) already issued, retry after 2026-10-21 10:00:00 UTC: x",
                datetime(2026, 10, 21, 10, 0, 0, tzinfo=UTC),
            ),
            ("Retry After 2026-10-21 10:00:00 UTC", datetime(2026, 10, 21, 10, 0, tzinfo=UTC)),
            ("retry-after: 2026-10-21T10:00:00Z", datetime(2026, 10, 21, 10, 0, tzinfo=UTC)),
            ("retry after 2026-10-21 10:00:00", datetime(2026, 10, 21, 10, 0, tzinfo=UTC)),
            (
                '{"msg":"retry after 2026-10-22 01:02:03 UTC: x"}',
                datetime(2026, 10, 22, 1, 2, 3, tzinfo=UTC),
            ),
        ],
        ids=["lets-encrypt-clause", "mixed-case", "iso-t-z", "no-zone", "inside-json"],
    )
    def test_a_date_clause_is_read_as_utc(self, text: str, expected: datetime) -> None:
        assert parse_retry_after(text, T0) == expected

    @pytest.mark.parametrize(
        ("text", "seconds"),
        [
            ("Retry-After: 120", 120),
            ("retry after 3600", 3600),
            ("retry-after 90s", 90),
            ("Retry-After: 300 seconds", 300),
        ],
    )
    def test_a_number_of_seconds_is_added_to_now(self, text: str, seconds: int) -> None:
        assert parse_retry_after(text, T0) == T0 + timedelta(seconds=seconds)

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "no hint here",
            "retry later",
            "retry after soon",
            "retry after 99999999999",
            "retry after 2026-13-45 99:99:99 UTC",
        ],
    )
    def test_no_usable_hint_returns_none(self, text: str) -> None:
        assert parse_retry_after(text, T0) is None

    def test_a_date_in_the_past_returns_none(self) -> None:
        assert parse_retry_after("retry after 2026-10-19 10:00:00 UTC", T0) is None

    def test_a_date_equal_to_now_returns_none(self) -> None:
        assert parse_retry_after("retry after 2026-10-20 12:00:00 UTC", T0) is None

    def test_zero_seconds_returns_none(self) -> None:
        assert parse_retry_after("Retry-After: 0", T0) is None

    def test_a_far_date_is_capped_at_seven_days(self) -> None:
        assert parse_retry_after("retry after 2027-06-01 00:00:00 UTC", T0) == T0 + MAX_RETRY_AFTER

    def test_a_large_number_of_seconds_is_capped_at_seven_days(self) -> None:
        assert parse_retry_after("Retry-After: 999999999", T0) == T0 + MAX_RETRY_AFTER

    def test_the_date_wins_when_both_forms_could_match(self) -> None:
        text = "retry after 2026-10-21 10:00:00 UTC (Retry-After: 60)"

        assert parse_retry_after(text, T0) == datetime(2026, 10, 21, 10, 0, tzinfo=UTC)


# --- failed-validation limiter ----------------------------------------------------------------


class TestValidationLimiter:
    def test_fewer_than_four_recent_failures_do_not_limit(self) -> None:
        failures = [T0 - 30 * MINUTE, T0 - 20 * MINUTE, T0 - 10 * MINUTE]

        assert limiter_not_before(failures, T0) is None

    def test_four_recent_failures_wait_until_the_oldest_ages_out(self) -> None:
        failures = [T0 - 50 * MINUTE, T0 - 40 * MINUTE, T0 - 30 * MINUTE, T0 - 10 * MINUTE]

        assert limiter_not_before(failures, T0) == failures[0] + VALIDATION_WINDOW

    def test_five_failures_wait_for_the_second_oldest(self) -> None:
        failures = [T0 - 55 * MINUTE, T0 - 50 * MINUTE, T0 - 30 * MINUTE, T0 - 20 * MINUTE, T0]

        # One more attempt is allowed once only three failures remain in the window.
        assert limiter_not_before(failures, T0) == failures[1] + VALIDATION_WINDOW

    def test_the_result_leaves_one_fewer_than_the_limit_in_the_window(self) -> None:
        failures = [T0 - 55 * MINUTE, T0 - 50 * MINUTE, T0 - 30 * MINUTE, T0 - 20 * MINUTE, T0]
        when = limiter_not_before(failures, T0)
        assert when is not None

        assert limiter_not_before(failures, when) is None
        assert limiter_not_before(failures, when - timedelta(seconds=1)) is not None

    def test_failures_older_than_an_hour_are_ignored(self) -> None:
        failures = [T0 - 3 * HOUR, T0 - 2 * HOUR, T0 - 90 * MINUTE, T0 - 61 * MINUTE, T0]

        assert limiter_not_before(failures, T0) is None

    def test_a_failure_exactly_an_hour_old_is_outside_the_window(self) -> None:
        failures = [T0 - HOUR, T0 - 30 * MINUTE, T0 - 20 * MINUTE, T0 - 10 * MINUTE]

        assert limiter_not_before(failures, T0) is None
        assert prune_validation_failures(failures, T0) == failures[1:]

    def test_the_input_order_does_not_matter(self) -> None:
        failures = [T0 - 10 * MINUTE, T0 - 50 * MINUTE, T0 - 30 * MINUTE, T0 - 40 * MINUTE]

        assert limiter_not_before(failures, T0) == T0 - 50 * MINUTE + VALIDATION_WINDOW

    def test_prune_returns_the_survivors_oldest_first(self) -> None:
        failures = [T0 - 5 * MINUTE, T0 - 2 * HOUR, T0 - 30 * MINUTE]

        assert prune_validation_failures(failures, T0) == [T0 - 30 * MINUTE, T0 - 5 * MINUTE]

    def test_the_store_limits_production_unauthorized_failures_to_four_per_hour(
        self, store: AcmeStateStore
    ) -> None:
        """Successes in between reset the backoff, so only the limiter can hold the fourth."""
        outcomes: list[FailureOutcome] = []
        for index in range(4):
            now = T0 + 2 * MINUTE * index * 2
            start_attempt(store, now)
            outcomes.append(
                store.record_failure(
                    CERT, now=now, error_class=AcmeErrorClass.UNAUTHORIZED, production=True
                )
            )
            if index < 3:
                store.record_success(CERT, now=now + MINUTE, next_attempt_at=None, installed=False)

        assert [o.next_attempt_at - (T0 + 4 * MINUTE * i) for i, o in enumerate(outcomes[:3])] == [
            INITIAL_BACKOFF
        ] * 3
        assert outcomes[3].next_attempt_at == T0 + VALIDATION_WINDOW

    def test_staging_failures_are_not_counted(self, store: AcmeStateStore) -> None:
        for index in range(5):
            now = T0 + 4 * MINUTE * index
            store.record_failure(
                CERT, now=now, error_class=AcmeErrorClass.UNAUTHORIZED, production=False
            )
            store.record_success(CERT, now=now + MINUTE, next_attempt_at=None, installed=False)

        assert store.get(CERT).validation_failures == []

    def test_other_failure_classes_are_not_counted_in_production(
        self, store: AcmeStateStore
    ) -> None:
        for index in range(5):
            store.record_failure(
                CERT,
                now=T0 + MINUTE * index,
                error_class=AcmeErrorClass.DNS_AUTH,
                production=True,
            )

        assert store.get(CERT).validation_failures == []

    def test_old_failures_leave_the_persisted_list(self, store: AcmeStateStore) -> None:
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.UNAUTHORIZED)
        later = T0 + 2 * HOUR

        store.record_failure(CERT, now=later, error_class=AcmeErrorClass.UNAUTHORIZED)

        assert store.get(CERT).validation_failures == [later]


# --- names_hash and bound_excerpt -------------------------------------------------------------


class TestNamesHash:
    def test_it_is_the_sha256_of_the_sorted_lowercase_names(self) -> None:
        expected = hashlib.sha256(b"a.example.com\nb.example.com").hexdigest()

        assert names_hash(["b.example.com", "a.example.com"]) == expected

    def test_order_does_not_matter(self) -> None:
        assert names_hash(["a.x", "b.x", "c.x"]) == names_hash(["c.x", "a.x", "b.x"])

    def test_case_and_surrounding_whitespace_do_not_matter(self) -> None:
        assert names_hash(["  A.Example.COM "]) == names_hash(["a.example.com"])

    def test_duplicates_collapse(self) -> None:
        assert names_hash(["a.x", "A.X", "a.x"]) == names_hash(["a.x"])

    def test_different_sets_differ(self) -> None:
        assert names_hash(["a.x"]) != names_hash(["a.x", "b.x"])
        assert names_hash(["*.x"]) != names_hash(["x"])

    def test_it_accepts_any_iterable(self) -> None:
        assert names_hash(n for n in ["a.x", "b.x"]) == names_hash(["a.x", "b.x"])

    def test_it_is_lowercase_hex_of_the_right_length(self) -> None:
        digest = names_hash(NAMES)

        assert len(digest) == 64
        assert digest == digest.lower()
        int(digest, 16)


class TestBoundExcerpt:
    def test_short_text_is_returned_with_whitespace_collapsed(self) -> None:
        assert bound_excerpt("a  b\n\n c\t d") == "a b c d"

    def test_long_text_is_truncated_with_an_ellipsis_to_the_limit(self) -> None:
        result = bound_excerpt("x" * 5000)

        assert len(result) == MAX_EXCERPT_CHARS == 512
        assert result.endswith("...")

    def test_text_at_the_limit_is_untouched(self) -> None:
        assert bound_excerpt("y" * 512) == "y" * 512

    def test_a_custom_limit_applies(self) -> None:
        assert bound_excerpt("abcdefghij", 6) == "abc..."

    def test_control_characters_become_spaces(self) -> None:
        result = bound_excerpt("a\x00b\x1b[31mc\x07d")

        assert "\x00" not in result
        assert "\x1b" not in result
        assert "\x07" not in result
        assert result.startswith("a b")

    def test_the_result_is_one_line(self) -> None:
        assert "\n" not in bound_excerpt("one\ntwo\r\nthree")

    def test_empty_text_stays_empty(self) -> None:
        assert bound_excerpt("") == ""
        assert bound_excerpt("   \n\t ") == ""


# --- loading ----------------------------------------------------------------------------------


class TestLoad:
    def test_a_missing_file_is_an_empty_state(self, store: AcmeStateStore) -> None:
        assert store.certificate_names() == []
        assert store.get(CERT).attempts == 0
        assert store.get(CERT).next_attempt_at is None
        assert store.has_installed(CERT) is False

    def test_loading_creates_neither_the_directory_nor_the_file(self, acme_dir: Path) -> None:
        AcmeStateStore(acme_dir)

        assert not acme_dir.exists()

    def test_a_missing_entry_reads_as_a_blank_state(self, store: AcmeStateStore) -> None:
        entry = store.get("never-seen")

        assert entry.names == []
        assert entry.error_code is None
        assert entry.consecutive_failures == 0
        assert entry.validation_failures == []

    def test_the_path_is_state_json_under_the_acme_directory(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        assert store.path == acme_dir / STATE_FILENAME == acme_dir / "state.json"

    def test_a_written_state_round_trips_through_a_new_store(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        store.record_failure(
            CERT, now=T0 + MINUTE, error_class=AcmeErrorClass.DNS_ZONE, excerpt="no zone"
        )
        before = store.get(CERT)

        again = AcmeStateStore(acme_dir)

        assert again.get(CERT) == before
        assert again.certificate_names() == [CERT]


CORRUPT_FILES: dict[str, bytes] = {
    "empty": b"",
    "not-json": b"{ this is not json",
    "truncated": b'{"version": 1, "certificates": {"wildcard": {"names": ["a"',
    "invalid-utf8": b"\xff\xfe\x00\x01 garbage",
    "json-list": b"[]",
    "json-string": b'"state"',
    "json-null": b"null",
    "no-version": b'{"certificates": {}}',
    "unknown-version": b'{"version": 2, "certificates": {}}',
    "string-version": b'{"version": "1", "certificates": {}}',
    "certificates-a-list": b'{"version": 1, "certificates": []}',
    "unknown-top-level-key": b'{"version": 1, "certificates": {}, "extra": true}',
    "unknown-entry-key": b'{"version": 1, "certificates": {"a": {"mystery": 1}}}',
    "negative-attempts": b'{"version": 1, "certificates": {"a": {"attempts": -1}}}',
    "naive-datetime": (
        b'{"version": 1, "certificates": {"a": {"last_attempt_at": "2026-10-20T12:00:00"}}}'
    ),
    "unknown-error-code": b'{"version": 1, "certificates": {"a": {"error_code": "exploded"}}}',
    "names-not-a-list": b'{"version": 1, "certificates": {"a": {"names": "x"}}}',
}


class TestUnusableFile:
    @pytest.mark.parametrize("case", list(CORRUPT_FILES))
    def test_an_unusable_file_raises_acme_state_error(self, acme_dir: Path, case: str) -> None:
        acme_dir.mkdir(parents=True)
        (acme_dir / STATE_FILENAME).write_bytes(CORRUPT_FILES[case])

        with pytest.raises(AcmeStateError) as excinfo:
            AcmeStateStore(acme_dir)

        assert str(acme_dir / STATE_FILENAME) in str(excinfo.value)

    @pytest.mark.parametrize("case", list(CORRUPT_FILES))
    def test_an_unusable_file_is_left_untouched(self, acme_dir: Path, case: str) -> None:
        acme_dir.mkdir(parents=True)
        path = acme_dir / STATE_FILENAME
        path.write_bytes(CORRUPT_FILES[case])

        with pytest.raises(AcmeStateError):
            AcmeStateStore(acme_dir)

        assert path.read_bytes() == CORRUPT_FILES[case]
        assert sorted(p.name for p in acme_dir.iterdir()) == [STATE_FILENAME]

    def test_the_message_for_invalid_json_says_how_to_recover(self, acme_dir: Path) -> None:
        acme_dir.mkdir(parents=True)
        (acme_dir / STATE_FILENAME).write_bytes(CORRUPT_FILES["not-json"])

        with pytest.raises(AcmeStateError, match="corrupt") as excinfo:
            AcmeStateStore(acme_dir)

        assert "Remove it" in str(excinfo.value)

    def test_the_message_for_an_unknown_version_names_both_versions(self, acme_dir: Path) -> None:
        acme_dir.mkdir(parents=True)
        (acme_dir / STATE_FILENAME).write_bytes(CORRUPT_FILES["unknown-version"])

        with pytest.raises(AcmeStateError, match="unknown version 2") as excinfo:
            AcmeStateStore(acme_dir)

        assert "understands 1" in str(excinfo.value)

    def test_the_message_for_a_wrong_shape_names_the_first_problem(self, acme_dir: Path) -> None:
        acme_dir.mkdir(parents=True)
        (acme_dir / STATE_FILENAME).write_bytes(CORRUPT_FILES["negative-attempts"])

        with pytest.raises(AcmeStateError, match="expected shape") as excinfo:
            AcmeStateStore(acme_dir)

        assert "attempts" in str(excinfo.value)

    def test_a_state_path_that_is_a_directory_cannot_be_read(self, acme_dir: Path) -> None:
        (acme_dir / STATE_FILENAME).mkdir(parents=True)

        with pytest.raises(AcmeStateError, match="cannot be read"):
            AcmeStateStore(acme_dir)

    def test_a_hand_edited_long_excerpt_is_rebounded_on_load(self, acme_dir: Path) -> None:
        acme_dir.mkdir(parents=True)
        document = {
            "version": 1,
            "certificates": {CERT: {"error_excerpt": "z" * 10_000, "error_code": "internal"}},
        }
        (acme_dir / STATE_FILENAME).write_text(json.dumps(document))

        excerpt = AcmeStateStore(acme_dir).get(CERT).error_excerpt

        assert excerpt is not None
        assert len(excerpt) == MAX_EXCERPT_CHARS

    def test_an_empty_certificates_document_is_valid(self, acme_dir: Path) -> None:
        acme_dir.mkdir(parents=True)
        (acme_dir / STATE_FILENAME).write_text('{"version": 1, "certificates": {}}')

        assert AcmeStateStore(acme_dir).certificate_names() == []


# --- persistence ------------------------------------------------------------------------------


class TestPersistence:
    def test_a_transition_writes_valid_versioned_json(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)

        document = read_doc(acme_dir / STATE_FILENAME)

        assert document["version"] == 1
        assert isinstance(document["certificates"], dict)
        assert list(document["certificates"]) == [CERT]  # type: ignore[arg-type]

    def test_the_file_is_pretty_printed_and_ends_with_a_newline(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)

        text = (acme_dir / STATE_FILENAME).read_text()

        assert text.endswith("}\n")
        assert "\n  " in text

    def test_datetimes_are_stored_timezone_aware(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)

        entry = read_doc(acme_dir / STATE_FILENAME)["certificates"][CERT]  # type: ignore[index]

        assert entry["last_attempt_at"].startswith("2026-10-20T12:00:00")
        assert entry["last_attempt_at"].endswith(("Z", "+00:00"))

    def test_no_temporary_file_is_left_behind(self, store: AcmeStateStore, acme_dir: Path) -> None:
        start_attempt(store)
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)
        store.record_request(CERT, now=T0)
        store.clear_backoff(CERT)
        store.prune([], now=T0)

        assert sorted(p.name for p in acme_dir.iterdir()) == [STATE_FILENAME]

    def test_the_first_write_creates_the_directory_tree(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "acme"

        start_attempt(AcmeStateStore(deep))

        assert (deep / STATE_FILENAME).is_file()

    def test_a_failed_replace_keeps_the_old_file_and_memory_in_agreement(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        start_attempt(store)
        path = acme_dir / STATE_FILENAME
        before_bytes = path.read_bytes()
        before = store.get(CERT)

        def boom(src: object, dst: object) -> None:
            raise OSError("disk on fire")

        monkeypatch.setattr(state_module.os, "replace", boom)

        with pytest.raises(OSError, match="disk on fire"):
            store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)

        assert path.read_bytes() == before_bytes
        assert store.get(CERT) == before
        assert sorted(p.name for p in acme_dir.iterdir()) == [STATE_FILENAME]

    def test_a_failed_first_write_leaves_no_file_and_no_entry(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(src: object, dst: object) -> None:
            raise OSError("no space")

        monkeypatch.setattr(state_module.os, "replace", boom)

        with pytest.raises(OSError):
            start_attempt(store)

        assert not (acme_dir / STATE_FILENAME).exists()
        assert store.certificate_names() == []
        assert store.get(CERT).attempts == 0

    def test_the_write_replaces_the_file_in_one_step(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The destination is only ever the old content or the complete new content."""
        start_attempt(store)
        path = acme_dir / STATE_FILENAME
        seen: list[dict[str, object]] = []
        real_replace = os.replace

        def spy(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            seen.append(
                {"dst_before": read_doc(Path(dst)), "src": json.loads(Path(src).read_text())}
            )
            real_replace(src, dst)

        monkeypatch.setattr(state_module.os, "replace", spy)

        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)

        (call,) = seen
        assert call["dst_before"]["certificates"][CERT]["error_code"] is None  # type: ignore[index]
        assert call["src"]["certificates"][CERT]["error_code"] == "internal"  # type: ignore[index]
        assert read_doc(path)["certificates"][CERT]["error_code"] == "internal"  # type: ignore[index]

    @posix_perms
    def test_the_directory_is_0700_and_the_file_0600(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)

        assert stat.S_IMODE(acme_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((acme_dir / STATE_FILENAME).stat().st_mode) == 0o600

    @posix_perms
    def test_the_modes_hold_under_a_permissive_umask(self, acme_dir: Path) -> None:
        previous = os.umask(0)
        try:
            start_attempt(AcmeStateStore(acme_dir))
        finally:
            os.umask(previous)

        assert stat.S_IMODE(acme_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((acme_dir / STATE_FILENAME).stat().st_mode) == 0o600

    @posix_perms
    def test_a_loose_existing_directory_is_tightened_on_write(self, acme_dir: Path) -> None:
        acme_dir.mkdir(parents=True)
        acme_dir.chmod(0o755)

        start_attempt(AcmeStateStore(acme_dir))

        assert stat.S_IMODE(acme_dir.stat().st_mode) == 0o700

    @posix_perms
    def test_a_loose_existing_file_is_replaced_by_a_0600_file(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        (acme_dir / STATE_FILENAME).chmod(0o644)

        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)

        assert stat.S_IMODE((acme_dir / STATE_FILENAME).stat().st_mode) == 0o600


# --- queries ----------------------------------------------------------------------------------


class TestQueries:
    def test_get_returns_a_copy(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        entry = store.get(CERT)

        entry.attempts = 99
        entry.names.append("tampered.example")

        assert store.get(CERT).attempts == 1
        assert store.get(CERT).names == NAMES

    def test_certificate_names_are_sorted(self, store: AcmeStateStore) -> None:
        for name in ("zeta", "alpha", "mid"):
            start_attempt(store, name=name)

        assert store.certificate_names() == ["alpha", "mid", "zeta"]

    def test_has_installed_follows_a_recorded_install(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        assert store.has_installed(CERT) is False

        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )

        assert store.has_installed(CERT) is True
        assert store.has_installed("other") is False

    def test_names_changed_is_false_before_anything_is_installed(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store)

        assert store.names_changed(CERT, ["something-else.example.com"]) is False
        assert store.names_changed("never-seen", NAMES) is False

    def test_names_changed_compares_with_the_installed_names(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )

        assert store.names_changed(CERT, NAMES) is False
        assert store.names_changed(CERT, ["*.EXAMPLE.com"]) is False
        assert store.names_changed(CERT, [*NAMES, "example.com"]) is True
        assert store.names_changed(CERT, ["*.other.example"]) is True

    def test_names_changed_ignores_names_of_a_later_uninstalled_attempt(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )
        start_attempt(store, T0 + HOUR, names=["new.example.com"])
        store.record_failure(CERT, now=T0 + HOUR, error_class=AcmeErrorClass.INTERNAL)

        assert store.names_changed(CERT, NAMES) is False
        assert store.names_changed(CERT, ["new.example.com"]) is True


class TestIsNewMaterial:
    def installed(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.record_success(
            CERT,
            now=T0,
            next_attempt_at=None,
            installed=True,
            serial="0a1b2c",
            fingerprint="deadbeef",
        )

    def test_everything_is_new_when_nothing_is_installed(self, store: AcmeStateStore) -> None:
        assert store.is_new_material(CERT, serial="1", fingerprint="2") is True

    def test_an_attempt_without_an_install_is_still_new(self, store: AcmeStateStore) -> None:
        start_attempt(store)

        assert store.is_new_material(CERT, serial="1", fingerprint="2") is True

    def test_the_installed_serial_and_fingerprint_are_not_new(self, store: AcmeStateStore) -> None:
        self.installed(store)

        assert store.is_new_material(CERT, serial="0a1b2c", fingerprint="deadbeef") is False

    def test_the_comparison_is_case_insensitive(self, store: AcmeStateStore) -> None:
        self.installed(store)

        assert store.is_new_material(CERT, serial="0A1B2C", fingerprint="DEADBEEF") is False

    def test_a_different_serial_is_new(self, store: AcmeStateStore) -> None:
        self.installed(store)

        assert store.is_new_material(CERT, serial="0a1b2d", fingerprint="deadbeef") is True

    def test_a_different_fingerprint_is_new(self, store: AcmeStateStore) -> None:
        self.installed(store)

        assert store.is_new_material(CERT, serial="0a1b2c", fingerprint="deadbeee") is True

    def test_another_certificate_is_not_compared_with_this_one(self, store: AcmeStateStore) -> None:
        self.installed(store)

        assert store.is_new_material("other", serial="0a1b2c", fingerprint="deadbeef") is True

    def test_a_not_installed_success_keeps_the_recorded_identity(
        self, store: AcmeStateStore
    ) -> None:
        self.installed(store)

        store.record_success(CERT, now=T0 + HOUR, next_attempt_at=None, installed=False)

        assert store.is_new_material(CERT, serial="0a1b2c", fingerprint="deadbeef") is False
        assert store.is_new_material(CERT, serial="ffff", fingerprint="deadbeef") is True


# --- transitions ------------------------------------------------------------------------------


class TestAttemptStart:
    def test_it_records_the_attempt_and_arms_the_crash_guard(self, store: AcmeStateStore) -> None:
        entry = store.record_attempt_start(
            CERT, now=T0, names=NAMES, directory=DIRECTORY, reason="missing"
        )

        assert entry.attempts == 1
        assert entry.last_attempt_at == T0
        assert entry.names == NAMES
        assert entry.directory == DIRECTORY
        assert entry.renewal_reason == "missing"
        assert entry.next_attempt_at == T0 + INITIAL_BACKOFF

    def test_each_start_counts_an_attempt(self, store: AcmeStateStore) -> None:
        for index in range(3):
            start_attempt(store, T0 + HOUR * index)

        assert store.get(CERT).attempts == 3

    def test_the_guard_is_persisted_before_any_outcome(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        """A crash mid-run leaves this file; the next process must wait, not re-run at once."""
        start_attempt(store)

        recovered = AcmeStateStore(acme_dir).get(CERT)

        assert recovered.next_attempt_at == T0 + INITIAL_BACKOFF
        assert recovered.last_attempt_at == T0
        assert recovered.last_success_at is None
        assert recovered.error_code is None

    def test_the_guard_is_the_initial_backoff_with_no_failure_counted(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store, T0 + HOUR)

        entry = store.get(CERT)

        assert entry.next_attempt_at == T0 + HOUR + INITIAL_BACKOFF
        assert entry.consecutive_failures == 0

    def test_the_removed_backoff_queries_are_gone(self, store: AcmeStateStore) -> None:
        """Whether an entry is held back is the runner's call (it knows failure from schedule)."""
        assert not hasattr(store, "in_backoff")
        assert not hasattr(store, "backoff_until")

    def test_the_guard_does_not_erase_the_previous_failure(self, store: AcmeStateStore) -> None:
        store.record_failure(
            CERT, now=T0, error_class=AcmeErrorClass.DNS_AUTH, excerpt="403 from Cloudflare"
        )

        start_attempt(store, T0 + HOUR)

        entry = store.get(CERT)
        assert entry.consecutive_failures == 1
        assert entry.error_code is AcmeErrorClass.DNS_AUTH
        assert entry.error_excerpt == "403 from Cloudflare"

    def test_the_guard_leaves_the_installed_identity_alone(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )

        start_attempt(store, T0 + HOUR, names=["other.example.com"])

        entry = store.get(CERT)
        assert entry.installed_serial == "ab"
        assert entry.installed_fingerprint == "cd"
        assert entry.issued_names_hash == names_hash(NAMES)

    def test_entries_are_independent_per_certificate(self, store: AcmeStateStore) -> None:
        start_attempt(store, name="one")
        start_attempt(store, T0 + HOUR, name="two", names=["two.example.com"])

        assert store.get("one").names == NAMES
        assert store.get("two").names == ["two.example.com"]
        assert store.get("one").attempts == store.get("two").attempts == 1


class TestRecordSuccess:
    def test_an_install_records_identity_names_hash_and_clears_failures(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store)
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.TIMEOUT, excerpt="slow")
        next_check = T0 + 12 * HOUR

        entry = store.record_success(
            CERT,
            now=T0 + HOUR,
            next_attempt_at=next_check,
            installed=True,
            serial="0a",
            fingerprint="ff",
        )

        assert entry.installed_serial == "0a"
        assert entry.installed_fingerprint == "ff"
        assert entry.installed_at == T0 + HOUR
        assert entry.issued_names_hash == names_hash(NAMES)
        assert entry.last_success_at == T0 + HOUR
        assert entry.next_attempt_at == next_check
        assert entry.consecutive_failures == 0
        assert entry.error_code is None
        assert entry.error_excerpt is None
        assert entry.retry_after is None

    def test_an_install_without_serial_or_fingerprint_is_a_value_error_and_writes_nothing(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        with pytest.raises(ValueError, match="serial and fingerprint"):
            store.record_success(CERT, now=T0, next_attempt_at=None, installed=True)
        with pytest.raises(ValueError, match="serial and fingerprint"):
            store.record_success(CERT, now=T0, next_attempt_at=None, installed=True, serial="ab")

        assert not (acme_dir / STATE_FILENAME).exists()
        assert store.certificate_names() == []

    def test_a_clean_exit_without_an_install_keeps_the_installed_fields(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )
        start_attempt(store, T0 + HOUR, names=["changed.example.com"])

        entry = store.record_success(CERT, now=T0 + 2 * HOUR, next_attempt_at=None, installed=False)

        assert entry.installed_serial == "ab"
        assert entry.installed_fingerprint == "cd"
        assert entry.installed_at == T0
        assert entry.issued_names_hash == names_hash(NAMES)
        assert entry.last_success_at == T0 + 2 * HOUR

    def test_none_as_the_next_attempt_clears_the_limit(self, store: AcmeStateStore) -> None:
        start_attempt(store)

        store.record_success(CERT, now=T0, next_attempt_at=None, installed=False)

        assert store.get(CERT).next_attempt_at is None

    def test_a_scheduled_check_is_stored_without_any_failure_state(
        self, store: AcmeStateStore
    ) -> None:
        """After a success ``next_attempt_at`` is the next check, not a failure backoff."""
        start_attempt(store)
        store.record_success(CERT, now=T0, next_attempt_at=T0 + 12 * HOUR, installed=False)

        entry = store.get(CERT)
        assert entry.next_attempt_at == T0 + 12 * HOUR
        assert entry.consecutive_failures == 0
        assert entry.error_code is None

    def test_old_validation_failures_are_pruned_and_recent_ones_kept(
        self, store: AcmeStateStore
    ) -> None:
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.UNAUTHORIZED)
        store.record_failure(CERT, now=T0 + 90 * MINUTE, error_class=AcmeErrorClass.UNAUTHORIZED)

        store.record_success(CERT, now=T0 + 100 * MINUTE, next_attempt_at=None, installed=False)

        assert store.get(CERT).validation_failures == [T0 + 90 * MINUTE]


class TestRecordFailure:
    def test_failures_back_off_by_doubling_and_cap_at_a_day(self, store: AcmeStateStore) -> None:
        expected_hours = [0.25, 0.5, 1, 2, 4, 8, 16, 24, 24, 24]
        now = T0
        for count, hours in enumerate(expected_hours, start=1):
            outcome = store.record_failure(CERT, now=now, error_class=AcmeErrorClass.INTERNAL)

            assert outcome.consecutive_failures == count
            assert outcome.next_attempt_at == now + timedelta(hours=hours)
            assert store.get(CERT).next_attempt_at == outcome.next_attempt_at
            now = outcome.next_attempt_at

    def test_a_success_resets_the_doubling(self, store: AcmeStateStore) -> None:
        for step in range(3):
            store.record_failure(CERT, now=T0 + HOUR * step, error_class=AcmeErrorClass.INTERNAL)
        store.record_success(CERT, now=T0 + 4 * HOUR, next_attempt_at=None, installed=False)

        outcome = store.record_failure(CERT, now=T0 + 5 * HOUR, error_class=AcmeErrorClass.INTERNAL)

        assert outcome.consecutive_failures == 1
        assert outcome.next_attempt_at == T0 + 5 * HOUR + INITIAL_BACKOFF

    def test_it_records_the_class_and_a_bounded_excerpt(self, store: AcmeStateStore) -> None:
        store.record_failure(
            CERT, now=T0, error_class=AcmeErrorClass.ACME_UNREACHABLE, excerpt="q" * 9000
        )

        entry = store.get(CERT)
        assert entry.error_code is AcmeErrorClass.ACME_UNREACHABLE
        assert entry.error_excerpt is not None
        assert len(entry.error_excerpt) == MAX_EXCERPT_CHARS

    def test_an_empty_excerpt_is_stored_as_none(self, store: AcmeStateStore) -> None:
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL, excerpt="  \n ")

        assert store.get(CERT).error_excerpt is None

    def test_a_multiline_excerpt_is_stored_on_one_line(self, store: AcmeStateStore) -> None:
        store.record_failure(
            CERT, now=T0, error_class=AcmeErrorClass.INTERNAL, excerpt="line one\nline two"
        )

        assert store.get(CERT).error_excerpt == "line one line two"

    def test_a_rate_limit_stores_the_effective_retry_after(self, store: AcmeStateStore) -> None:
        retry = T0 + 5 * HOUR

        outcome = store.record_failure(
            CERT, now=T0, error_class=AcmeErrorClass.RATE_LIMITED, retry_after=retry
        )

        assert outcome.next_attempt_at == retry
        assert outcome.retry_after == retry
        assert store.get(CERT).retry_after == retry

    def test_a_rate_limit_without_a_hint_waits_the_floor(self, store: AcmeStateStore) -> None:
        outcome = store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.RATE_LIMITED)

        assert outcome.next_attempt_at == T0 + HOUR
        assert outcome.retry_after == T0 + HOUR

    def test_a_rate_limit_hint_beyond_a_week_is_capped(self, store: AcmeStateStore) -> None:
        outcome = store.record_failure(
            CERT,
            now=T0,
            error_class=AcmeErrorClass.RATE_LIMITED,
            retry_after=T0 + timedelta(days=60),
        )

        assert outcome.next_attempt_at == T0 + MAX_RETRY_AFTER

    def test_other_classes_store_no_retry_after(self, store: AcmeStateStore) -> None:
        outcome = store.record_failure(
            CERT, now=T0, error_class=AcmeErrorClass.DNS_AUTH, retry_after=T0 + 5 * HOUR
        )

        assert outcome.retry_after is None
        assert store.get(CERT).retry_after is None
        assert outcome.next_attempt_at == T0 + INITIAL_BACKOFF

    def test_a_later_non_rate_limit_failure_clears_the_stored_retry_after(
        self, store: AcmeStateStore
    ) -> None:
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.RATE_LIMITED)

        store.record_failure(CERT, now=T0 + 2 * HOUR, error_class=AcmeErrorClass.DNS_AUTH)

        assert store.get(CERT).retry_after is None

    def test_a_success_clears_the_stored_retry_after(self, store: AcmeStateStore) -> None:
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.RATE_LIMITED)

        store.record_success(CERT, now=T0 + 2 * HOUR, next_attempt_at=None, installed=False)

        assert store.get(CERT).retry_after is None

    def test_the_outcome_is_frozen_and_describes_the_decision(self, store: AcmeStateStore) -> None:
        outcome = store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.CONFIG)

        assert outcome.error_class is AcmeErrorClass.CONFIG
        assert outcome.consecutive_failures == 1
        with pytest.raises(ValueError, match="frozen"):
            outcome.consecutive_failures = 5  # type: ignore[misc]

    def test_a_failure_never_touches_the_installed_material_fields(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )
        before = store.get(CERT)

        store.record_failure(CERT, now=T0 + HOUR, error_class=AcmeErrorClass.INVALID_OUTPUT)

        entry = store.get(CERT)
        assert entry.installed_serial == before.installed_serial
        assert entry.installed_fingerprint == before.installed_fingerprint
        assert entry.installed_at == before.installed_at
        assert entry.issued_names_hash == before.issued_names_hash
        assert entry.last_success_at == before.last_success_at

    def test_the_failure_log_event_carries_no_excerpt(self, store: AcmeStateStore) -> None:
        with structlog.testing.capture_logs() as logs:
            store.record_failure(
                CERT,
                now=T0,
                error_class=AcmeErrorClass.DNS_AUTH,
                excerpt="Authorization: Bearer hunter2",
            )

        (event,) = [e for e in logs if e["event"] == "acme.state.failure_recorded"]
        assert event["certificate"] == CERT
        assert event["error_code"] == "dns_auth"
        assert event["consecutive_failures"] == 1
        assert event["next_attempt_at"] == (T0 + INITIAL_BACKOFF).isoformat()
        assert "hunter2" not in json.dumps(logs, default=str)
        assert "excerpt" not in event


# --- request and clear_backoff --------------------------------------------------------------


class TestRecordRequest:
    def test_it_stamps_the_last_request_and_persists_it(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)

        store.record_request(CERT, now=T0 + MINUTE)

        assert store.get(CERT).last_request_at == T0 + MINUTE
        assert AcmeStateStore(acme_dir).get(CERT).last_request_at == T0 + MINUTE

    def test_a_later_request_replaces_the_stamp(self, store: AcmeStateStore) -> None:
        store.record_request(CERT, now=T0)
        store.record_request(CERT, now=T0 + HOUR)

        assert store.get(CERT).last_request_at == T0 + HOUR

    def test_it_creates_the_entry_when_none_exists(self, store: AcmeStateStore) -> None:
        store.record_request("fresh", now=T0)

        assert store.certificate_names() == ["fresh"]
        assert store.get("fresh").attempts == 0

    def test_it_leaves_every_other_field_alone(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.DNS_AUTH, excerpt="403")
        before = store.get(CERT)

        store.record_request(CERT, now=T0 + MINUTE)

        after = store.get(CERT)
        assert after.model_copy(update={"last_request_at": None}) == before

    def test_a_success_and_a_failure_keep_the_stamp(self, store: AcmeStateStore) -> None:
        """The 60 s request floor must survive the attempt its request started."""
        store.record_request(CERT, now=T0)
        start_attempt(store, T0 + MINUTE)
        store.record_failure(CERT, now=T0 + MINUTE, error_class=AcmeErrorClass.INTERNAL)
        store.record_success(CERT, now=T0 + HOUR, next_attempt_at=None, installed=False)

        assert store.get(CERT).last_request_at == T0

    def test_a_blank_entry_has_no_request(self, store: AcmeStateStore) -> None:
        assert store.get("never-seen").last_request_at is None


class TestClearBackoff:
    def failing(self, store: AcmeStateStore, error_class: AcmeErrorClass) -> None:
        start_attempt(store)
        store.record_failure(CERT, now=T0, error_class=error_class, excerpt="the failure")

    def test_it_clears_the_failure_backoff_and_reports_a_change(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        self.failing(store, AcmeErrorClass.DNS_AUTH)
        store.record_failure(CERT, now=T0 + HOUR, error_class=AcmeErrorClass.DNS_AUTH)

        changed = store.clear_backoff(CERT)

        entry = store.get(CERT)
        assert changed is True
        assert entry.consecutive_failures == 0
        assert entry.next_attempt_at is None
        assert entry.retry_after is None
        persisted = AcmeStateStore(acme_dir).get(CERT)
        assert persisted.consecutive_failures == 0
        assert persisted.next_attempt_at is None

    def test_the_error_class_and_excerpt_stay_until_the_next_attempt_replaces_them(
        self, store: AcmeStateStore
    ) -> None:
        self.failing(store, AcmeErrorClass.DNS_ZONE)

        store.clear_backoff(CERT)

        entry = store.get(CERT)
        assert entry.error_code is AcmeErrorClass.DNS_ZONE
        assert entry.error_excerpt == "the failure"

    def test_the_failed_validation_window_stays_so_the_ca_limit_is_still_respected(
        self, store: AcmeStateStore
    ) -> None:
        for step in range(3):
            store.record_failure(
                CERT, now=T0 + MINUTE * step, error_class=AcmeErrorClass.UNAUTHORIZED
            )

        store.clear_backoff(CERT)

        assert store.get(CERT).validation_failures == [T0, T0 + MINUTE, T0 + 2 * MINUTE]

    def test_the_installed_identity_and_the_request_stamp_stay(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )
        store.record_request(CERT, now=T0 + MINUTE)
        store.record_failure(CERT, now=T0 + HOUR, error_class=AcmeErrorClass.CONFIG)

        store.clear_backoff(CERT)

        entry = store.get(CERT)
        assert entry.installed_serial == "ab"
        assert entry.installed_fingerprint == "cd"
        assert entry.issued_names_hash == names_hash(NAMES)
        assert entry.last_request_at == T0 + MINUTE
        assert entry.attempts == 1

    def test_a_rate_limit_retry_after_is_cleared_too(self, store: AcmeStateStore) -> None:
        store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.RATE_LIMITED)
        assert store.get(CERT).retry_after is not None

        store.clear_backoff(CERT)

        assert store.get(CERT).retry_after is None

    def test_the_next_failure_after_a_clear_starts_the_doubling_over(
        self, store: AcmeStateStore
    ) -> None:
        for step in range(4):
            store.record_failure(
                CERT, now=T0 + HOUR * step, error_class=AcmeErrorClass.DNS_AUTH
            )

        store.clear_backoff(CERT)
        outcome = store.record_failure(
            CERT, now=T0 + 10 * HOUR, error_class=AcmeErrorClass.DNS_AUTH
        )

        assert outcome.consecutive_failures == 1
        assert outcome.next_attempt_at == T0 + 10 * HOUR + INITIAL_BACKOFF

    def test_an_unknown_certificate_is_not_a_change_and_writes_nothing(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        assert store.clear_backoff("never-seen") is False

        assert not (acme_dir / STATE_FILENAME).exists()
        assert store.certificate_names() == []

    def test_an_entry_with_nothing_to_clear_is_not_a_change_and_writes_nothing(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        store.record_success(CERT, now=T0, next_attempt_at=None, installed=False)
        before = (acme_dir / STATE_FILENAME).read_bytes()

        assert store.clear_backoff(CERT) is False

        assert (acme_dir / STATE_FILENAME).read_bytes() == before

    def test_a_scheduled_check_counts_as_something_to_clear(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.record_success(CERT, now=T0, next_attempt_at=T0 + 12 * HOUR, installed=False)

        assert store.clear_backoff(CERT) is True
        assert store.get(CERT).next_attempt_at is None

    def test_clearing_twice_changes_nothing_the_second_time(self, store: AcmeStateStore) -> None:
        self.failing(store, AcmeErrorClass.CONFIG)

        assert store.clear_backoff(CERT) is True
        assert store.clear_backoff(CERT) is False

    def test_a_failed_write_keeps_the_backoff_in_memory(
        self, store: AcmeStateStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.failing(store, AcmeErrorClass.DNS_AUTH)
        before = store.get(CERT)

        def boom(src: object, dst: object) -> None:
            raise OSError("read-only file system")

        monkeypatch.setattr(state_module.os, "replace", boom)

        with pytest.raises(OSError):
            store.clear_backoff(CERT)

        assert store.get(CERT) == before


# --- prune ------------------------------------------------------------------------------------


class TestPrune:
    def test_an_undeclared_entry_is_marked_not_deleted_and_its_name_returned(
        self, store: AcmeStateStore
    ) -> None:
        for name in ("keep", "gone-b", "gone-a"):
            start_attempt(store, name=name)

        retired = store.prune(["keep"], now=T0 + HOUR)

        assert retired == ["gone-a", "gone-b"]
        assert store.get("gone-a").pruned_at == T0 + HOUR
        assert store.get("gone-b").attempts == 1, "history is kept"
        assert store.get("keep").pruned_at is None

    def test_a_pruned_entry_is_not_listed_as_a_certificate(self, store: AcmeStateStore) -> None:
        for name in ("keep", "gone"):
            start_attempt(store, name=name)

        store.prune(["keep"], now=T0)

        assert store.certificate_names() == ["keep"]

    def test_the_mark_is_persisted(self, store: AcmeStateStore, acme_dir: Path) -> None:
        start_attempt(store, name="keep")
        start_attempt(store, name="gone")

        store.prune(["keep"], now=T0 + HOUR)

        reloaded = AcmeStateStore(acme_dir)
        assert reloaded.certificate_names() == ["keep"]
        gone = read_doc(acme_dir / STATE_FILENAME)["certificates"]["gone"]  # type: ignore[index]
        assert gone["pruned_at"].startswith("2026-10-20T13:00:00")

    def test_an_entry_is_kept_until_seven_days_after_it_was_marked(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        store.prune([], now=T0)
        almost = T0 + PRUNE_RETENTION - timedelta(seconds=1)

        assert timedelta(days=7) == PRUNE_RETENTION
        assert store.prune([], now=almost) == []
        assert CERT in read_doc(acme_dir / STATE_FILENAME)["certificates"]  # type: ignore[operator]

        assert store.prune([], now=T0 + PRUNE_RETENTION) == [CERT]
        assert read_doc(acme_dir / STATE_FILENAME)["certificates"] == {}

    def test_a_later_prune_does_not_extend_the_retention(self, store: AcmeStateStore) -> None:
        start_attempt(store)
        store.prune([], now=T0)

        store.prune([], now=T0 + 3 * HOUR)

        assert store.get(CERT).pruned_at == T0

    def test_redeclaring_a_pruned_certificate_restores_it_with_its_history(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        store.record_success(
            CERT, now=T0, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )
        store.prune([], now=T0 + HOUR)

        retired = store.prune([CERT], now=T0 + 2 * HOUR)

        assert retired == [], "a restore is not a retirement"
        entry = store.get(CERT)
        assert entry.pruned_at is None
        assert entry.installed_serial == "ab"
        assert entry.attempts == 1
        assert store.certificate_names() == [CERT]
        assert AcmeStateStore(acme_dir).get(CERT).pruned_at is None

    def test_a_restored_certificate_is_not_deleted_by_a_later_prune(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store)
        store.prune([], now=T0)
        store.prune([CERT], now=T0 + HOUR)

        store.prune([CERT], now=T0 + 30 * 24 * HOUR)

        assert store.certificate_names() == [CERT]

    def test_marking_one_and_deleting_another_returns_both_sorted(
        self, store: AcmeStateStore
    ) -> None:
        start_attempt(store, name="old")
        store.prune([], now=T0)
        start_attempt(store, name="fresh")

        result = store.prune([], now=T0 + PRUNE_RETENTION)

        assert result == ["fresh", "old"]
        assert store.get("old").attempts == 0, "deleted"
        assert store.get("fresh").pruned_at == T0 + PRUNE_RETENTION

    def test_declared_names_without_an_entry_are_ignored(self, store: AcmeStateStore) -> None:
        start_attempt(store, name="keep")

        assert store.prune(["keep", "never-seen"], now=T0) == []
        assert store.certificate_names() == ["keep"]

    def test_nothing_to_change_does_not_write(self, store: AcmeStateStore, acme_dir: Path) -> None:
        assert store.prune(["anything"], now=T0) == []

        assert not (acme_dir / STATE_FILENAME).exists()

    def test_nothing_to_change_leaves_an_existing_file_byte_identical(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        before = (acme_dir / STATE_FILENAME).read_bytes()

        store.prune([CERT], now=T0)

        assert (acme_dir / STATE_FILENAME).read_bytes() == before

    def test_an_already_marked_entry_inside_the_retention_does_not_rewrite_the_file(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)
        store.prune([], now=T0)
        before = (acme_dir / STATE_FILENAME).read_bytes()

        store.prune([], now=T0 + HOUR)

        assert (acme_dir / STATE_FILENAME).read_bytes() == before

    def test_pruning_everything_leaves_a_valid_document_with_the_entries_marked(
        self, store: AcmeStateStore, acme_dir: Path
    ) -> None:
        start_attempt(store)

        store.prune([], now=T0)

        document = read_doc(acme_dir / STATE_FILENAME)
        assert document["version"] == 1
        assert list(document["certificates"]) == [CERT]  # type: ignore[arg-type]
        assert AcmeStateStore(acme_dir).get(CERT).pruned_at == T0

    def test_a_failed_write_keeps_the_entries_unmarked_in_memory(
        self, store: AcmeStateStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        start_attempt(store)

        def boom(src: object, dst: object) -> None:
            raise OSError("read-only file system")

        monkeypatch.setattr(state_module.os, "replace", boom)

        with pytest.raises(OSError):
            store.prune([], now=T0)

        assert store.certificate_names() == [CERT]
        assert store.get(CERT).pruned_at is None

    def test_a_declared_set_may_be_a_generator(self, store: AcmeStateStore) -> None:
        start_attempt(store, name="keep")
        start_attempt(store, name="gone")

        assert store.prune((n for n in ["keep"]), now=T0) == ["gone"]

    def test_now_is_keyword_only(self, store: AcmeStateStore) -> None:
        with pytest.raises(TypeError):
            store.prune([], T0)  # type: ignore[misc]


# --- fields absent from older state files ---------------------------------------------------


class TestNewFields:
    def test_both_default_to_none(self, store: AcmeStateStore) -> None:
        entry = store.get("never-seen")

        assert entry.last_request_at is None
        assert entry.pruned_at is None

    def test_a_file_without_them_loads_with_the_defaults(self, acme_dir: Path) -> None:
        """A state file from before the fields existed stays valid."""
        acme_dir.mkdir(parents=True)
        document = {"version": 1, "certificates": {CERT: {"attempts": 2}}}
        (acme_dir / STATE_FILENAME).write_text(json.dumps(document))

        entry = AcmeStateStore(acme_dir).get(CERT)

        assert entry.attempts == 2
        assert entry.last_request_at is None
        assert entry.pruned_at is None

    @pytest.mark.parametrize("key", ["last_request_at", "pruned_at"])
    def test_a_naive_datetime_is_refused(self, acme_dir: Path, key: str) -> None:
        acme_dir.mkdir(parents=True)
        document = {"version": 1, "certificates": {CERT: {key: "2026-10-20T12:00:00"}}}
        (acme_dir / STATE_FILENAME).write_text(json.dumps(document))

        with pytest.raises(AcmeStateError, match=key):
            AcmeStateStore(acme_dir)

    def test_both_round_trip(self, store: AcmeStateStore, acme_dir: Path) -> None:
        store.record_request(CERT, now=T0)
        store.prune([], now=T0 + HOUR)

        entry = AcmeStateStore(acme_dir).get(CERT)

        assert entry.last_request_at == T0
        assert entry.pruned_at == T0 + HOUR


# --- durability: fsync and directory permissions -------------------------------------------------


class TestBestEffortDurability:
    def test_a_failing_directory_fsync_does_not_fail_the_write(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(path: Path) -> None:
            raise OSError("fsync of a directory is not supported here")

        monkeypatch.setattr(state_module, "_fsync_dir", boom)

        start_attempt(store)

        assert read_doc(acme_dir / STATE_FILENAME)["certificates"][CERT]["attempts"] == 1  # type: ignore[index]

    def test_memory_adopts_the_document_once_the_rename_happened(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The file is renamed into place; a durability-only failure afterwards must not leave
        memory behind the file."""

        def boom(path: Path) -> None:
            raise OSError("no dir fsync")

        monkeypatch.setattr(state_module, "_fsync_dir", boom)

        start_attempt(store)

        assert store.get(CERT).attempts == 1
        assert AcmeStateStore(acme_dir).get(CERT).attempts == 1

    def test_a_failing_directory_fsync_is_logged_once_per_store(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(path: Path) -> None:
            raise OSError("no dir fsync")

        monkeypatch.setattr(state_module, "_fsync_dir", boom)

        with structlog.testing.capture_logs() as logs:
            start_attempt(store)
            store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)
            store.record_request(CERT, now=T0)

        (event,) = [e for e in logs if e["event"] == "acme.state.fsync_dir_failed"]
        assert event["directory"] == os.fspath(acme_dir)
        assert "no dir fsync" in event["error"]
        assert event["log_level"] == "warning"

    def test_another_store_warns_for_itself(
        self, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(path: Path) -> None:
            raise OSError("no dir fsync")

        monkeypatch.setattr(state_module, "_fsync_dir", boom)

        with structlog.testing.capture_logs() as logs:
            start_attempt(AcmeStateStore(acme_dir))
            start_attempt(AcmeStateStore(acme_dir), T0 + HOUR)

        assert len([e for e in logs if e["event"] == "acme.state.fsync_dir_failed"]) == 2

    def test_the_directory_fsync_itself_never_raises_for_a_real_directory(
        self, tmp_path: Path
    ) -> None:
        state_module._fsync_dir(tmp_path)

    def test_a_failing_file_fsync_still_fails_the_write_and_leaves_memory_alone(
        self, store: AcmeStateStore, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        start_attempt(store)
        path = acme_dir / STATE_FILENAME
        before_bytes = path.read_bytes()
        before = store.get(CERT)

        def boom(fd: int) -> None:
            raise OSError("disk on fire")

        monkeypatch.setattr(state_module.os, "fsync", boom)

        with pytest.raises(OSError, match="disk on fire"):
            store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)

        assert path.read_bytes() == before_bytes
        assert store.get(CERT) == before
        assert sorted(p.name for p in acme_dir.iterdir()) == [STATE_FILENAME]

    @posix_perms
    def test_a_directory_that_cannot_be_restricted_is_warned_about_once_and_still_written(
        self, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_chmod = os.chmod

        def selective(path: str | os.PathLike[str], mode: int, **kwargs: object) -> None:
            if Path(path) == acme_dir:
                raise PermissionError("operation not permitted")
            real_chmod(path, mode, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(state_module.os, "chmod", selective)
        store = AcmeStateStore(acme_dir)

        with structlog.testing.capture_logs() as logs:
            start_attempt(store)
            store.record_failure(CERT, now=T0, error_class=AcmeErrorClass.INTERNAL)
            store.record_request(CERT, now=T0)

        (event,) = [e for e in logs if e["event"] == "acme.state.chmod_dir_failed"]
        assert event["directory"] == os.fspath(acme_dir)
        assert "operation not permitted" in event["error"]
        assert store.get(CERT).attempts == 1
        assert AcmeStateStore(acme_dir).get(CERT).last_request_at == T0

    @posix_perms
    def test_the_two_best_effort_warnings_are_independent(
        self, acme_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_chmod = os.chmod

        def selective(path: str | os.PathLike[str], mode: int, **kwargs: object) -> None:
            if Path(path) == acme_dir:
                raise PermissionError("nope")
            real_chmod(path, mode, **kwargs)  # type: ignore[arg-type]

        def no_fsync_dir(path: Path) -> None:
            raise OSError("no dir fsync")

        monkeypatch.setattr(state_module.os, "chmod", selective)
        monkeypatch.setattr(state_module, "_fsync_dir", no_fsync_dir)
        store = AcmeStateStore(acme_dir)

        with structlog.testing.capture_logs() as logs:
            start_attempt(store)
            store.record_request(CERT, now=T0)

        events = sorted(e["event"] for e in logs if str(e["event"]).startswith("acme.state."))
        assert events == ["acme.state.chmod_dir_failed", "acme.state.fsync_dir_failed"]
