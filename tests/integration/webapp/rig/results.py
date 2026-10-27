"""Assertion outcome bookkeeping for the rig run."""

import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


class Outcome(enum.StrEnum):
    """PASS; FAIL (a behaviour contradicted); FINDING (not confirmed, not faked); SKIPPED."""

    PASS = "PASS"
    FAIL = "FAIL"
    FINDING = "FINDING"
    SKIPPED = "SKIPPED"


class CheckFailed(Exception):
    """An assertion's expectation was contradicted by what the rig observed."""


class CheckFinding(Exception):
    """An assertion could not be confirmed; recorded as a finding, never as a pass."""


@dataclass(frozen=True)
class AssertionResult:
    """One assertion's outcome and a one-line, secret-free detail."""

    number: str
    title: str
    outcome: Outcome
    detail: str = ""


@dataclass
class ResultBook:
    """Collects assertion results, retries and metrics for the summary and the exit code."""

    results: list[AssertionResult] = field(default_factory=list)
    skew_retries: list[str] = field(default_factory=list)
    metrics: dict[str, str] = field(default_factory=dict)
    infrastructure_errors: list[str] = field(default_factory=list)

    def record(self, number: str, title: str, outcome: Outcome, detail: str = "") -> None:
        """Append a result."""
        self.results.append(AssertionResult(number, title, outcome, detail))

    async def run(
        self, number: str, title: str, check: Callable[[], Awaitable[str | None]]
    ) -> Outcome:
        """Run `check`; it returns a detail string, or raises CheckFailed or CheckFinding."""
        try:
            detail = await check() or ""
        except CheckFailed as exc:
            self.record(number, title, Outcome.FAIL, str(exc))
            return Outcome.FAIL
        except CheckFinding as exc:
            self.record(number, title, Outcome.FINDING, str(exc))
            return Outcome.FINDING
        except Exception as exc:
            self.record(number, title, Outcome.FAIL, f"{type(exc).__name__}: {exc}")
            return Outcome.FAIL
        self.record(number, title, Outcome.PASS, detail)
        return Outcome.PASS

    def skip_remaining(self, expected: list[tuple[str, str]], reason: str) -> None:
        """Record SKIPPED for every expected (number, title) with no result yet."""
        done = {result.number for result in self.results}
        for number, title in expected:
            if number not in done:
                self.record(number, title, Outcome.SKIPPED, reason)

    def count(self, outcome: Outcome) -> int:
        """How many results have `outcome`."""
        return sum(1 for result in self.results if result.outcome is outcome)

    def exit_code(self) -> int:
        """0 all pass; 1 any FAIL, SKIPPED or infrastructure error; 3 findings only."""
        if self.infrastructure_errors or self.count(Outcome.FAIL) or self.count(Outcome.SKIPPED):
            return 1
        return 3 if self.count(Outcome.FINDING) else 0

    def summary_lines(self) -> list[str]:
        """A fixed-format summary: one line per result, retries, metrics, then totals."""
        lines = ["== assertion summary =="]
        lines.extend(
            f"{r.number:>4}  {r.outcome.value:<8} {r.title}"
            + (f" -- {r.detail}" if r.detail else "")
            for r in sorted(self.results, key=_sort_key)
        )
        lines.append(f"clock-skew retries: {len(self.skew_retries)}")
        lines.extend(f"  retry: {entry}" for entry in self.skew_retries)
        lines.extend(f"metric {key}: {value}" for key, value in self.metrics.items())
        lines.extend(f"infrastructure error: {error}" for error in self.infrastructure_errors)
        lines.append(
            "totals: "
            + ", ".join(f"{o.value.lower()}={self.count(o)}" for o in Outcome)
            + f"; exit {self.exit_code()}"
        )
        return lines


def _sort_key(result: AssertionResult) -> tuple[int, str]:
    digits = "".join(ch for ch in result.number if ch.isdigit())
    return int(digits or 0), result.number
