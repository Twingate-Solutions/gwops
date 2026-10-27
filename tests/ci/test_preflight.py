"""Tests for gwops.ci.preflight: the CI real-binary config preflight runner.

The classification tests feed synthetic ``SpawnOutcome``s straight
into :func:`classify_outcome` / :func:`classify_ci_outcome` — no real binary, no
subprocess, deterministic and fast. The runner/entrypoint tests monkeypatch
``validate_config_by_spawn`` at its import site in ``gwops.ci.preflight`` so the async
aggregation and CLI exit-code logic are exercised without touching a process. Nothing in
this file imports the renderer or reconciler.

``classify_outcome`` is the lenient classifier the reconciler's live check shares;
``classify_ci_outcome`` is the strict one the CI preflight uses.
"""

from pathlib import Path

import pytest
import structlog
import yaml

from gwops.ci.preflight import (
    SCHEMA_BREAK_MARKERS,
    STEP3_RUNTIME_PATH_RE,
    Classification,
    classify_ci_outcome,
    classify_outcome,
    main,
    preflight_config,
    run_preflight,
)
from gwops.supervisor.spawn import SpawnOutcome, SpawnVerdict

# Stderr of the extracted gateway binary run (inside python:3.12-slim, linux/amd64) against
# tests/fixtures/rendered/minimal.yaml with no runtime files present. The JSON warning line is
# written with the 2.0.0 GA logger name (`system`); the error and usage text are as captured.
_REAL_CREDENTIAL_LOAD_STDERR = (
    '{"levelname":"warn","ts":"2026-10-06T20:38:23.731Z","logger":"system",'
    '"caller":"config/config.go:412","message":"No redirect received"}\n'
    "Error: failed to create proxy failed to create Kubernetes handler: failed to create "
    "kubernetes transport: open /data/k8s-creds/solo/ca.crt: no such file or directory\n"
    "Usage:\n  gateway start [flags]\n\nFlags:\n      --config string   Path to the "
    "configuration file\n"
)


class TestClassifyOutcome:
    """The lenient classifier shared with the reconciler's live pre-flight."""

    def test_healthy_passes(self) -> None:
        verdict = classify_outcome(SpawnOutcome(verdict=SpawnVerdict.HEALTHY))
        assert verdict.classification is Classification.HEALTHY
        assert verdict.passed is True

    def test_rejected_with_failed_to_validate_config_is_schema_break(self) -> None:
        outcome = SpawnOutcome(
            verdict=SpawnVerdict.REJECTED,
            stderr_text="Error: failed to validate config: maxSize out of range\n",
        )
        verdict = classify_outcome(outcome)
        assert verdict.classification is Classification.SCHEMA_BREAK
        assert verdict.passed is False

    def test_rejected_with_failed_to_load_config_is_schema_break(self) -> None:
        outcome = SpawnOutcome(
            verdict=SpawnVerdict.REJECTED,
            stderr_text="Error: failed to load config: yaml: unmarshal error\n",
        )
        verdict = classify_outcome(outcome)
        assert verdict.classification is Classification.SCHEMA_BREAK
        assert verdict.passed is False

    def test_rejected_with_failed_to_create_proxy_is_expected_startup_failure(self) -> None:
        outcome = SpawnOutcome(
            verdict=SpawnVerdict.REJECTED,
            stderr_text="Error: failed to create proxy: open /data/pki/leaf.crt: no such file\n",
        )
        verdict = classify_outcome(outcome)
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE
        assert verdict.passed is True

    def test_rejected_with_unrecognized_stderr_is_expected_startup_failure(self) -> None:
        # The reconciler's live check: anything that isn't a schema-break marker is an
        # expected startup failure (e.g. EADDRINUSE while the live gateway holds the
        # ports), so valid configs are never rejected while the gateway is up. The CI
        # classifier is deliberately stricter (see TestClassifyCiOutcome).
        outcome = SpawnOutcome(
            verdict=SpawnVerdict.REJECTED,
            stderr_text="Error: listen tcp :8443: bind: address already in use\n",
        )
        verdict = classify_outcome(outcome)
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE
        assert verdict.passed is True

    def test_exited_zero_early_with_schema_break_marker_fails(self) -> None:
        outcome = SpawnOutcome(
            verdict=SpawnVerdict.EXITED_ZERO_EARLY,
            stderr_text="failed to validate config: something\n",
        )
        verdict = classify_outcome(outcome)
        assert verdict.classification is Classification.SCHEMA_BREAK
        assert verdict.passed is False

    def test_exited_zero_early_without_marker_is_expected_startup_failure(self) -> None:
        outcome = SpawnOutcome(verdict=SpawnVerdict.EXITED_ZERO_EARLY, stderr_text="")
        verdict = classify_outcome(outcome)
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE
        assert verdict.passed is True

    def test_markers_are_the_two_documented_substrings(self) -> None:
        # Locks the exact substrings of the upstream gateway's cmd/start.go stderr shapes so a
        # future edit can't silently drift.
        assert SCHEMA_BREAK_MARKERS == (
            "failed to load config",
            "failed to validate config",
        )


class TestClassifyCiOutcome:
    """The CI preflight passes only on positive evidence; the reconciler's stays lenient."""

    def test_healthy_passes(self) -> None:
        verdict = classify_ci_outcome(SpawnOutcome(verdict=SpawnVerdict.HEALTHY))
        assert verdict.classification is Classification.HEALTHY
        assert verdict.passed is True

    def test_expect_failure_with_healthy_fails(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(verdict=SpawnVerdict.HEALTHY),
            expect_failure=["failed to create proxy"],
        )
        assert verdict.passed is False
        assert verdict.classification is Classification.UNRECOGNIZED_FAILURE

    def test_expect_failure_with_zero_exit_fails(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(verdict=SpawnVerdict.EXITED_ZERO_EARLY),
            expect_failure=["failed to create proxy"],
        )
        assert verdict.passed is False

    def test_expect_failure_with_matching_marker_passes(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="Error: failed to create proxy failed to create web app config: "
                "ca \"/tmp/bad.pem\": failed to parse CA certificate\n",
            ),
            expect_failure=["failed to parse CA certificate"],
        )
        assert verdict.passed is True
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE

    def test_expect_failure_multiple_markers_all_present_passes(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="Error: failed to create proxy failed to create web app config: "
                "ca \"/tmp/gwops-ci-bad-ca-bundle.txt\": failed to parse CA certificate\n",
            ),
            expect_failure=["failed to create web app config", "failed to parse CA certificate",
                            "/tmp/gwops-ci-bad-ca-bundle.txt"],
        )
        assert verdict.passed is True

    def test_expect_failure_multiple_markers_one_missing_fails(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="Error: failed to create proxy: open /data/pki/leaf.crt: "
                "no such file or directory\n",
            ),
            expect_failure=["failed to create web app config", "missing_marker"],
        )
        assert verdict.passed is False

    def test_expect_failure_substring_match_works(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="Error: failed to create proxy: open /tmp/bad-bundle.txt: "
                "No such file or directory\n",
            ),
            expect_failure=["/tmp/bad-bundle.txt"],
        )
        assert verdict.passed is True

    def test_expect_failure_without_matching_marker_fails(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="Error: failed to create proxy: open /data/pki/leaf.crt: "
                "no such file or directory\n",
            ),
            expect_failure=["unsupported key"],
        )
        assert verdict.passed is False
        assert verdict.classification is Classification.UNRECOGNIZED_FAILURE

    def test_expect_failure_fails_on_a_schema_break_even_when_every_marker_matches(self) -> None:
        verdict = classify_ci_outcome(
            SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="Error: failed to validate config: maxSize out of range\n",
            ),
            expect_failure=["failed to validate config"],
        )
        assert verdict.passed is False
        assert verdict.classification is Classification.SCHEMA_BREAK

    def test_expect_failure_with_no_markers_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            classify_ci_outcome(
                SpawnOutcome(verdict=SpawnVerdict.REJECTED, stderr_text="anything\n"),
                expect_failure=[],
            )

    @pytest.mark.parametrize("marker", ["", "   ", "\t\n"])
    def test_expect_failure_with_a_blank_marker_is_refused(self, marker: str) -> None:
        with pytest.raises(ValueError, match="blank"):
            classify_ci_outcome(
                SpawnOutcome(verdict=SpawnVerdict.REJECTED, stderr_text="anything\n"),
                expect_failure=["failed to create proxy", marker],
            )

    @pytest.mark.parametrize(
        "stderr",
        [
            _REAL_CREDENTIAL_LOAD_STDERR,
            "Error: failed to create proxy: tls: private key does not match\n",
            "open /data/pki/leaf.crt: no such file or directory\n",
            "open /run/gwops/config.yaml: No such file or directory\n",
        ],
    )
    def test_positive_credential_load_marker_passes(self, stderr: str) -> None:
        verdict = classify_ci_outcome(SpawnOutcome(SpawnVerdict.REJECTED, stderr))
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE
        assert verdict.passed is True

    @pytest.mark.parametrize(
        "stderr",
        [
            "failed to load config: yaml: unmarshal error\n",
            "failed to validate config: maxSize out of range\n",
            # A schema marker wins even when a later step is also named.
            "failed to validate config: x\nfailed to create proxy: y\n",
        ],
    )
    def test_schema_break_fails(self, stderr: str) -> None:
        verdict = classify_ci_outcome(SpawnOutcome(SpawnVerdict.REJECTED, stderr))
        assert verdict.classification is Classification.SCHEMA_BREAK
        assert verdict.passed is False

    @pytest.mark.parametrize(
        ("verdict", "stderr"),
        [
            pytest.param(SpawnVerdict.EXITED_ZERO_EARLY, "", id="exited-zero-empty"),
            pytest.param(
                SpawnVerdict.EXITED_ZERO_EARLY,
                "failed to create proxy: open /data/x: no such file or directory\n",
                id="exited-zero-even-with-a-credential-load-marker",
            ),
            pytest.param(SpawnVerdict.REJECTED, "", id="rejected-empty-stderr"),
            pytest.param(
                SpawnVerdict.REJECTED,
                "Error: unknown flag: --config\nUsage:\n  gateway start [flags]\n",
                id="usage-error",
            ),
            pytest.param(
                SpawnVerdict.REJECTED,
                "panic: runtime error: invalid memory address\n\ngoroutine 1 [running]:\n",
                id="panic-before-config-load",
            ),
            pytest.param(SpawnVerdict.REJECTED, "exec format error\n", id="exec-format-error"),
            pytest.param(
                SpawnVerdict.REJECTED,
                "Error: listen tcp :8443: bind: address already in use\n",
                id="bind-error-is-not-evidence-in-ci",
            ),
            pytest.param(
                SpawnVerdict.REJECTED,
                "open /etc/hostname-missing: no such file or directory\n",
                id="missing-file-outside-runtime-dirs",
            ),
            pytest.param(
                SpawnVerdict.REJECTED,
                "open /database/x: no such file or directory\n",
                id="data-prefix-lookalike",
            ),
        ],
    )
    def test_everything_without_a_positive_marker_fails(
        self, verdict: SpawnVerdict, stderr: str
    ) -> None:
        result = classify_ci_outcome(SpawnOutcome(verdict, stderr))
        assert result.classification is Classification.UNRECOGNIZED_FAILURE
        assert result.passed is False

    def test_the_reconcilers_classifier_stays_lenient_for_the_same_input(self) -> None:
        # EADDRINUSE is legitimate while the live gateway holds the ports: the reconciler
        # must keep treating it as "config fine, environment busy".
        outcome = SpawnOutcome(
            SpawnVerdict.REJECTED, "Error: listen tcp :8443: bind: address already in use\n"
        )
        assert classify_outcome(outcome).passed is True
        assert classify_ci_outcome(outcome).passed is False


class TestGoldenCredentialPathsStillYieldTheCredentialLoadMarker:
    """The golden's content-addressed credential paths are absent in CI: expected failure.

    CI has no ``/data`` volume, so the gateway fails at proxy creation opening a copy.
    """

    _GOLDEN = Path(__file__).parent.parent / "fixtures" / "rendered" / "minimal.yaml"

    def _credential_paths(self) -> list[str]:
        doc = yaml.safe_load(self._GOLDEN.read_text(encoding="utf-8"))
        [upstream] = doc["kubernetes"]["upstreams"]
        return [upstream["bearerTokenFile"], upstream["caFile"]]

    def test_golden_credential_paths_are_under_the_runtime_only_data_dir(self) -> None:
        paths = self._credential_paths()
        assert all(p.startswith("/data/k8s-creds/") for p in paths)
        assert paths[0].startswith("/data/k8s-creds/solo-token-")
        assert paths[1].startswith("/data/k8s-creds/solo-ca-") and paths[1].endswith(".crt")

    @pytest.mark.parametrize("which", [0, 1])
    def test_runtime_path_pattern_matches_the_open_error_for_each_credential(
        self, which: int
    ) -> None:
        path = self._credential_paths()[which]
        stderr = f"kubernetes transport: open {path}: no such file or directory\n"
        assert STEP3_RUNTIME_PATH_RE.search(stderr) is not None
        verdict = classify_ci_outcome(SpawnOutcome(SpawnVerdict.REJECTED, stderr))
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE
        assert verdict.passed is True

    @pytest.mark.parametrize("which", [0, 1])
    def test_the_real_gateway_error_shape_with_the_new_path_passes(self, which: int) -> None:
        path = self._credential_paths()[which]
        stderr = _REAL_CREDENTIAL_LOAD_STDERR.replace("/data/k8s-creds/solo/ca.crt", path)
        assert path in stderr
        verdict = classify_ci_outcome(SpawnOutcome(SpawnVerdict.REJECTED, stderr))
        assert verdict.classification is Classification.EXPECTED_STARTUP_FAILURE


class TestRunPreflight:
    async def test_all_healthy_configs_pass(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(verdict=SpawnVerdict.HEALTHY)

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        configs = [tmp_path / "a.yaml", tmp_path / "b.yaml"]
        results = await run_preflight(tmp_path / "gateway", configs, timeout_seconds=0.1)
        assert len(results) == 2
        assert all(r.verdict.passed for r in results)

    async def test_one_schema_break_among_healthy_is_reported(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            if config_path.name == "bad.yaml":
                return SpawnOutcome(
                    verdict=SpawnVerdict.REJECTED,
                    stderr_text="failed to validate config: nope\n",
                )
            return SpawnOutcome(verdict=SpawnVerdict.HEALTHY)

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        configs = [tmp_path / "good.yaml", tmp_path / "bad.yaml"]
        results = await run_preflight(tmp_path / "gateway", configs, timeout_seconds=0.1)
        by_name = {r.config_path.name: r for r in results}
        assert by_name["good.yaml"].verdict.passed is True
        assert by_name["bad.yaml"].verdict.passed is False
        assert by_name["bad.yaml"].verdict.classification is Classification.SCHEMA_BREAK


class TestMainEntrypoint:
    async def test_exits_zero_when_every_config_is_healthy_or_fails_at_credential_load(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="failed to create proxy: open /data/pki/leaf.crt: no such file\n",
            )

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "golden.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main(["--", str(tmp_path / "gateway"), str(config)])
        assert exit_code == 0

    async def test_exits_nonzero_when_any_config_is_a_schema_break(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            if config_path.name == "bad.yaml":
                return SpawnOutcome(
                    verdict=SpawnVerdict.REJECTED,
                    stderr_text="failed to load config: bad yaml\n",
                )
            return SpawnOutcome(verdict=SpawnVerdict.HEALTHY)

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        good = tmp_path / "good.yaml"
        bad = tmp_path / "bad.yaml"
        good.write_text("twingate: {}\n", encoding="utf-8")
        bad.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main(["--", str(tmp_path / "gateway"), str(good), str(bad)])
        assert exit_code == 1

    async def test_accepts_custom_timeout_flag(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen_timeout: list[float] = []

        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            seen_timeout.append(timeout_seconds)
            return SpawnOutcome(verdict=SpawnVerdict.HEALTHY)

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "golden.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main(
            ["--timeout-seconds", "1.5", "--", str(tmp_path / "gateway"), str(config)]
        )
        assert exit_code == 0
        assert seen_timeout == [1.5]

    @pytest.mark.parametrize(
        ("verdict", "stderr"),
        [
            (SpawnVerdict.EXITED_ZERO_EARLY, ""),
            (SpawnVerdict.REJECTED, "Error: unknown flag: --config\n"),
            (SpawnVerdict.REJECTED, "exec format error\n"),
        ],
    )
    async def test_exits_nonzero_on_an_unrecognized_failure_and_logs_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        verdict: SpawnVerdict,
        stderr: str,
    ) -> None:
        from gwops.logging import configure_logging

        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(verdict=verdict, stderr_text=stderr)

        configure_logging()
        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "golden.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")

        exit_code = await main(["--", str(tmp_path / "gateway"), str(config)])

        assert exit_code == 1
        out = capsys.readouterr().out
        assert "ci.preflight_unrecognized_failure" in out
        assert "ci.preflight_failed" in out
        assert "unrecognized-failure" in out
        if stderr:
            assert stderr.strip() in out

    async def test_a_binary_that_cannot_be_executed_fails_loudly(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from gwops.logging import configure_logging

        async def _exec_format_error(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            raise OSError(8, "Exec format error")

        configure_logging()
        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _exec_format_error)
        config = tmp_path / "golden.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")

        assert await main(["--", str(tmp_path / "gateway"), str(config)]) == 1
        out = capsys.readouterr().out
        assert "could not execute" in out
        assert "Exec format error" in out

    async def test_the_real_binarys_credential_load_stderr_passes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(SpawnVerdict.REJECTED, _REAL_CREDENTIAL_LOAD_STDERR)

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "golden.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        assert await main(["--", str(tmp_path / "gateway"), str(config)]) == 0

    async def test_expect_failure_passes_when_marker_present(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(
                SpawnVerdict.REJECTED,
                "Error: failed to create proxy failed to create web app config: "
                "ca \"/tmp/bad.pem\": failed to parse CA certificate\n",
            )

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "canary.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main([
            "--expect-failure", "failed to parse CA certificate",
            "--", str(tmp_path / "gateway"), str(config)
        ])
        assert exit_code == 0

    async def test_expect_failure_multiple_markers_all_pass(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(
                SpawnVerdict.REJECTED,
                "Error: failed to create proxy failed to create web app config: "
                "ca \"/tmp/gwops-ci-bad-ca-bundle.txt\": failed to parse CA certificate\n",
            )

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "canary.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main([
            "--expect-failure", "failed to create web app config",
            "--expect-failure", "failed to parse CA certificate",
            "--expect-failure", "/tmp/gwops-ci-bad-ca-bundle.txt",
            "--", str(tmp_path / "gateway"), str(config)
        ])
        assert exit_code == 0

    async def test_expect_failure_fails_when_marker_absent(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(
                SpawnVerdict.REJECTED,
                "Error: failed to create proxy: open /data/pki/leaf.crt: no such file\n",
            )

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "canary.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main([
            "--expect-failure", "unsupported key",
            "--", str(tmp_path / "gateway"), str(config)
        ])
        assert exit_code == 1

    async def test_expect_failure_fails_when_not_rejected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(SpawnVerdict.HEALTHY)

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "canary.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main([
            "--expect-failure", "failed to create proxy",
            "--", str(tmp_path / "gateway"), str(config)
        ])
        assert exit_code == 1

    @pytest.mark.parametrize("marker", ["", "   "])
    async def test_a_blank_expect_failure_marker_is_a_usage_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        marker: str,
    ) -> None:
        async def _never_spawned(*_a: object, **_k: object) -> SpawnOutcome:
            raise AssertionError("must be refused before any spawn")

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _never_spawned)
        config = tmp_path / "canary.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        with pytest.raises(SystemExit) as excinfo:
            await main(["--expect-failure", marker, "--", str(tmp_path / "gateway"), str(config)])
        assert excinfo.value.code == 2
        assert "--expect-failure" in capsys.readouterr().err

    async def test_an_empty_marker_list_is_refused_before_any_spawn(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _never_spawned(*_a: object, **_k: object) -> SpawnOutcome:
            raise AssertionError("must be refused before any spawn")

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _never_spawned)
        with pytest.raises(ValueError, match="at least one"):
            await preflight_config(
                tmp_path / "gateway", tmp_path / "golden.yaml", expect_failure=[]
            )

    async def test_expect_failure_on_a_schema_break_exits_non_zero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(
                SpawnVerdict.REJECTED, "Error: failed to load config: yaml: unmarshal errors\n"
            )

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        config = tmp_path / "canary.yaml"
        config.write_text("twingate: {}\n", encoding="utf-8")
        exit_code = await main(
            ["--expect-failure", "failed to load config", "--", str(tmp_path / "gateway"),
             str(config)]
        )
        assert exit_code == 1

    @pytest.mark.parametrize(("markers", "expected"), [(["a", "b"], 2), (None, None)])
    async def test_the_marker_count_is_logged_only_in_expect_failure_mode(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        markers: list[str] | None,
        expected: int | None,
    ) -> None:
        async def _fake_validate(
            binary: Path, config_path: Path, *, timeout_seconds: float
        ) -> SpawnOutcome:
            return SpawnOutcome(SpawnVerdict.REJECTED, "failed to create proxy a b\n")

        monkeypatch.setattr("gwops.ci.preflight.validate_config_by_spawn", _fake_validate)
        with structlog.testing.capture_logs() as logs:
            await preflight_config(
                tmp_path / "gateway", tmp_path / "golden.yaml", expect_failure=markers
            )
        [event] = [e for e in logs if e["event"].startswith("ci.preflight_")]
        assert event.get("expect_failure_count") == expected
        assert ("expect_failure_count" in event) is (markers is not None)
