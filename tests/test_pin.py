"""The gateway pin (tag + image-index digest) is identical everywhere it lives.

The pin appears in ``Dockerfile``, ``Makefile``, ``build-images.yml`` and the image smoke
test. Bumping one without the others ships an image that differs from
what was tested, so this test fails on any drift. It also checks the Dockerfile's tag guard
and that the CI preflight v2 leg pulls ``dev`` with no way to skip or soften it.

The supply-chain pins are checked here too: the Python base image (tag + digest, in the
Dockerfile and the smoke test), exact ``==`` dependency versions in ``pyproject.toml``, the
hash-locked ``requirements.lock`` the Dockerfile installs from, and full-SHA ``uses:`` pins
in the workflows.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_DOCKERFILE = _ROOT / "Dockerfile"
_MAKEFILE = _ROOT / "Makefile"
_BUILD_IMAGES = _ROOT / ".github" / "workflows" / "build-images.yml"
_PYPROJECT = _ROOT / "pyproject.toml"
_LOCK = _ROOT / "requirements.lock"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_SMOKE = _ROOT / "tests" / "test_image_smoke.py"
_PREFLIGHT = _ROOT / ".github" / "workflows" / "preflight.yml"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _uncommented(path: Path) -> str:
    """File text with whole-line ``#`` comments removed."""
    return "\n".join(
        line for line in _text(path).splitlines() if not line.lstrip().startswith("#")
    )


def _all(pattern: str, text: str) -> list[str]:
    found = re.findall(pattern, text, flags=re.MULTILINE)
    assert found, f"pattern {pattern!r} not found"
    return found


def _dockerfile_guard_regex() -> re.Pattern[str]:
    """The tag-guard ERE as written in the Dockerfile's ``grep -Ezq`` line."""
    pattern_re = r"""printf %s "\$\{GATEWAY_TAG\}" \| grep -Ezq '([^']+)'"""
    (pattern,) = _all(pattern_re, _text(_DOCKERFILE))
    return re.compile(pattern)


def _workflow_inputs() -> dict[str, Any]:
    workflow = yaml.safe_load(_text(_BUILD_IMAGES))
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    triggers = workflow.get("on", workflow.get(True))
    inputs: dict[str, Any] = triggers["workflow_dispatch"]["inputs"]
    return inputs


def _dockerfile_pin() -> tuple[str, str]:
    tags = set(_all(r"^ARG GATEWAY_TAG=(\S+)$", _text(_DOCKERFILE)))
    digests = set(_all(r"^ARG GATEWAY_DIGEST=(\S+)$", _text(_DOCKERFILE)))
    assert len(tags) == 1, f"Dockerfile declares several GATEWAY_TAG defaults: {tags}"
    assert len(digests) == 1, f"Dockerfile declares several GATEWAY_DIGEST defaults: {digests}"
    return tags.pop(), digests.pop()


def _locations() -> dict[str, tuple[set[str], set[str]]]:
    """Per file: (tags, digests) found, for the files that carry the pin."""
    inputs = _workflow_inputs()
    build_images = _text(_BUILD_IMAGES)
    smoke = _text(_SMOKE)
    return {
        "Dockerfile": ({_dockerfile_pin()[0]}, {_dockerfile_pin()[1]}),
        "Makefile": (
            set(_all(r"^GATEWAY_TAG \?= (\S+)$", _text(_MAKEFILE))),
            set(_all(r"^GATEWAY_DIGEST \?= (\S+)$", _text(_MAKEFILE))),
        ),
        "build-images.yml": (
            {inputs["gateway_tag"]["default"]}
            | set(_all(r"inputs\.gateway_tag \|\| '([^']+)'", build_images)),
            {inputs["gateway_digest"]["default"]}
            | set(_all(r"inputs\.gateway_digest \|\| '([^']+)'", build_images)),
        ),
        "tests/test_image_smoke.py": (
            set(_all(r"os\.environ\.get\('GATEWAY_TAG', '([^']+)'\)", smoke)),
            set(_all(r'^_DEFAULT_GATEWAY_DIGEST = "([^"]+)"$', smoke)),
        ),
    }


def test_every_location_carries_the_dockerfile_pin() -> None:
    tag, digest = _dockerfile_pin()
    for name, (tags, digests) in _locations().items():
        assert tags == {tag}, f"{name}: GATEWAY_TAG {tags} != Dockerfile {tag}"
        assert digests == {digest}, f"{name}: GATEWAY_DIGEST {digests} != Dockerfile {digest}"


def test_pin_is_well_formed() -> None:
    tag, digest = _dockerfile_pin()
    assert _dockerfile_guard_regex().fullmatch(tag), f"pinned tag {tag!r} fails its own guard"
    assert _DIGEST_RE.fullmatch(digest), f"GATEWAY_DIGEST {digest!r} is not sha256:<64 hex>"


def test_dockerfile_pulls_binary_by_tag_and_digest() -> None:
    from_lines = _all(r"^FROM twingate/gateway:(.+) AS gateway-binary$", _text(_DOCKERFILE))
    assert len(from_lines) == 1
    assert from_lines[0].startswith("${GATEWAY_TAG}@${GATEWAY_DIGEST")


def test_image_version_env_equals_the_tag() -> None:
    assert "ENV GWOPS_GATEWAY_VERSION=${GATEWAY_TAG}" in _text(_DOCKERFILE)


def test_dockerfile_checks_digest_format() -> None:
    pattern_re = r"""printf %s "\$\{GATEWAY_DIGEST\}" \| grep -Ezq '([^']+)'"""
    (pattern,) = _all(pattern_re, _text(_DOCKERFILE))
    assert pattern == _DIGEST_RE.pattern


@pytest.mark.parametrize("tag", ["2.0.0", "2.0.0-dev-5ed8e12", "2.13.4", "2.0.0-dev-" + "a" * 40])
def test_guard_accepts(tag: str) -> None:
    assert _dockerfile_guard_regex().fullmatch(tag)


@pytest.mark.parametrize(
    "tag",
    [
        "1.1.0",
        "dev",
        "latest",
        "2",
        "2.0",
        "2.0.0-dev",
        "3.0.0",
        "2.0.0-dev-abc",
        "2.0.0-dev-5ED8E12",
        "2.0.0-dev-" + "a" * 41,
        "2.0.0 ",
        "",
    ],
)
def test_guard_rejects(tag: str) -> None:
    assert not _dockerfile_guard_regex().fullmatch(tag)


@pytest.mark.parametrize(
    "digest",
    ["", "sha256:", "sha256:abc", "sha256:" + "A" * 64, "sha256:" + "a" * 63, "sha512:" + "a" * 64],
)
def test_digest_format_rejects(digest: str) -> None:
    assert not _DIGEST_RE.fullmatch(digest)


# --- lego pin: Dockerfile and tests/test_image_smoke.py only -------------------------


def _lego_dockerfile_pin() -> tuple[str, str]:
    text = _text(_DOCKERFILE)
    tags = _all(r"^ARG LEGO_TAG=(\S+)$", text)
    digests = _all(r"^ARG LEGO_DIGEST=(\S+)$", text)
    # Global declaration plus the runtime-stage re-declaration.
    assert len(tags) == 2, f"expected 2 LEGO_TAG ARG lines, found {tags}"
    assert len(digests) == 2, f"expected 2 LEGO_DIGEST ARG lines, found {digests}"
    assert len(set(tags)) == 1, f"Dockerfile declares several LEGO_TAG defaults: {set(tags)}"
    assert len(set(digests)) == 1, (
        f"Dockerfile declares several LEGO_DIGEST defaults: {set(digests)}"
    )
    return tags[0], digests[0]


def _lego_tag_guard_regex() -> re.Pattern[str]:
    pattern_re = r"""printf %s "\$\{LEGO_TAG\}" \| grep -Ezq '([^']+)'"""
    (pattern,) = _all(pattern_re, _text(_DOCKERFILE))
    return re.compile(pattern)


def _lego_digest_guard_pattern() -> str:
    pattern_re = r"""printf %s "\$\{LEGO_DIGEST(?::\?[^}]*)?\}" \| grep -Ezq '([^']+)'"""
    (pattern,) = _all(pattern_re, _text(_DOCKERFILE))
    return pattern


def _lego_smoke_pin() -> tuple[set[str], set[str]]:
    smoke = _text(_SMOKE)
    return (
        set(_all(r'^_LEGO_TAG = "([^"]+)"$', smoke)),
        set(_all(r'^_LEGO_DIGEST = "([^"]+)"$', smoke)),
    )


def test_lego_smoke_test_carries_the_dockerfile_pin() -> None:
    tag, digest = _lego_dockerfile_pin()
    tags, digests = _lego_smoke_pin()
    assert tags == {tag}, f"test_image_smoke.py: _LEGO_TAG {tags} != Dockerfile {tag}"
    assert digests == {digest}, (
        f"test_image_smoke.py: _LEGO_DIGEST {digests} != Dockerfile {digest}"
    )


def test_lego_pin_is_well_formed() -> None:
    tag, digest = _lego_dockerfile_pin()
    assert _lego_tag_guard_regex().fullmatch(tag), f"pinned tag {tag!r} fails its own guard"
    assert _DIGEST_RE.fullmatch(digest), f"LEGO_DIGEST {digest!r} is not sha256:<64 hex>"


def test_dockerfile_pulls_lego_by_tag_and_digest() -> None:
    from_lines = _all(r"^FROM goacme/lego:(.+) AS lego-binary$", _text(_DOCKERFILE))
    assert len(from_lines) == 1
    assert from_lines[0].startswith("${LEGO_TAG}@${LEGO_DIGEST")


def test_dockerfile_lego_digest_is_required_non_empty() -> None:
    """The `:?` expansion fails the build on an empty digest, in the FROM and in the guard."""
    text = _text(_DOCKERFILE)
    from_line = _all(r"^FROM goacme/lego:.+ AS lego-binary$", text)[0]
    assert "${LEGO_DIGEST:?" in from_line
    assert re.search(r'printf %s "\$\{LEGO_DIGEST:\?[^}]+\}" \| grep -Ezq', text)


def test_dockerfile_copies_lego_from_the_pinned_stage() -> None:
    copies = _all(r"^COPY --from=lego-binary (.+)$", _text(_DOCKERFILE))
    assert copies == ["/lego /usr/local/bin/lego"]


def test_dockerfile_checks_lego_digest_format() -> None:
    assert _lego_digest_guard_pattern() == _DIGEST_RE.pattern


@pytest.mark.parametrize("tag", ["v5.5.2", "v5.0.0", "v5.13.4", "v5.0.10"])
def test_lego_guard_accepts(tag: str) -> None:
    assert _lego_tag_guard_regex().fullmatch(tag)


@pytest.mark.parametrize(
    "tag",
    [
        "latest",
        "v5",
        "5",
        "dev",
        "v5.5",
        "v4.9.0",
        "v4.x",
        "v6.0.0",
        "5.5.2",
        "v5.5.2-rc1",
        "v5.5.x",
        "v5.5.2 ",
        "",
    ],
)
def test_lego_guard_rejects(tag: str) -> None:
    assert not _lego_tag_guard_regex().fullmatch(tag)


@pytest.mark.parametrize("digest", ["", "sha256:", "sha256:" + "A" * 64, "sha256:" + "a" * 63])
def test_lego_digest_guard_rejects(digest: str) -> None:
    assert not re.fullmatch(_lego_digest_guard_pattern(), digest)


def _lego_pin_markers() -> list[str]:
    tag, digest = _lego_dockerfile_pin()
    return ["LEGO_TAG", "LEGO_DIGEST", "goacme/lego", tag, digest]


@pytest.mark.parametrize(
    "path",
    [_MAKEFILE, _BUILD_IMAGES, *sorted(_ROOT.glob("compose*.y*ml"))],
    ids=lambda p: p.name,
)
def test_lego_pin_is_not_duplicated_outside_dockerfile_and_smoke(path: Path) -> None:
    text = _uncommented(path)
    found = [marker for marker in _lego_pin_markers() if marker in text]
    assert not found, f"{path.name} carries the lego pin ({found}); it lives only in the Dockerfile"


def test_compose_files_are_discovered() -> None:
    names = {p.name for p in _ROOT.glob("compose*.y*ml")}
    assert "compose.yaml" in names


def test_tag_latest_input_defaults_false_and_gates_latest() -> None:
    inputs = _workflow_inputs()
    assert inputs["tag_latest"]["default"] is False
    assert inputs["tag_latest"]["type"] == "boolean"
    tags = _uncommented(_BUILD_IMAGES)
    assert ":latest" in tags
    # The only `:latest` tag line is conditional on the input; no unconditional one.
    for line in tags.splitlines():
        if re.search(r":latest\s*$", line.strip()):
            pytest.fail(f"unconditional :latest tag line: {line!r}")
    # The :latest tag is conditional on TAG_LATEST env var (which comes from inputs)
    assert "TAG_LATEST" in tags
    assert "&&" in tags


# --- preflight.yml: resolve and preflight jobs, no schedule trigger, no skips --------


def test_preflight_pulls_dev() -> None:
    assert "twingate/gateway:dev" in _uncommented(_PREFLIGHT)


def test_preflight_has_resolve_and_preflight_jobs() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    jobs = workflow["jobs"]
    assert "resolve" in jobs, "preflight.yml must have a 'resolve' job"
    assert "preflight" in jobs, "preflight.yml must have a 'preflight' job"
    assert jobs["preflight"].get("needs") == "resolve", "preflight job must depend on resolve"


def test_preflight_has_no_schedule_trigger() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    triggers = workflow.get("on", workflow.get(True))
    assert "schedule" not in triggers, "preflight.yml must not have a schedule trigger"


def test_resolve_job_has_timeout() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_job = workflow["jobs"]["resolve"]
    assert "timeout-minutes" in resolve_job, "resolve job must have timeout-minutes"


def test_preflight_job_has_timeout() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_job = workflow["jobs"]["preflight"]
    assert "timeout-minutes" in preflight_job, "preflight job must have timeout-minutes"


def test_both_jobs_have_persist_credentials_false() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    for job_name in ("resolve", "preflight"):
        job = workflow["jobs"][job_name]
        found_checkout = False
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout"):
                found_checkout = True
                assert step.get("with", {}).get("persist-credentials") is False, \
                    f"job {job_name!r} checkout must have persist-credentials: false"
        assert found_checkout, f"job {job_name!r} must have an actions/checkout step"


def test_resolve_job_exposes_outputs() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_job = workflow["jobs"]["resolve"]
    outputs = resolve_job.get("outputs", {})
    assert "index_digest" in outputs, "resolve job must output index_digest"
    assert "amd64_digest" in outputs, "resolve job must output amd64_digest"


def test_resolve_validates_digests() -> None:
    preflight_text = _uncommented(_PREFLIGHT)
    # The validate step should check both INDEX_DIGEST and AMD64_DIGEST
    assert "sha256:[0-9a-f]{64}" in preflight_text, \
        "resolve job must validate digest format"
    assert 'grep -Ezq' in preflight_text, \
        "resolve job must use grep -Ezq for digest validation"


def test_pull_step_uses_env_not_interpolation() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_job = workflow["jobs"]["resolve"]

    found_pull = False
    for step in resolve_job["steps"]:
        if step.get("name") and "Pull" in step["name"]:
            found_pull = True
            run = step.get("run", "")
            # The step should use $AMD64_DIGEST from env, not interpolation
            assert "$AMD64_DIGEST" in run, "pull step must use $AMD64_DIGEST from env"
            assert step.get("env", {}).get("AMD64_DIGEST"), "pull step must set AMD64_DIGEST in env"

    assert found_pull, "resolve job must have a Pull step"


def test_extract_step_uses_env_not_interpolation() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_job = workflow["jobs"]["resolve"]

    found_extract = False
    for step in resolve_job["steps"]:
        if step.get("name") and "Extract" in step["name"]:
            found_extract = True
            run = step.get("run", "")
            # The step should NOT use ${{ steps.resolve_dev.outputs.amd64_digest }}
            # in the run block; it should use $AMD64_DIGEST from env instead
            assert "$AMD64_DIGEST" in run, "extract step must use $AMD64_DIGEST from env"
            assert step.get("env", {}).get("AMD64_DIGEST"), \
                "extract step must set AMD64_DIGEST in env"

    assert found_extract, "resolve job must have an Extract step"


def test_preflight_job_has_no_secrets() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_job = workflow["jobs"]["preflight"]
    for step in preflight_job["steps"]:
        # No step should reference secrets, except possibly a login step
        run = step.get("run", "")
        uses = step.get("uses", "")
        if "login" not in uses.lower():
            for line in run.split("\n"):
                assert "secrets." not in line, \
                    f"preflight job step {step.get('name')!r} references secrets: {line}"
        # The with dict should not reference secrets (except login step)
        with_dict = step.get("with", {})
        if "login" not in uses.lower():
            for key, val in with_dict.items():
                if isinstance(val, str):
                    assert "secrets." not in val, \
                        f"preflight job step {step.get('name')!r} has secret in 'with.{key}'"


def test_preflight_job_runs_make_preflight_ci() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_job = workflow["jobs"]["preflight"]

    found_preflight_ci = False
    for step in preflight_job["steps"]:
        run = step.get("run", "")
        if "make preflight-ci" in run:
            found_preflight_ci = True
            assert "GATEWAY_BIN" in run, "preflight-ci step must pass GATEWAY_BIN"
            assert "CONFIGS" in run, "preflight-ci step must pass CONFIGS"
            break

    assert found_preflight_ci, "preflight job must run 'make preflight-ci' in a step"


def test_preflight_has_no_skip_path() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            run = step.get("run", "")
            if run:
                # Allow exit 0 only in docker logout context; critical steps must not skip
                step_name = step.get("name", "")
                critical = ["resolve", "pull", "extract", "validate", "preflight"]
                if any(x in step_name.lower() for x in critical):
                    assert not re.search(r"\bexit\s+0\b", run), \
                        f"critical step {step_name!r} must not have 'exit 0' skip"


def test_preflight_has_no_continue_on_error() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    for job_name, job in workflow["jobs"].items():
        assert "continue-on-error" not in job, f"job {job_name!r} sets continue-on-error"
        for step in job["steps"]:
            step_name = step.get("name", "")
            # Login step is allowed to have if:; others should not
            is_login = any(x in step_name.lower() for x in ["log in", "login", "docker"])
            if step.get("if") and not is_login:
                raise AssertionError(
                    f"step {step_name!r} has 'if:' (only login step allowed)"
                )
            assert "continue-on-error" not in step, f"step {step_name!r} sets continue-on-error"
    assert "continue-on-error" not in _uncommented(_PREFLIGHT)


# --- preflight.yml: resolve-pinned and preflight-pinned jobs ----------------------


def test_preflight_has_pinned_resolve_and_preflight_jobs() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    jobs = workflow["jobs"]
    assert "resolve-pinned" in jobs, "preflight.yml must have a 'resolve-pinned' job"
    assert "preflight-pinned" in jobs, "preflight.yml must have a 'preflight-pinned' job"
    assert jobs["preflight-pinned"].get("needs") == "resolve-pinned", \
        "preflight-pinned job must depend on resolve-pinned"


def test_resolve_pinned_job_has_timeout() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_pinned_job = workflow["jobs"]["resolve-pinned"]
    assert "timeout-minutes" in resolve_pinned_job, "resolve-pinned job must have timeout-minutes"


def test_preflight_pinned_job_has_timeout() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_pinned_job = workflow["jobs"]["preflight-pinned"]
    assert "timeout-minutes" in preflight_pinned_job, (
        "preflight-pinned job must have timeout-minutes"
    )


def test_resolve_pinned_and_preflight_pinned_have_persist_credentials_false() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    for job_name in ("resolve-pinned", "preflight-pinned"):
        job = workflow["jobs"][job_name]
        found_checkout = False
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout"):
                found_checkout = True
                assert step.get("with", {}).get("persist-credentials") is False, \
                    f"job {job_name!r} checkout must have persist-credentials: false"
        assert found_checkout, f"job {job_name!r} must have an actions/checkout step"


def test_resolve_pinned_job_exposes_outputs() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_pinned_job = workflow["jobs"]["resolve-pinned"]
    outputs = resolve_pinned_job.get("outputs", {})
    assert "index_digest" in outputs, "resolve-pinned job must output index_digest"
    assert "amd64_digest" in outputs, "resolve-pinned job must output amd64_digest"


def test_resolve_pinned_validates_tag_and_digest() -> None:
    preflight_text = _uncommented(_PREFLIGHT)
    # resolve-pinned must validate both tag and digest format
    assert "grep -Ezq" in preflight_text, \
        "resolve-pinned job must use grep -Ezq for validation"
    # Must check tag format like build-images.yml does
    assert r"^2\.[0-9]" in preflight_text, \
        "resolve-pinned job must validate tag format (2.X.Y or 2.X.Y-dev-<sha>)"


def test_resolve_pinned_extracts_from_dockerfile() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    resolve_pinned_job = workflow["jobs"]["resolve-pinned"]

    found_extract = False
    for step in resolve_pinned_job["steps"]:
        if step.get("id") == "extract_pin":
            found_extract = True
            run = step.get("run", "")
            assert "Dockerfile" in run, "extract_pin step must read Dockerfile"
            assert "GATEWAY_TAG" in run, "extract_pin step must extract GATEWAY_TAG"
            assert "GATEWAY_DIGEST" in run, "extract_pin step must extract GATEWAY_DIGEST"
            break

    assert found_extract, "resolve-pinned job must have an 'extract_pin' step"


def test_preflight_pinned_job_has_no_secrets() -> None:
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_pinned_job = workflow["jobs"]["preflight-pinned"]
    for step in preflight_pinned_job["steps"]:
        # No step should reference secrets, except possibly a login step
        run = step.get("run", "")
        uses = step.get("uses", "")
        if "login" not in uses.lower():
            for line in run.split("\n"):
                assert "secrets." not in line, \
                    f"preflight-pinned job step {step.get('name')!r} references secrets: {line}"
        # The with dict should not reference secrets (except login step)
        with_dict = step.get("with", {})
        if "login" not in uses.lower():
            for key, val in with_dict.items():
                if isinstance(val, str):
                    assert "secrets." not in val, \
                        f"preflight-pinned job step {step.get('name')!r} has secret in 'with.{key}'"


def test_preflight_pinned_runs_five_steps() -> None:
    """preflight-pinned must run the same five preflight steps as preflight."""
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_pinned_job = workflow["jobs"]["preflight-pinned"]

    step_names = [s.get("name", "") for s in preflight_pinned_job["steps"]]

    # The five preflight steps, in order
    expected_steps = [
        "Preflight golden - minimal",
        "Preflight golden - webapp",
        "Preflight canary - bad CA bundle",
        "Preflight canary - bad template key",
        "Preflight golden - on-demand TLS issuance",
    ]

    for expected in expected_steps:
        found = any(expected in name for name in step_names)
        assert found, f"preflight-pinned must have a step matching '{expected}'"

    # Verify they appear in the same order
    indices = []
    for expected in expected_steps:
        for i, name in enumerate(step_names):
            if expected in name:
                indices.append(i)
                break
    assert indices == sorted(indices), \
        f"preflight-pinned steps must appear in order: {expected_steps}"


def test_preflight_pinned_uses_pinned_binary() -> None:
    """preflight-pinned must use /tmp/gateway-pinned, not /tmp/gateway-dev."""
    workflow = yaml.safe_load(_text(_PREFLIGHT))
    preflight_pinned_job = workflow["jobs"]["preflight-pinned"]

    found_pinned_ref = False
    for step in preflight_pinned_job["steps"]:
        run = step.get("run", "")
        env = step.get("env", {})

        # Check env vars and run blocks
        if "/tmp/gateway-pinned" in run or any(
            "/tmp/gateway-pinned" in str(v) for v in env.values()
        ):
            found_pinned_ref = True

        # Make sure it doesn't accidentally reference the dev binary
        assert "/tmp/gateway-dev" not in run, \
            f"preflight-pinned step {step.get('name')!r} must not reference /tmp/gateway-dev"
        for key, val in env.items():
            assert "/tmp/gateway-dev" not in str(val), (
                f"preflight-pinned step {step.get('name')!r} env var {key} "
                "must not reference /tmp/gateway-dev"
            )

    assert found_pinned_ref, "preflight-pinned job must reference /tmp/gateway-pinned"


# --- Python base image pin: Dockerfile and tests/test_image_smoke.py only --------------


def _python_dockerfile_pin() -> tuple[str, str]:
    text = _text(_DOCKERFILE)
    tags = _all(r"^ARG PYTHON_TAG=(\S+)$", text)
    digests = _all(r"^ARG PYTHON_DIGEST=(\S+)$", text)
    assert len(tags) == 1, f"expected one PYTHON_TAG ARG line, found {tags}"
    assert len(digests) == 1, f"expected one PYTHON_DIGEST ARG line, found {digests}"
    return tags[0], digests[0]


def test_python_pin_is_well_formed() -> None:
    tag, digest = _python_dockerfile_pin()
    assert tag == "3.12-slim", f"PYTHON_TAG {tag!r} is not 3.12-slim"
    assert _DIGEST_RE.fullmatch(digest), f"PYTHON_DIGEST {digest!r} is not sha256:<64 hex>"


def test_dockerfile_pulls_python_by_tag_and_digest() -> None:
    from_lines = _all(r"^FROM python:(.+) AS runtime$", _text(_DOCKERFILE))
    assert len(from_lines) == 1
    assert from_lines[0].startswith("${PYTHON_TAG}@${PYTHON_DIGEST:?")


def test_every_dockerfile_from_is_pinned_by_digest() -> None:
    from_lines = _all(r"^FROM (\S+)", _text(_DOCKERFILE))
    assert len(from_lines) == 3
    for ref in from_lines:
        assert "@${" in ref or "@sha256:" in ref, f"FROM {ref} is not pinned by digest"


def test_python_smoke_test_carries_the_dockerfile_pin() -> None:
    tag, digest = _python_dockerfile_pin()
    smoke = _text(_SMOKE)
    assert set(_all(r'^_PYTHON_TAG = "([^"]+)"$', smoke)) == {tag}
    assert set(_all(r'^_PYTHON_DIGEST = "([^"]+)"$', smoke)) == {digest}
    assert '"python:3.12-slim"' not in smoke, "smoke test uses an unpinned python image"


def test_lock_header_regeneration_command_uses_the_pinned_python_image() -> None:
    tag, digest = _python_dockerfile_pin()
    assert f"python:{tag}@{digest}" in _text(_LOCK)


# --- pyproject.toml and requirements.lock: exact versions, hashes ----------------------

_EXACT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.+!-]*)$")
_LOCK_HEADER_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+?)(?: \\)?$")
_LOCK_HASH_RE = re.compile(r"^\s+--hash=(sha256:[0-9a-f]{64})(?: \\)?$")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pyproject() -> dict[str, Any]:
    return tomllib.loads(_text(_PYPROJECT))


def _lock_blocks() -> dict[str, tuple[str, list[str]]]:
    """Package name -> (version, hashes) from the lock's ``name==version`` blocks."""
    blocks: dict[str, tuple[str, list[str]]] = {}
    current: str | None = None
    for line in _text(_LOCK).splitlines():
        if line.startswith("#") or not line.strip():
            continue
        header = _LOCK_HEADER_RE.match(line)
        if header:
            current = _norm(header.group(1))
            blocks[current] = (header.group(2), [])
            continue
        hashed = _LOCK_HASH_RE.match(line)
        assert hashed and current, f"unexpected line in requirements.lock: {line!r}"
        blocks[current][1].append(hashed.group(1))
    return blocks


def test_pyproject_pins_every_dependency_exactly() -> None:
    data = _pyproject()
    reqs: list[str] = list(data["project"]["dependencies"])
    for extra in data["project"]["optional-dependencies"].values():
        reqs.extend(extra)
    reqs.extend(data["build-system"]["requires"])
    assert reqs
    for req in reqs:
        assert _EXACT_RE.fullmatch(req), f"pyproject.toml requirement {req!r} is not name==version"


def test_lock_has_hashes_for_every_package() -> None:
    blocks = _lock_blocks()
    assert blocks
    for name, (_, hashes) in blocks.items():
        assert hashes, f"requirements.lock: {name} has no --hash entries"


def test_lock_carries_the_runtime_and_build_pins_from_pyproject() -> None:
    data = _pyproject()
    runtime = [*data["project"]["dependencies"], *data["build-system"]["requires"]]
    blocks = _lock_blocks()
    for req in runtime:
        match = _EXACT_RE.fullmatch(req)
        assert match, req
        name, version = _norm(match.group(1)), match.group(2)
        assert name in blocks, f"requirements.lock is missing {name}"
        assert blocks[name][0] == version, (
            f"requirements.lock has {name}=={blocks[name][0]}, pyproject.toml has {version}"
        )


def test_lock_holds_no_dev_dependencies() -> None:
    blocks = _lock_blocks()
    for req in _pyproject()["project"]["optional-dependencies"]["dev"]:
        match = _EXACT_RE.fullmatch(req)
        assert match, req
        assert _norm(match.group(1)) not in blocks, f"{req} is a dev dependency, not for the image"


def test_dockerfile_installs_from_the_hashed_lock_without_resolving() -> None:
    text = _text(_DOCKERFILE)
    assert re.search(
        r"^RUN pip install .*--require-hashes .*-r /tmp/build/requirements\.lock$",
        text,
        flags=re.MULTILINE,
    )
    assert "COPY requirements.lock /tmp/build/requirements.lock" in text
    # gwops itself: no dependency resolution, no isolated build that would fetch setuptools.
    assert re.search(
        r"^RUN pip install [^\n]*--no-deps [^\n]*--no-build-isolation /tmp/build",
        text,
        flags=re.MULTILINE,
    )


# --- GitHub Actions: full-SHA pins, no floating installs -------------------------------

_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
_SHA_PIN_RE = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
_VERSION_COMMENT_RE = re.compile(r"^\s+# v\d+\.\d+\.\d+\s*$")


@pytest.mark.parametrize("path", sorted(_WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_workflow_actions_are_pinned_to_a_commit_sha(path: Path) -> None:
    found = 0
    for line in _text(path).splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _USES_RE.match(line)
        if not match:
            continue
        found += 1
        ref, rest = match.groups()
        assert _SHA_PIN_RE.fullmatch(ref), f"{path.name}: {ref} is not pinned to a full SHA"
        assert _VERSION_COMMENT_RE.fullmatch(rest), (
            f"{path.name}: {ref} lacks a trailing '# vX.Y.Z' comment"
        )
    assert found, f"{path.name}: no uses: lines found"


@pytest.mark.parametrize("path", sorted(_WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_workflow_pip_installs_use_the_pinned_project_files(path: Path) -> None:
    for line in _uncommented(path).splitlines():
        if "pip install" not in line:
            continue
        assert "--require-hashes -r requirements.lock" in line or "--no-deps" in line, (
            f"{path.name}: unpinned install: {line.strip()!r}"
        )
