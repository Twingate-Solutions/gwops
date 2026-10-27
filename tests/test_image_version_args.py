"""Static checks that both images bake their release version in at build time, with no ENV.

The version reaches the User-Agent through a generated ``_version.py`` that the build
overwrites from a build arg; a runtime ``ENV`` would let a deployment lie about it.
"""

import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_GWOPS_DOCKERFILE = _ROOT / "Dockerfile"
_VERIFIER_DOCKERFILE = _ROOT / "tests" / "integration" / "webapp" / "verifier" / "Dockerfile"
_BUILD_IMAGES = _ROOT / ".github" / "workflows" / "build-images.yml"

_GUARD_REGEX = "^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _instructions(path: Path) -> list[str]:
    """Dockerfile instructions with line continuations joined and comments dropped."""
    joined = re.sub(r"\\\r?\n", " ", _text(path))
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@pytest.mark.parametrize(
    ("dockerfile", "arg", "written_file"),
    [
        (_GWOPS_DOCKERFILE, "GWOPS_VERSION", "src/gwops/_version.py"),
        (_VERIFIER_DOCKERFILE, "VERIFIER_VERSION", "/app/_version.py"),
    ],
    ids=["gwops", "verifier"],
)
class TestVersionBuildArg:
    def test_arg_defaults_to_the_dev_version(
        self, dockerfile: Path, arg: str, written_file: str
    ) -> None:
        assert f"ARG {arg}=0.0.0-dev" in _instructions(dockerfile)

    def test_the_value_is_checked_before_use(
        self, dockerfile: Path, arg: str, written_file: str
    ) -> None:
        guards = [
            i
            for i in _instructions(dockerfile)
            if i.startswith("RUN") and "grep -Ezq" in i and f"${{{arg}}}" in i
        ]
        assert len(guards) == 1
        guard = guards[0]
        assert f"${{{arg}}}" in guard
        assert _GUARD_REGEX in guard
        assert "exit 1" in guard

    def test_the_build_writes_the_version_module(
        self, dockerfile: Path, arg: str, written_file: str
    ) -> None:
        writers = [i for i in _instructions(dockerfile) if "printf" in i and "_version.py" in i]
        assert len(writers) == 1
        writer = writers[0]
        assert f"${{{arg}}}" in writer
        assert "__version__" in writer
        assert written_file in writer

    def test_the_arg_is_declared_before_it_is_used(
        self, dockerfile: Path, arg: str, written_file: str
    ) -> None:
        text = _text(dockerfile)
        assert text.index(f"ARG {arg}=") < text.index(f"${{{arg}}}")

    def test_no_env_instruction_carries_the_version(
        self, dockerfile: Path, arg: str, written_file: str
    ) -> None:
        env_lines = [i for i in _instructions(dockerfile) if i.startswith("ENV")]
        assert not [i for i in env_lines if arg in i]
        assert not re.search(rf"^\s*ENV\s+{arg}\b", _text(dockerfile), re.MULTILINE)


class TestVerifierCopiesTheVersionModule:
    def test_the_version_module_is_copied_next_to_the_app(self) -> None:
        copies = [i for i in _instructions(_VERIFIER_DOCKERFILE) if i.startswith("COPY")]
        assert "COPY app.py _version.py ./" in copies

    def test_the_source_file_exists_with_the_dev_default(self) -> None:
        source = _text(_ROOT / "tests" / "integration" / "webapp" / "verifier" / "_version.py")
        assert '__version__ = "0.0.0-dev"' in source


class TestGwopsVersionModule:
    def test_the_source_default_is_the_dev_version(self) -> None:
        assert '__version__ = "0.0.0-dev"' in _text(_ROOT / "src" / "gwops" / "_version.py")

    def test_the_version_file_is_written_before_the_package_is_installed(self) -> None:
        text = _text(_GWOPS_DOCKERFILE)
        assert text.index("> /tmp/build/src/gwops/_version.py") < text.index(
            "pip install --no-cache-dir --no-deps --no-build-isolation /tmp/build"
        )


class TestBuildImagesWorkflowTagTrigger:
    """Test that build-images.yml triggers on semver tags and includes version tagging."""

    @staticmethod
    def _text(path: Path) -> str:
        return path.read_text(encoding="utf-8")

    @staticmethod
    def _workflow() -> dict:
        text = TestBuildImagesWorkflowTagTrigger._text(_BUILD_IMAGES)
        workflow = yaml.safe_load(text)
        return workflow

    @staticmethod
    def _triggers() -> dict:
        workflow = TestBuildImagesWorkflowTagTrigger._workflow()
        triggers = workflow.get("on", workflow.get(True))
        return triggers

    def test_workflow_has_push_tag_trigger(self) -> None:
        """Workflow must trigger on push to semver tags."""
        triggers = self._triggers()
        assert "push" in triggers, "workflow must have push trigger"
        assert "tags" in triggers["push"], "push trigger must have tags filter"

    def test_push_tag_filter_matches_semver(self) -> None:
        """Push tag filter must match v<major>.<minor>.<patch> pattern."""
        triggers = self._triggers()
        tags = triggers["push"]["tags"]
        assert isinstance(tags, list), "push.tags must be a list"
        assert len(tags) > 0, "push.tags must not be empty"
        assert "v[0-9]+" in tags[0], f"tag pattern must include semver glob: {tags[0]}"

    def test_workflow_still_has_workflow_dispatch(self) -> None:
        """Workflow must keep workflow_dispatch for manual builds."""
        triggers = self._triggers()
        assert "workflow_dispatch" in triggers, "workflow must keep workflow_dispatch"
        assert "inputs" in triggers["workflow_dispatch"], "workflow_dispatch must have inputs"

    def test_workflow_dispatch_inputs_unchanged(self) -> None:
        """Workflow_dispatch inputs must remain gateway_tag, gateway_digest, tag_latest."""
        triggers = self._triggers()
        inputs = triggers["workflow_dispatch"]["inputs"]
        assert "gateway_tag" in inputs, "inputs must have gateway_tag"
        assert "gateway_digest" in inputs, "inputs must have gateway_digest"
        assert "tag_latest" in inputs, "inputs must have tag_latest"

    def test_gateway_tag_input_defaults_to_2_0_0(self) -> None:
        """Gateway tag input default must be the pinned 2.0.0."""
        triggers = self._triggers()
        default = triggers["workflow_dispatch"]["inputs"]["gateway_tag"]["default"]
        assert default == "2.0.0", f"gateway_tag default must be 2.0.0, got {default}"

    def test_gateway_digest_input_has_correct_default(self) -> None:
        """Gateway digest input default must match the pinned digest."""
        triggers = self._triggers()
        default = triggers["workflow_dispatch"]["inputs"]["gateway_digest"]["default"]
        expected = "sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1"
        assert default == expected, f"gateway_digest default mismatch: {default}"

    def test_gateway_tag_fallback_in_validate_step(self) -> None:
        """Validate step must use gateway_tag input with 2.0.0 fallback."""
        text = self._text(_BUILD_IMAGES)
        assert "inputs.gateway_tag || '2.0.0'" in text, \
            "validate step must use inputs.gateway_tag || '2.0.0' pattern"

    def test_gateway_digest_fallback_in_validate_step(self) -> None:
        """Validate step must use gateway_digest input with pinned digest fallback."""
        text = self._text(_BUILD_IMAGES)
        expected_digest = "sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1"
        assert f"inputs.gateway_digest || '{expected_digest}'" in text, \
            f"validate step must use inputs.gateway_digest || '{expected_digest}' pattern"

    def test_gwops_version_passed_in_build_args(self) -> None:
        """Build must pass GWOPS_VERSION from steps.version.outputs.version in build-args."""
        text = self._text(_BUILD_IMAGES)
        assert "GWOPS_VERSION=${{ steps.version.outputs.version }}" in text, \
            "build-push action must pass GWOPS_VERSION build arg"

    def test_version_tag_in_tags_block_conditional_on_tag_ref(self) -> None:
        """Tags block must include version tag conditioned on github.ref_type == 'tag'."""
        text = self._text(_BUILD_IMAGES)
        assert "github.ref_type == 'tag'" in text, \
            "tags block must check github.ref_type == 'tag' for version tag"
        assert "steps.version.outputs.version" in text, \
            "tags block must reference steps.version.outputs.version"

    def test_no_empty_tag_lines(self) -> None:
        """Tags block must not have lines that expand to empty strings unconditionally."""
        text = self._text(_BUILD_IMAGES)
        assert "${{ }}" not in text, "tags block must not have empty interpolations"

    def test_tag_latest_false_by_default(self) -> None:
        """tag_latest input must default to false."""
        triggers = self._triggers()
        default = triggers["workflow_dispatch"]["inputs"]["tag_latest"]["default"]
        assert default is False, f"tag_latest default must be False, got {default}"

    def test_job_summary_includes_version_tag_on_tag_push(self) -> None:
        """Job summary must conditionally include version tag pull command on tag ref."""
        text = self._text(_BUILD_IMAGES)
        assert 'REF_TYPE: ${{ github.ref_type }}' in text, \
            "job summary must capture REF_TYPE"
        assert 'if [ "$REF_TYPE" = "tag" ]' in text, \
            "job summary must check if REF_TYPE is 'tag'"

