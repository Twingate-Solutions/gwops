"""pyjwt is rig-only: absent from gwops' dependencies, its Dockerfile and its source.

The rig verifier under ``tests/integration/webapp/verifier/`` owns its own requirements. This
guard needs no pyjwt itself; it reads files and parses source.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"
_DOCKERFILE = _ROOT / "Dockerfile"
_SRC = _ROOT / "src" / "gwops"

_FORBIDDEN_DISTRIBUTIONS = {"pyjwt", "jwt"}
_FORBIDDEN_TEXT = re.compile(r"(?<!\w)(?:py)?jwt(?!\w)", re.IGNORECASE)
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_IMPORT_CALLS = {"import_module", "__import__"}


def _distribution_names(requirements: list[str]) -> set[str]:
    """Return PEP 503-normalised distribution names from PEP 508 requirement strings."""
    names: set[str] = set()
    for requirement in requirements:
        match = _NAME.match(requirement)
        if match:
            names.add(re.sub(r"[-_.]+", "-", match.group(1)).lower())
    return names


def _imports_jwt(source: str) -> list[int]:
    """Return line numbers where ``source`` imports the top-level ``jwt`` package."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == "jwt" for alias in node.names):
                lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and (node.module or "").split(".")[0] == "jwt":
                lines.append(node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            first = node.args[0] if node.args else None
            if (
                name in _IMPORT_CALLS
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and first.value.split(".")[0] == "jwt"
            ):
                lines.append(node.lineno)
    return lines


def _pyproject() -> dict[str, Any]:
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))


def test_pyproject_runtime_dependencies_exclude_pyjwt() -> None:
    """[project].dependencies lists no pyjwt/jwt distribution."""
    dependencies: list[str] = _pyproject()["project"]["dependencies"]

    names = _distribution_names(dependencies)

    assert "httpx" in names, "parser sanity: known dependency not found"
    assert names.isdisjoint(_FORBIDDEN_DISTRIBUTIONS)


def test_pyproject_optional_dependencies_exclude_pyjwt() -> None:
    """No [project.optional-dependencies] group (dev included) lists pyjwt/jwt."""
    groups: dict[str, list[str]] = _pyproject()["project"].get("optional-dependencies", {})

    assert groups, "parser sanity: expected at least the dev group"
    for group, requirements in groups.items():
        names = _distribution_names(requirements)
        assert names.isdisjoint(_FORBIDDEN_DISTRIBUTIONS), f"extra {group!r} lists pyjwt"


def test_pyproject_dependency_groups_exclude_pyjwt() -> None:
    """Any PEP 735 [dependency-groups] entries list no pyjwt/jwt either."""
    groups: dict[str, list[Any]] = _pyproject().get("dependency-groups", {})

    for group, entries in groups.items():
        names = _distribution_names([entry for entry in entries if isinstance(entry, str)])
        assert names.isdisjoint(_FORBIDDEN_DISTRIBUTIONS), f"group {group!r} lists pyjwt"


def test_dockerfile_does_not_install_pyjwt_or_the_rig_verifier() -> None:
    """The gwops Dockerfile mentions neither pyjwt/jwt nor the rig verifier's requirements."""
    code = [
        line
        for line in _DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    text = "\n".join(code)

    assert _FORBIDDEN_TEXT.search(text) is None
    assert "webapp-verifier" not in text


def test_no_gwops_module_imports_jwt() -> None:
    """No module under src/gwops imports ``jwt`` (statically or via import_module/__import__)."""
    modules = sorted(_SRC.rglob("*.py"))
    assert modules, "scan sanity: no gwops modules found"

    offenders = {
        str(path.relative_to(_ROOT)): lines
        for path in modules
        if (lines := _imports_jwt(path.read_text(encoding="utf-8")))
    }

    assert offenders == {}


@pytest.mark.parametrize(
    "source",
    [
        "import jwt",
        "import jwt.algorithms",
        "from jwt import decode",
        "from jwt.exceptions import InvalidTokenError",
        "import os, jwt",
        "import importlib\nimportlib.import_module('jwt')",
        "__import__('jwt.api_jwt')",
    ],
)
def test_import_detector_flags_jwt_imports(source: str) -> None:
    """The scanner behind the src/gwops guard is not vacuous."""
    assert _imports_jwt(source) != []


@pytest.mark.parametrize(
    "source",
    ["from gwops.jwks import jwks_url", "from . import jwt_local", "import jwks", "x = 'jwt'"],
)
def test_import_detector_ignores_unrelated_names(source: str) -> None:
    """The scanner does not flag the gwops JWKS module or string literals."""
    assert _imports_jwt(source) == []


@pytest.mark.parametrize("requirement", ["PyJWT[crypto]>=2.8", "pyjwt==2.15.1", "jwt", "PyJWT"])
def test_requirement_parser_normalises_pyjwt_spellings(requirement: str) -> None:
    """Every spelling of the forbidden distributions is recognised."""
    assert not _distribution_names([requirement]).isdisjoint(_FORBIDDEN_DISTRIBUTIONS)


def test_forbidden_text_pattern_matches_pyjwt_but_not_jwks() -> None:
    """The Dockerfile pattern matches pyjwt/jwt tokens and leaves ``jwks`` alone."""
    assert _FORBIDDEN_TEXT.search("RUN pip install pyjwt[crypto]")
    assert _FORBIDDEN_TEXT.search("RUN pip install PyJWT==2.8")
    assert _FORBIDDEN_TEXT.search("RUN pip install jwt")
    assert _FORBIDDEN_TEXT.search("ENV JWKS_URL=x") is None
