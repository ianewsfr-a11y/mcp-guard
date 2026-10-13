"""v0.3: package metadata and the PyPI publishing workflow."""

import importlib
import re
from pathlib import Path

import pytest
import yaml

import mcp_guard

ROOT = Path(__file__).resolve().parent.parent
tomllib = pytest.importorskip("tomllib")  # stdlib from Python 3.11


@pytest.fixture(scope="module")
def project():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def publish():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "publish.yml")
                          .read_text(encoding="utf-8"))


@pytest.mark.unit
def test_build_backend_is_hatchling(project):
    assert project["build-system"]["build-backend"] == "hatchling.build"
    assert any(r.startswith("hatchling") for r in project["build-system"]["requires"])


@pytest.mark.unit
def test_core_metadata(project):
    meta = project["project"]
    assert meta["name"] == "mcp-guard-audit"
    assert meta["license"] == "MIT"
    assert meta["requires-python"] == ">=3.10"
    assert meta["readme"] == "README.md"
    assert "version" in meta["dynamic"]
    assert project["tool"]["hatch"]["version"]["path"] == "mcp_guard/__init__.py"
    assert {"Topic :: Security", "Environment :: Console"} <= set(meta["classifiers"])
    # PEP 639: a license expression excludes the deprecated License :: classifiers
    assert not any(c.startswith("License ::") for c in meta["classifiers"])


@pytest.mark.unit
def test_cli_entry_point_resolves(project):
    target = project["project"]["scripts"]["mcp-guard"]
    assert target == "mcp_guard.cli:cli"
    module, attr = target.split(":")
    command = getattr(importlib.import_module(module), attr)
    assert {"inspect", "test-injection"} <= set(command.commands)


@pytest.mark.unit
def test_runtime_dependencies_match_requirements(project):
    declared = sorted(project["project"]["dependencies"])
    pinned = sorted(line.strip() for line in (ROOT / "requirements.txt")
                    .read_text(encoding="utf-8").splitlines() if line.strip())
    assert declared == pinned


@pytest.mark.unit
def test_version_is_semver_and_typed_marker_ships():
    assert re.fullmatch(r"\d+\.\d+\.\d+", mcp_guard.__version__)
    assert (ROOT / "mcp_guard" / "py.typed").exists()
    assert f"## v{mcp_guard.__version__}" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


@pytest.mark.unit
def test_readme_links_work_on_pypi():
    """PyPI renders the README outside the repo: relative links would 404."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    relative = re.findall(r"\]\((?!https?://|#)([^)]+)\)", readme)
    assert relative == []


# --- publish.yml -------------------------------------------------------------


@pytest.mark.unit
def test_publish_triggers_on_published_release(publish):
    trigger = publish.get("on", publish.get(True))  # YAML 1.1 reads `on` as True
    assert trigger == {"release": {"types": ["published"]}}


@pytest.mark.unit
def test_publish_uses_trusted_publishing_with_least_privilege(publish):
    assert publish["permissions"] == {"contents": "read"}
    job = publish["jobs"]["publish"]
    assert job["permissions"] == {"id-token": "write"}
    assert job["environment"]["name"] == "pypi"
    assert job["needs"] == "build"
    uses = [step.get("uses", "") for step in job["steps"]]
    assert any(u.startswith("pypa/gh-action-pypi-publish@") for u in uses)


@pytest.mark.unit
def test_actions_are_pinned_to_commit_shas(publish):
    uses = [step["uses"] for job in publish["jobs"].values()
            for step in job["steps"] if "uses" in step]
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses


@pytest.mark.unit
def test_release_must_come_from_main_and_be_tested_on_310(publish):
    build = publish["jobs"]["build"]
    assert build["needs"] == "test"
    assert "merge-base --is-ancestor" in "\n".join(s.get("run", "") for s in build["steps"])
    assert "3.10" in publish["jobs"]["test"]["strategy"]["matrix"]["python"]


@pytest.mark.unit
def test_publish_has_no_long_lived_credentials():
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "password" not in text and "secrets." not in text


@pytest.mark.unit
def test_build_job_checks_the_tag_with_pinned_tools(publish):
    steps = publish["jobs"]["build"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps)
    assert "twine check --strict" in scripts
    assert re.search(r"build==\d", scripts) and re.search(r"twine==\d", scripts)
    tests = "\n".join(s.get("run", "") for s in publish["jobs"]["test"]["steps"])
    assert "pytest" in tests
    tag_check = next(s for s in steps if "tag" in s.get("name", "").lower())
    assert "${{" not in tag_check["run"]  # tag passed via env, not interpolated
    assert re.search(r"__version__ = \\?\"", tag_check["run"])
