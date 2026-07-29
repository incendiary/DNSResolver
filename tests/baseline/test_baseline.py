"""
Baseline invariant tests — always present, never disabled.

These tests verify repo hygiene, not application logic:
  - VERSION file exists and matches the latest git tag
  - No unpinned @main/@master refs in user-facing docs
  - version.py __version__ matches VERSION file
"""

import os
import re
import subprocess

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def test_version_file_exists_and_is_semver():
    version_path = os.path.join(REPO_ROOT, "VERSION")
    assert os.path.isfile(version_path), f"VERSION file not found at {version_path}"
    version = open(version_path).read().strip()
    assert re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$", version), (
        f"'{version}' is not valid semver (expected X.Y.Z)"
    )


def test_version_file_matches_version_py():
    version_path = os.path.join(REPO_ROOT, "VERSION")
    version_py_path = os.path.join(REPO_ROOT, "version.py")
    file_version = open(version_path).read().strip()
    content = open(version_py_path).read()
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    assert m, "Could not find __version__ in version.py"
    assert file_version == m.group(1), (
        f"VERSION ({file_version}) != version.py ({m.group(1)})"
    )


def test_no_unpinned_refs_in_docs():
    violations = []
    for fname in ["README.md"]:
        fpath = os.path.join(REPO_ROOT, fname)
        if not os.path.isfile(fpath):
            continue
        for i, line in enumerate(open(fpath), 1):
            if re.search(r"@main\b|@master\b", line):
                violations.append(f"{fname}:{i}: {line.rstrip()}")
    assert not violations, "Unpinned @main/@master refs found:\n" + "\n".join(
        violations
    )


def test_version_tag_exists_in_git():
    version_path = os.path.join(REPO_ROOT, "VERSION")
    version = open(version_path).read().strip()
    expected_tag = f"v{version}"

    result = subprocess.run(
        ["git", "-C", REPO_ROOT, "tag", "-l", "v*"],
        capture_output=True,
        text=True,
    )
    tags = [t for t in result.stdout.splitlines() if t]

    if not tags:
        pytest.skip("no git tags present (shallow checkout or pre-release)")

    def semver(tag):
        return tuple(int(p) for p in tag.lstrip("v").split(".")[:3])

    highest_tag = max(tags, key=semver)

    assert expected_tag in tags or semver(version) > semver(highest_tag), (
        f"Git tag '{expected_tag}' not found and VERSION ({version}) is not "
        f"newer than the highest existing tag ({highest_tag})"
    )
