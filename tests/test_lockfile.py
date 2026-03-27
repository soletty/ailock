"""Tests for lockfile read/write."""

import json
import tempfile
from pathlib import Path

import pytest
from ailock.core.lockfile import Lockfile, PackageEntry


def test_lockfile_create_and_write(tmp_path):
    lf = Lockfile()
    entry = PackageEntry(
        name="litellm",
        version="1.84.0",
        hashes=["sha256:abc123", "sha256:def456"],
        source="pypi",
    )
    lf.add_package(entry)

    output = tmp_path / ".ailock"
    written = lf.write(output)

    assert written.exists()
    data = json.loads(output.read_text())
    assert data["schema_version"] == "1"
    assert "litellm" in data["packages"]
    assert data["packages"]["litellm"]["version"] == "1.84.0"
    assert "sha256:abc123" in data["packages"]["litellm"]["hashes"]


def test_lockfile_load(tmp_path):
    data = {
        "schema_version": "1",
        "ailock_version": "0.1.0",
        "generated_at": "2024-11-15T09:41:22+00:00",
        "source_files": ["requirements.txt"],
        "packages": {
            "litellm": {
                "version": "1.84.0",
                "hashes": ["sha256:abc123"],
                "source": "pypi",
            }
        },
    }
    lockfile_path = tmp_path / ".ailock"
    lockfile_path.write_text(json.dumps(data))

    lf = Lockfile.load(lockfile_path)
    assert len(lf) == 1
    assert "litellm" in lf.packages
    assert lf.packages["litellm"].version == "1.84.0"
    assert lf.packages["litellm"].hashes == ["sha256:abc123"]


def test_lockfile_load_missing():
    with pytest.raises(FileNotFoundError):
        Lockfile.load(Path("/nonexistent/.ailock"))


def test_lockfile_normalize_package_names(tmp_path):
    """Package names should be normalized (lowercase, underscore → hyphen)."""
    lf = Lockfile()
    entry = PackageEntry(
        name="LangChain_Core",
        version="0.3.0",
        hashes=["sha256:abc123"],
    )
    lf.add_package(entry)
    assert "langchain-core" in lf.packages


def test_lockfile_sorted_packages(tmp_path):
    """Packages should be sorted alphabetically in the output."""
    lf = Lockfile()
    for name in ["openai", "anthropic", "litellm"]:
        lf.add_package(PackageEntry(name=name, version="1.0.0", hashes=[]))

    output = tmp_path / ".ailock"
    lf.write(output)
    data = json.loads(output.read_text())
    keys = list(data["packages"].keys())
    assert keys == sorted(keys)


def test_lockfile_exists(tmp_path):
    path = tmp_path / ".ailock"
    assert not Lockfile.exists(path)
    path.write_text("{}")
    assert Lockfile.exists(path)
